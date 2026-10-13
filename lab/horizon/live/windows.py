"""Exploratory native Windows IPv4/IPv6 fixture measured from macOS BPF.

The supplemental protocol cannot satisfy the Linux null gate or all of #66.
The operator starts windows-endpoint.ps1; this tool opens no guest shell.
"""
import argparse
import base64
import collections
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import subprocess
import time

import lab

PROTOCOL = {
    "version": "horizon-windows-ipv4-exploratory/v1", "runs": 3,
    "seed_start": 66100, "replicates": 12, "window_ms": 800,
    "washout_ms": 300, "packets_per_second": 3, "max_packets": 48,
    "max_duration_seconds": 90, "primary_outcome": "SACK negotiation difference",
    "expected": "difference", "alpha": .05,
    "expected_basis": "Native Windows SACK support hypothesis; no independently controlled SACK null",
    "limitations": ["IPv4 only; no Windows IPv6/BSD/held-out coverage",
        "Exploratory 3-run workload; no statistical acceptance or independent population claim",
        "Accuracy means agreement with the registered Windows SACK hypothesis, not an independently toggled SACK ground truth",
        "Direct Ethernet path to VM on operator-selected Fusion virtual segment",
        "Existing guest routes remain; no network-disconnected or NAT-path claim",
        "macOS source kernel RSTs remain enabled and are included in independent capture",
        "Resources measure macOS scanner/runner children, not Windows server CPU/RSS"]}


def private_v4(value):
    address = ipaddress.IPv4Address(value)
    if not any(address in ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
        raise ValueError("Windows fixture must use an operator-owned RFC1918 virtual segment")
    return str(address)


def private_address(value):
    address = ipaddress.ip_address(value)
    if address.version == 4:
        return private_v4(value)
    if address.scope_id or address not in ipaddress.IPv6Network("fc00::/7"):
        raise ValueError("Windows IPv6 fixture must use an operator-owned ULA virtual segment")
    return str(address)


def protocol_for(family):
    if family == 4:
        return PROTOCOL
    if family != 6:
        raise ValueError("unsupported Windows address family")
    protocol = json.loads(json.dumps(PROTOCOL))
    protocol.update(version="horizon-windows-ipv6-exploratory/v1", seed_start=66200)
    protocol["limitations"][0] = "IPv6 only; no controlled Windows null/BSD/held-out coverage"
    protocol["limitations"].append("IPv6 scanner uses kernel TCP connect; its SYN TX and full handshake traffic are independently captured")
    protocol["limitations"].append("Temporary ULA addresses create a direct attached IPv6 path; no routed IPv6/NAT coverage")
    return protocol


def planned_runs(family, protocol):
    return [{"id": f"windows-v{family}-clean-{n:03d}", "seed": protocol["seed_start"] + n,
             "platform": "Windows", "family": family, "impairment": "clean", "expected": "difference"}
            for n in range(protocol["runs"])]


def truth(target, source, request="TRUTH"):
    family = socket.AF_INET6 if ipaddress.ip_address(target).version == 6 else socket.AF_INET
    with socket.socket(family) as sock:
        sock.settimeout(10)
        sock.bind((source, 0))
        sock.connect((target, 443))
        sock.sendall((request + "\n").encode())
        data = b""
        while not data.endswith(b"\n"):
            part = sock.recv(65536)
            if not part or len(data) + len(part) > 262144:
                raise ValueError("missing/oversized Windows truth response")
            data += part
    return json.loads(data)


def validate_scan_capture(frames, source, target, packets_tx):
    """A zero-drop capture can still miss a short workload before buffer flush."""
    if not isinstance(packets_tx, int) or packets_tx < 1:
        raise ValueError("missing scanner TX denominator")
    count = 0
    family = ipaddress.ip_address(target).version
    source_bytes, target_bytes = ipaddress.ip_address(source).packed, ipaddress.ip_address(target).packed
    for frame, copies in frames.items():
        if family == 4:
            if len(frame) < 54 or frame[12:14] != b"\x08\x00" or frame[14] >> 4 != 4:
                continue
            offset = 14 + (frame[14] & 15) * 4
            if offset < 34 or len(frame) < offset + 20 or frame[23] != 6:
                continue
            addresses_match = frame[26:30] == source_bytes and frame[30:34] == target_bytes
        else:
            # This fixture emits ordinary IPv6 TCP, without extension headers.
            if len(frame) < 74 or frame[12:14] != b"\x86\xdd" or frame[14] >> 4 != 6 or frame[20] != 6:
                continue
            offset = 54
            addresses_match = frame[22:38] == source_bytes and frame[38:54] == target_bytes
        if (addresses_match and frame[offset + 2:offset + 4] == b"\x01\xbb"
                and frame[offset + 13] & 0x17 == 2):
            count += copies
    if count < packets_tx:
        raise ValueError("scanner SYN transmissions missing from independent capture")


def validate_truth(state, target, source, mac, fixture=None):
    if state.get("platform") != "Windows" or not state.get("build") or not state.get("fixture"):
        raise ValueError("missing native Windows build/fixture identity")
    if fixture is not None and state["fixture"] != fixture:
        raise ValueError("Windows listener identity changed during study")
    if state.get("local_address") != target or state.get("peer_address") != source or state.get("port") != 443:
        raise ValueError("Windows truth contradicts allowlisted scope")
    if state.get("adapter", {}).get("MacAddress", "").replace("-", ":").lower() != mac.lower():
        raise ValueError("Windows adapter differs from specified next-hop MAC")
    if not state.get("fixture_rule_present"):
        raise ValueError("temporary fixture firewall rule missing")
    rules = state.get("fixture_rule", [])
    if len(rules) != 1 or rules[0].get("Enabled") != 1 or rules[0].get("Direction") != 1 or rules[0].get("Action") != 2:
        raise ValueError("fixture rule is not enabled inbound allow")
    addresses, ports = state.get("fixture_addresses", []), state.get("fixture_ports", [])
    # CIM/PowerShell versions serialize singleton filters as a scalar or array.
    # Accept exactly one value in either representation; never widen the scope.
    def single(value, expected):
        return value == expected or value == [expected]
    def single_address(value, expected):
        if isinstance(value, list):
            if len(value) != 1: return False
            value = value[0]
        try:
            return ipaddress.ip_address(value) == ipaddress.ip_address(expected)
        except (ValueError, TypeError):
            return False
    if len(addresses) != 1 or not single_address(addresses[0].get("LocalAddress"), target) or not single_address(addresses[0].get("RemoteAddress"), source):
        raise ValueError("fixture rule address scope differs from plan")
    if len(ports) != 1 or str(ports[0].get("Protocol")) not in ("TCP", "6") or not single(ports[0].get("LocalPort"), "443"):
        raise ValueError("fixture rule protocol/port differs from plan")
    if not state.get("tcp_global") or not state.get("tcp_settings") or not state.get("firewall_profiles"):
        raise ValueError("missing native TCP/firewall context")
    return state["fixture"]


def analyze(out, binary):
    manifest = json.loads((out / "manifest.json").read_text())
    target, source, mac = manifest["target"], manifest["source"], manifest["next_hop_mac"]
    target, source = private_address(target), private_address(source)
    family = ipaddress.ip_address(target).version
    if ipaddress.ip_address(source).version != family or source == target:
        raise ValueError("Windows source/target family or identity differs")
    protocol = protocol_for(family)
    if json.loads((out / "protocol.json").read_text()) != protocol or manifest["protocol_sha256"] != lab.digest(out / "protocol.json"):
        raise ValueError("Windows supplemental protocol differs from registration")
    planned = planned_runs(family, protocol)
    if manifest["planned"] != planned:
        raise ValueError("Windows all-planned-run denominator/seed changed")
    rows = []
    seen = set()
    for result in manifest["results"]:
        entry = next((p for p in planned if p["id"] == result["id"]), None)
        if not entry or entry["id"] in seen:
            raise ValueError("unknown/duplicate Windows run")
        seen.add(entry["id"])
        directory = out / entry["id"]
        row = dict(entry)
        try:
            for when in ("before", "after"):
                validate_truth(json.loads((directory / f"truth-{when}.json").read_text()),
                               target, source, mac, manifest["fixture"])
            report_path = directory / "horizon" / "report.json"
            report = json.loads(lab.command(binary, "horizon", "replay", str(report_path)))["report"]
            if report["backend"].startswith("synthetic"):
                raise ValueError("synthetic Windows evidence rejected")
            if report["experiment"] != lab.experiment(target, entry["seed"]) or report["experiment"] != json.loads((directory / "experiment.json").read_text()):
                raise ValueError("Windows experiment differs from frozen settings")
            row.update(lab.metrics(report))
            scanner = lab.scan_result(directory / "scan" / "stdout.txt", target)
            row["scan_state"], row["scan_correct"] = scanner["state"], scanner["state"] == "open"
            for mode in ("scan", "horizon"):
                run = directory / mode
                resources = json.loads((run / "resources.json").read_text())
                row[mode + "_resources"] = resources
                traffic, frames = lab.pcap(run / "traffic.pcap")
                if (run / "traffic.pcap").stat().st_size > 1048576:
                    raise ValueError("independent Windows capture exceeds 1 MiB budget")
                row[mode + "_traffic"] = traffic
                drops = re.search(r"(\d+) packets dropped by kernel", (run / "capture.log").read_text())
                if not drops or int(drops[1]) or resources["exit_code"]:
                    raise ValueError(f"{mode}: child failure or missing/nonzero independent drops")
                if mode == "horizon":
                    sent = collections.Counter(base64.b64decode(e["frame"], validate=True)
                        for trial in report["trials"] for e in trial["evidence"] if e["direction"] != "rx")
                    if sent - frames:
                        raise ValueError("Windows TX missing from independent capture")
                else:
                    validate_scan_capture(frames, source, target, scanner.get("packets_tx"))
            if not row["completed"] or row["backend_drops"] or row["runner_tx_packets"] > protocol["max_packets"]:
                raise ValueError("incomplete/budget/drop-invalid Windows report")
        except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
            row["error"] = str(error)
        rows.append(row)
    summary = {"version": protocol["version"], "rows": rows,
               "stratum": lab.stratum(rows, len(planned), "difference"),
               "issue_66_complete": False, "limitations": protocol["limitations"],
               "cleanup_verified": manifest.get("cleanup_verified", False)}
    lab.save(out / "summary.json", summary)
    return summary


def collect(args):
    if platform.system() != "Darwin":
        raise RuntimeError("this collector requires macOS Ethernet BPF")
    target, source = private_address(args.target), private_address(args.source)
    family = ipaddress.ip_address(target).version
    if ipaddress.ip_address(source).version != family or source == target:
        raise ValueError("Windows source and target must be distinct and in the same family")
    protocol = protocol_for(family)
    binary = str(Path(args.binary).resolve())
    out = Path(args.output).resolve()
    out.mkdir(mode=0o700)
    os.umask(0o077)
    def terminate(_signal, _frame):
        raise KeyboardInterrupt("Windows collection cancelled")
    signal.signal(signal.SIGTERM, terminate)
    lab.save(out / "protocol.json", protocol)
    planned = planned_runs(family, protocol)
    manifest = {"protocol_sha256": lab.digest(out / "protocol.json"), "planned": planned,
                "results": [], "completed": False, "target": target, "source": source,
                "next_hop_mac": args.mac, "interface": args.interface}
    lab.save(out / "manifest.json", manifest)  # registered before any collector traffic
    try:
        state = truth(target, source)
        lab.save(out / "truth-initial.json", state)
        manifest["fixture"] = validate_truth(state, target, source, args.mac)
        lab.save(out / "environment.json", {"platform": platform.platform(),
            "nyxr_sha256": lab.digest(Path(binary)), "buildinfo": lab.command("go", "version", "-m", binary),
            "interface": lab.command("ifconfig", args.interface),
            "collector_sha256": lab.digest(Path(__file__)),
            "helper_sha256": lab.digest(lab.HERE / "windows-endpoint.ps1")})
        for entry in planned:
            directory = out / entry["id"]
            directory.mkdir()
            manifest["results"].append({"id": entry["id"]})
            lab.save(out / "manifest.json", manifest)
            before = truth(target, source)
            lab.save(directory / "truth-before.json", before)
            validate_truth(before, target, source, args.mac, manifest["fixture"])
            lab.save(directory / "experiment.json", lab.experiment(target, entry["seed"]))
            common = [binary, "horizon", "resolve", "--experiment", str(directory / "experiment.json"),
                      "--allow-targets", target, "--allow-ports", "443"]
            (directory / "plan.json").write_text(lab.command(*common, "--dry-run"))
            for mode in ("scan", "horizon"):
                run = directory / mode
                run.mkdir()
                with (run / "capture.log").open("wb") as log:
                    capture = subprocess.Popen(["tcpdump", "--immediate-mode", "-i", args.interface, "-U", "-s", "0", "-w",
                        str(run / "traffic.pcap"), f"host {target} and host {source} and tcp port 443"], stderr=log)
                    try:
                        for _ in range(100):
                            if "listening on" in (run / "capture.log").read_text(): break
                            if capture.poll() is not None: raise RuntimeError("BPF capture failed")
                            time.sleep(.02)
                        else: raise RuntimeError("BPF capture did not become ready")
                        if mode == "horizon":
                            cmd = common + ["--interface", args.interface, "--source-ip", source,
                                "--next-hop-mac", args.mac, "--output", str(run / "report.json")]
                        else:
                            cmd = [binary, "scan", "--no-db", "--no-last-pcapng", "--profile", "custom",
                                "--protocols", "tcp", "--tcp-mode", "syn" if family == 4 else "connect", "--interface", args.interface,
                                "--source-ip", source, "--next-hop-mac", args.mac, "--ports", "443", "--workers", "1",
                                "--timeout", "800ms", "--rate", "3", "--json", target]
                        lab.measure(cmd, run)
                        time.sleep(.15)
                    finally:
                        if capture.poll() is None:
                            capture.send_signal(signal.SIGINT)
                            try: capture.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                capture.kill(); capture.wait()
                                raise RuntimeError("independent capture failed to flush")
            after = truth(target, source)
            lab.save(directory / "truth-after.json", after)
            validate_truth(after, target, source, args.mac, manifest["fixture"])
            print(entry["id"], "collected", flush=True)
        manifest["completed"] = True
    except BaseException as error:
        manifest["collection_error"] = str(error)
        raise
    finally:
        if manifest.get("fixture"):
            try:
                cleanup = truth(target, source, "STOP")
                lab.save(out / "cleanup.json", cleanup)
                manifest["cleanup_verified"] = cleanup.get("fixture") == manifest["fixture"] and not cleanup.get("fixture_rule_present", True)
            except Exception as error:
                manifest["cleanup_error"] = str(error)
        lab.save(out / "manifest.json", manifest)
    print(json.dumps(analyze(out, binary)["stratum"], indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "analyze"))
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--target")
    parser.add_argument("--source")
    parser.add_argument("--interface")
    parser.add_argument("--mac")
    args = parser.parse_args()
    if args.command == "run":
        if not all((args.target, args.source, args.interface, args.mac)): parser.error("run requires target/source/interface/mac")
        collect(args)
    else:
        print(json.dumps(analyze(Path(args.output), args.binary)["stratum"], indent=2))
