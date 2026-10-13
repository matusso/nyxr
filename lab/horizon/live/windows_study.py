"""Collect and audit a bounded native Windows clean/blocked TCP fixture.

The guest runs windows-endpoint.ps1 -StudyControl. This collector never opens a
guest shell or changes TCP features. IPv4 and IPv6 keep separate denominators.
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
import windows

HERE = Path(__file__).resolve().parent
PROTOCOL = json.loads((HERE / "windows-study-protocol.json").read_text())


def plan(family):
    seed = PROTOCOL["seed_start"][str(family)]
    entries = []
    for mode, count in (("clean", PROTOCOL["clean_runs_per_family"]),
                        ("blocked", PROTOCOL["blocked_runs_per_family"])):
        for n in range(count):
            entries.append({"id": f"windows-v{family}-{mode}-{n:03d}",
                            "seed": seed + len(entries), "family": family,
                            "mode": mode,
                            "expected": PROTOCOL["clean_expected"] if mode == "clean" else PROTOCOL["blocked_expected"]})
    return entries


def control(target, source, request="TRUTH"):
    return windows.truth(target, source, request, port=8443)


def one(value, expected):
    return value == expected or value == [expected]


def one_address(value, expected):
    if isinstance(value, list):
        if len(value) != 1:
            return False
        value = value[0]
    try:
        return ipaddress.ip_address(value) == ipaddress.ip_address(expected)
    except (TypeError, ValueError):
        return False


def validate_rule(state, prefix, target, source, port, action, present=True):
    if bool(state.get(prefix + "_rule_present")) != present:
        raise ValueError(f"native {prefix} rule presence differs from plan")
    if not present:
        return
    rules = state.get(prefix + "_rule", [])
    addresses = state.get(prefix + "_addresses", [])
    ports = state.get(prefix + "_ports", [])
    allowed_actions = {str(action), "block" if action == 4 else "allow"}
    if (len(rules) != 1 or rules[0].get("Enabled") != 1 or rules[0].get("Direction") != 1 or
            str(rules[0].get("Action")).lower() not in allowed_actions):
        raise ValueError(f"native {prefix} rule action/direction differs from plan")
    if len(addresses) != 1 or not one_address(addresses[0].get("LocalAddress"), target) or not one_address(addresses[0].get("RemoteAddress"), source):
        raise ValueError(f"native {prefix} rule address scope differs from plan")
    if len(ports) != 1 or str(ports[0].get("Protocol")) not in ("TCP", "6") or not one(ports[0].get("LocalPort"), str(port)):
        raise ValueError(f"native {prefix} rule protocol/port differs from plan")


def validate_truth(state, target, source, mac, fixture, blocked):
    windows.validate_truth(state, target, source, mac, fixture)
    if state.get("study_control") is not True:
        raise ValueError("Windows fixed study control is absent")
    validate_rule(state, "control", target, source, 8443, 2)
    validate_rule(state, "block", target, source, 443, 4, blocked)
    if state.get("sack_setting") != "Native Windows TCP; this helper does not change SACK":
        raise ValueError("Windows SACK configuration claim changed")
    return state


def capture_and_run(args, directory, family, target, source, command, mode):
    directory.mkdir()
    with (directory / "capture.log").open("wb") as log:
        capture = subprocess.Popen(["tcpdump", "--immediate-mode", "-i", args.interface,
            "-U", "-s", "0", "-w", str(directory / "traffic.pcap"),
            f"host {target} and host {source} and tcp port 443"], stderr=log)
        try:
            for _ in range(100):
                if "listening on" in (directory / "capture.log").read_text():
                    break
                if capture.poll() is not None:
                    raise RuntimeError("BPF capture failed")
                time.sleep(.02)
            else:
                raise RuntimeError("BPF capture did not become ready")
            lab.measure(command, directory)
            time.sleep(.15)
        finally:
            if capture.poll() is None:
                capture.send_signal(signal.SIGINT)
                try:
                    capture.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    capture.kill()
                    capture.wait()
                    raise RuntimeError("independent capture failed to flush")


def collect(args):
    if platform.system() != "Darwin":
        raise RuntimeError("collector requires macOS Ethernet BPF")
    target, source = windows.private_address(args.target), windows.private_address(args.source)
    family = ipaddress.ip_address(target).version
    if ipaddress.ip_address(source).version != family or target == source:
        raise ValueError("Windows source/target family or identity differs")
    binary = str(Path(args.binary).resolve())
    out = Path(args.output).resolve()
    out.mkdir(mode=0o700)
    os.umask(0o077)
    planned = plan(family)
    lab.save(out / "protocol.json", PROTOCOL)
    manifest = {"version": PROTOCOL["version"], "protocol_sha256": lab.digest(out / "protocol.json"),
                "planned": planned, "results": [], "target": target, "source": source,
                "next_hop_mac": args.mac, "interface": args.interface, "completed": False}
    lab.save(out / "manifest.json", manifest)  # Freeze the full denominator before traffic.

    def terminate(_signal, _frame):
        raise KeyboardInterrupt("Windows collection cancelled")
    signal.signal(signal.SIGTERM, terminate)
    try:
        initial = control(target, source)
        lab.save(out / "truth-initial.json", initial)
        fixture = initial.get("fixture")
        validate_truth(initial, target, source, args.mac, fixture, False)
        sack_registry = (initial.get("sackopts_registry_present"), initial.get("sackopts_registry_value"))
        manifest["fixture"] = fixture
        lab.save(out / "environment.json", {"platform": platform.platform(),
            "nyxr_sha256": lab.digest(Path(binary)), "buildinfo": lab.command("go", "version", "-m", binary),
            "interface": lab.command("ifconfig", args.interface),
            "collector_sha256": lab.digest(Path(__file__)),
            "helper_sha256": lab.digest(HERE / "windows-endpoint.ps1")})
        for entry in planned:
            mode = entry["mode"]
            state = control(target, source, "BLOCK" if mode == "blocked" else "UNBLOCK")
            validate_truth(state, target, source, args.mac, fixture, mode == "blocked")
            if (state.get("sackopts_registry_present"), state.get("sackopts_registry_value")) != sack_registry:
                raise ValueError("Windows SACK registry state changed during study")
            directory = out / entry["id"]
            directory.mkdir()
            manifest["results"].append({"id": entry["id"]})
            lab.save(out / "manifest.json", manifest)
            lab.save(directory / "truth-before.json", state)
            experiment = lab.experiment(target, entry["seed"])
            lab.save(directory / "experiment.json", experiment)
            common = [binary, "horizon", "resolve", "--experiment", str(directory / "experiment.json"),
                      "--allow-targets", target, "--allow-ports", "443"]
            (directory / "plan.json").write_text(lab.command(*common, "--dry-run"))
            scan = [binary, "scan", "--no-db", "--no-last-pcapng", "--profile", "custom",
                    "--protocols", "tcp", "--tcp-mode", "syn" if family == 4 else "connect",
                    "--interface", args.interface, "--source-ip", source, "--next-hop-mac", args.mac,
                    "--ports", "443", "--workers", "1", "--timeout", "800ms", "--rate", "3", "--json", target]
            horizon = common + ["--interface", args.interface, "--source-ip", source,
                                "--next-hop-mac", args.mac, "--output", str(directory / "horizon" / "report.json")]
            capture_and_run(args, directory / "scan", family, target, source, scan, "scan")
            capture_and_run(args, directory / "horizon", family, target, source, horizon, "horizon")
            after = control(target, source)
            validate_truth(after, target, source, args.mac, fixture, mode == "blocked")
            if (after.get("sackopts_registry_present"), after.get("sackopts_registry_value")) != sack_registry:
                raise ValueError("Windows SACK registry state changed during study")
            lab.save(directory / "truth-after.json", after)
            print(entry["id"], "collected", flush=True)
        manifest["completed"] = True
    except BaseException as error:
        manifest["collection_error"] = str(error)
        raise
    finally:
        if manifest.get("fixture"):
            try:
                cleanup = control(target, source, "STOP")
                lab.save(out / "cleanup.json", cleanup)
                manifest["cleanup_verified"] = cleanup.get("fixture") == manifest["fixture"] and not any(
                    cleanup.get(name) for name in ("fixture_rule_present", "control_rule_present", "block_rule_present"))
            except Exception as error:
                manifest["cleanup_error"] = str(error)
        lab.save(out / "manifest.json", manifest)
    print(json.dumps(analyze(out, binary)["strata"], indent=2))


def analyze(out, binary):
    manifest = json.loads((out / "manifest.json").read_text())
    if manifest.get("version") != PROTOCOL["version"] or json.loads((out / "protocol.json").read_text()) != PROTOCOL:
        raise ValueError("Windows study protocol differs from registration")
    if manifest.get("protocol_sha256") != lab.digest(out / "protocol.json"):
        raise ValueError("Windows study protocol hash differs")
    target, source, mac = manifest["target"], manifest["source"], manifest["next_hop_mac"]
    target, source = windows.private_address(target), windows.private_address(source)
    family = ipaddress.ip_address(target).version
    planned = plan(family)
    if manifest["planned"] != planned:
        raise ValueError("Windows study denominator/seed differs")
    rows, seen = [], set()
    initial = json.loads((out / "truth-initial.json").read_text())
    validate_truth(initial, target, source, mac, manifest["fixture"], False)
    sack_registry = (initial.get("sackopts_registry_present"), initial.get("sackopts_registry_value"))
    for result in manifest["results"]:
        entry = next((p for p in planned if p["id"] == result["id"]), None)
        if entry is None or entry["id"] in seen:
            raise ValueError("unknown/duplicate Windows study run")
        seen.add(entry["id"])
        directory = out / entry["id"]
        row = dict(entry)
        try:
            for when in ("before", "after"):
                state = json.loads((directory / f"truth-{when}.json").read_text())
                validate_truth(state, target, source, mac, manifest["fixture"], entry["mode"] == "blocked")
                if (state.get("sackopts_registry_present"), state.get("sackopts_registry_value")) != sack_registry:
                    raise ValueError("Windows SACK registry state changed during study")
            report = json.loads(lab.command(binary, "horizon", "replay", str(directory / "horizon" / "report.json")))["report"]
            if report["backend"].startswith("synthetic"):
                raise ValueError("synthetic Windows evidence rejected")
            if report["experiment"] != lab.experiment(target, entry["seed"]) or report["experiment"] != json.loads((directory / "experiment.json").read_text()):
                raise ValueError("Windows study experiment differs from frozen settings")
            row.update(lab.metrics(report))
            scan = lab.scan_result(directory / "scan" / "stdout.txt", target)
            row["scan_state"] = scan["state"]
            row["scan_correct"] = scan["state"] == ("open" if entry["mode"] == "clean" else "filtered")
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
                        raise ValueError("Windows HORIZON TX missing from independent capture")
                else:
                    windows.validate_scan_capture(frames, source, target, scan.get("packets_tx"))
            if not row["completed"] or row["backend_drops"] or row["runner_tx_packets"] > PROTOCOL["max_packets"]:
                raise ValueError("incomplete/budget/drop-invalid Windows study report")
        except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
            row["error"] = str(error)
        rows.append(row)
    strata = {}
    for mode, count in (("clean", PROTOCOL["clean_runs_per_family"]),
                        ("blocked", PROTOCOL["blocked_runs_per_family"])):
        group = [row for row in rows if row["mode"] == mode]
        valid = [row for row in group if "error" not in row]
        expected = PROTOCOL["clean_expected"] if mode == "clean" else PROTOCOL["blocked_expected"]
        correct = sum(row["outcome"] == expected for row in valid)
        strata[mode] = {"planned": count, "collected": len(group), "valid": len(valid),
                        "invalid": len(group) - len(valid), "missing": count - len(group),
                        "correct": correct, "unresolved": sum(row["outcome"] == "unresolved" for row in valid),
                        "conditional_numerical_gate": bool(mode == "clean" and len(valid) == count and
                            correct / count >= .9 and all(row.get("scan_correct") for row in valid))}
    summary = {"version": PROTOCOL["version"], "family": family, "rows": rows,
               "strata": strata, "cleanup_verified": manifest.get("cleanup_verified", False),
               "issue_66_complete": False, "limitations": PROTOCOL["limitations"]}
    lab.save(out / "summary.json", summary)
    return summary


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
        if not all((args.target, args.source, args.interface, args.mac)):
            parser.error("run requires target/source/interface/mac")
        collect(args)
    else:
        print(json.dumps(analyze(Path(args.output), args.binary)["strata"], indent=2))
