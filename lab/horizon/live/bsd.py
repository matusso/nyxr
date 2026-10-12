"""Bounded clean FreeBSD IPv4/IPv6 SACK-on and SACK-off baseline from macOS.

The guest runs bsd-endpoint.c, which has no command execution interface.
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
import subprocess
import time

import lab
import windows  # Reuse private scope, AF-aware fixed messages and SYN capture checks.

HERE = Path(__file__).resolve().parent
PROTOCOL = json.loads((HERE / "bsd-protocol.json").read_text())


def planned_runs():
    rows = []
    for repetition in range(PROTOCOL["runs_per_stratum"]):
        for family in PROTOCOL["families"]:
            for state in PROTOCOL["states"]:
                case = "effect" if state else "null"
                rows.append({"id": f"freebsd-v{family}-{case}-{repetition:03d}",
                             "seed": PROTOCOL["seed_start"] + len(rows), "platform": "FreeBSD",
                             "family": family, "sack": state, "impairment": "clean",
                             "expected": "difference" if state else "no-difference"})
    return rows


def validate_scope(manifest):
    for family in (4, 6):
        target = windows.private_address(manifest[f"target_v{family}"])
        source = windows.private_address(manifest[f"source_v{family}"])
        if ipaddress.ip_address(target).version != family or ipaddress.ip_address(source).version != family or target == source:
            raise ValueError("FreeBSD source/target family or identity differs")
        if target != manifest[f"target_v{family}"] or source != manifest[f"source_v{family}"]:
            raise ValueError("FreeBSD addresses must be canonical")


def validate_truth(state, manifest, sack=None, fixture=None):
    if state.get("platform") != "FreeBSD" or not state.get("release") or not state.get("fixture"):
        raise ValueError("missing native FreeBSD identity")
    if fixture is not None and state["fixture"] != fixture:
        raise ValueError("FreeBSD fixture identity changed")
    if state.get("port") != 443 or state.get("interface") != manifest["guest_interface"]:
        raise ValueError("FreeBSD listener scope differs")
    for family in (4, 6):
        if state.get(f"local_v{family}") != manifest[f"target_v{family}"] or state.get(f"peer_v{family}") != manifest[f"source_v{family}"]:
            raise ValueError("FreeBSD allowlisted addresses differ")
    addresses = state.get("addresses", {})
    if addresses.get("exit_status") != 0:
        raise ValueError("FreeBSD address snapshot failed")
    text = addresses.get("text", "")
    match = re.search(r"\bether\s+([0-9a-f:]{17})", text, re.I)
    if not match or match[1].lower() != manifest["next_hop_mac"].lower():
        raise ValueError("FreeBSD adapter MAC differs")
    for family in (4, 6):
        prefix = "inet" if family == 4 else "inet6"
        if not re.search(r"\b" + prefix + r"\s+" + re.escape(manifest[f"target_v{family}"]) + r"(?:\s|/)", text):
            raise ValueError("FreeBSD listener address not assigned")
    if state.get("original_sack") not in (0, 1) or state.get("sack") not in (0, 1):
        raise ValueError("native FreeBSD SACK control missing")
    if sack is not None and state["sack"] != sack:
        raise ValueError("native FreeBSD SACK contradicts registered state")
    for key in ("routes", "versions", "tcp_settings"):
        if state.get(key, {}).get("exit_status") != 0 or not state[key].get("text"):
            raise ValueError("missing native FreeBSD configuration snapshot")
    if not re.search(r"\bnet\.inet\.tcp\.sack\.enable:\s*" + str(state["sack"]) + r"\b", state["tcp_settings"]["text"]):
        raise ValueError("FreeBSD SACK syscall and native snapshot disagree")
    if not state.get("firewall", {}).get("text"):
        raise ValueError("missing FreeBSD firewall context")
    if sack is not None and state.get("listeners_closed") is not False:
        raise ValueError("FreeBSD fixture listeners closed before measurement")
    return state["fixture"]


def analyze(out, binary):
    manifest = json.loads((out / "manifest.json").read_text())
    validate_scope(manifest)
    if json.loads((out / "protocol.json").read_text()) != PROTOCOL or manifest["protocol_sha256"] != lab.digest(out / "protocol.json"):
        raise ValueError("FreeBSD protocol differs from registration")
    planned = planned_runs()
    if manifest["planned"] != planned:
        raise ValueError("FreeBSD all-planned denominator/seed/state changed")
    rows, seen = [], set()
    for result in manifest["results"]:
        entry = next((p for p in planned if p["id"] == result["id"]), None)
        if not entry or entry["id"] in seen:
            raise ValueError("unknown/duplicate FreeBSD run")
        seen.add(entry["id"])
        directory = out / entry["id"]
        row = dict(entry)
        target, source = manifest[f"target_v{entry['family']}"], manifest[f"source_v{entry['family']}"]
        try:
            for when in ("before", "after"):
                validate_truth(json.loads((directory / f"truth-{when}.json").read_text()), manifest, entry["sack"], manifest["fixture"])
            saved = directory / "horizon" / "report.json"
            report = json.loads(lab.command(binary, "horizon", "replay", str(saved)))["report"]
            if report["backend"].startswith("synthetic"):
                raise ValueError("synthetic FreeBSD evidence rejected")
            if report["experiment"] != lab.experiment(target, entry["seed"]) or report["experiment"] != json.loads((directory / "experiment.json").read_text()):
                raise ValueError("FreeBSD experiment differs from registered settings")
            row.update(lab.metrics(report))
            scanner = lab.scan_result(directory / "scan" / "stdout.txt", target)
            row.update(scan_state=scanner["state"], scan_correct=scanner["state"] == "open")
            for mode in ("scan", "horizon"):
                run = directory / mode
                resources = json.loads((run / "resources.json").read_text())
                row[mode + "_resources"] = resources
                traffic, frames = lab.pcap(run / "traffic.pcap")
                row[mode + "_traffic"] = traffic
                drops = re.search(r"(\d+) packets dropped by kernel", (run / "capture.log").read_text())
                if not drops or int(drops[1]) or resources["exit_code"] or (run / "traffic.pcap").stat().st_size > 1048576:
                    raise ValueError("FreeBSD child/capture failure or budget exceeded")
                if mode == "scan":
                    windows.validate_scan_capture(frames, source, target, scanner.get("packets_tx"))
                else:
                    sent = collections.Counter(base64.b64decode(e["frame"], validate=True)
                        for trial in report["trials"] for e in trial["evidence"] if e["direction"] != "rx")
                    if sent - frames:
                        raise ValueError("FreeBSD HORIZON TX missing from independent capture")
            if not row["completed"] or row["backend_drops"] or row["runner_tx_packets"] > PROTOCOL["max_packets"]:
                raise ValueError("incomplete or drop/budget-invalid FreeBSD report")
        except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
            row["error"] = str(error)
        rows.append(row)
    strata = {}
    for family in PROTOCOL["families"]:
        for sack in PROTOCOL["states"]:
            selected = [r for r in rows if r["family"] == family and r["sack"] == sack]
            name = f"v{family}-{'effect' if sack else 'null'}"
            strata[name] = lab.stratum(selected, PROTOCOL["runs_per_stratum"], "difference" if sack else "no-difference")
    summary = {"version": PROTOCOL["version"], "rows": rows, "strata": strata,
               "cleanup_verified": manifest.get("cleanup_verified", False),
               "issue_66_complete": False, "limitations": PROTOCOL["limitations"]}
    lab.save(out / "summary.json", summary)
    return summary


def collect(args):
    if platform.system() != "Darwin":
        raise RuntimeError("FreeBSD collector requires macOS Ethernet BPF")
    manifest = {key: getattr(args, key) for key in ("target_v4", "source_v4", "target_v6", "source_v6", "guest_interface")}
    manifest.update(next_hop_mac=args.mac, interface=args.interface, planned=planned_runs(), results=[], completed=False)
    validate_scope(manifest)
    assigned = lab.command("ifconfig", args.interface)
    if not all(manifest[f"source_v{family}"] in assigned for family in (4, 6)):
        raise ValueError("both source addresses must be assigned before collection")
    out = Path(args.output).resolve(); out.mkdir(mode=0o700); os.umask(0o077)
    binary = str(Path(args.binary).resolve())
    def terminate(_signal, _frame): raise KeyboardInterrupt("FreeBSD collection cancelled")
    signal.signal(signal.SIGTERM, terminate)
    lab.save(out / "protocol.json", PROTOCOL)
    manifest["protocol_sha256"] = lab.digest(out / "protocol.json")
    lab.save(out / "manifest.json", manifest)  # Freeze before any collector traffic.
    def control(request="TRUTH"):
        return windows.truth(manifest["target_v4"], manifest["source_v4"], request)
    try:
        state = control(); lab.save(out / "truth-initial.json", state)
        manifest["fixture"] = validate_truth(state, manifest)
        manifest["original_sack"] = state["original_sack"]
        lab.save(out / "environment.json", {"platform": platform.platform(), "nyxr_sha256": lab.digest(Path(binary)),
            "buildinfo": lab.command("go", "version", "-m", binary), "interface": assigned,
            "collector_sha256": lab.digest(Path(__file__)), "helper_sha256": lab.digest(HERE / "bsd-endpoint.c")})
        for entry in manifest["planned"]:
            directory = out / entry["id"]; directory.mkdir()
            manifest["results"].append({"id": entry["id"]}); lab.save(out / "manifest.json", manifest)
            before = control(f"SACK{entry['sack']}")
            lab.save(directory / "truth-before.json", before)
            validate_truth(before, manifest, entry["sack"], manifest["fixture"])
            target, source = manifest[f"target_v{entry['family']}"], manifest[f"source_v{entry['family']}"]
            lab.save(directory / "experiment.json", lab.experiment(target, entry["seed"]))
            common = [binary, "horizon", "resolve", "--experiment", str(directory / "experiment.json"), "--allow-targets", target, "--allow-ports", "443"]
            (directory / "plan.json").write_text(lab.command(*common, "--dry-run"))
            for mode in ("scan", "horizon"):
                run = directory / mode; run.mkdir()
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
                            cmd = common + ["--interface", args.interface, "--source-ip", source, "--next-hop-mac", args.mac, "--output", str(run / "report.json")]
                        else:
                            cmd = [binary, "scan", "--no-db", "--no-last-pcapng", "--profile", "custom", "--protocols", "tcp",
                                "--tcp-mode", "syn" if entry["family"] == 4 else "connect", "--interface", args.interface,
                                "--source-ip", source, "--next-hop-mac", args.mac, "--ports", "443", "--workers", "1", "--timeout", "800ms", "--rate", "3", "--json", target]
                        lab.measure(cmd, run); time.sleep(.15)
                    finally:
                        if capture.poll() is None:
                            capture.send_signal(signal.SIGINT)
                            try: capture.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                capture.kill(); capture.wait(); raise RuntimeError("independent capture failed to flush")
            after = control(); lab.save(directory / "truth-after.json", after)
            validate_truth(after, manifest, entry["sack"], manifest["fixture"])
            print(entry["id"], "collected", flush=True)
        manifest["completed"] = True
    except BaseException as error:
        manifest["collection_error"] = str(error); raise
    finally:
        if manifest.get("fixture"):
            try:
                cleanup = control("STOP"); lab.save(out / "cleanup.json", cleanup)
                manifest["cleanup_verified"] = cleanup.get("fixture") == manifest["fixture"] and cleanup.get("listeners_closed") is True and cleanup.get("sack") == manifest["original_sack"]
            except Exception as error: manifest["cleanup_error"] = str(error)
        lab.save(out / "manifest.json", manifest)
    print(json.dumps(analyze(out, binary)["strata"], indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "analyze"))
    parser.add_argument("--binary", required=True); parser.add_argument("--output", required=True)
    for key in ("target-v4", "source-v4", "target-v6", "source-v6", "guest-interface", "interface", "mac"):
        parser.add_argument("--" + key)
    args = parser.parse_args()
    if args.command == "run":
        if not all(getattr(args, key.replace('-', '_')) for key in ("target-v4", "source-v4", "target-v6", "source-v6", "guest-interface", "interface", "mac")):
            parser.error("run requires explicit addresses, guest/source interfaces and next-hop MAC")
        collect(args)
    else: print(json.dumps(analyze(Path(args.output), args.binary)["strata"], indent=2))
