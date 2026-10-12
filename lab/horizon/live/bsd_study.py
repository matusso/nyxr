"""Frozen two-VNET configuration-reserved BSD study; no guest shell interface."""
import argparse
import base64
import collections
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import signal
import socket
import subprocess
import threading
import time

import bsd
import lab
import windows

HERE = Path(__file__).resolve().parent
PROTOCOL = json.loads((HERE / "bsd-study-protocol.json").read_text())


def planned_runs():
    rows = []
    for role_index, role in enumerate(PROTOCOL["roles"]):
        rng = random.Random(PROTOCOL["order_seed"] + role_index)
        for block in range(PROTOCOL["blocks"]):
            batch = []
            for family in PROTOCOL["families"]:
                for condition in PROTOCOL["conditions"]:
                    for sack, count in ((0, PROTOCOL["nulls_per_block"]), (1, PROTOCOL["effects_per_block"])):
                        for repeat in range(count):
                            batch.append({"role": role, "block": block, "family": family, "sack": sack,
                                "impairment": condition, "expected": "difference" if sack else "no-difference",
                                "id": f"{role}-v{family}-{condition}-sack{sack}-{block:02d}-{repeat}"})
            rng.shuffle(batch)
            rows.extend(batch)
        for family in PROTOCOL["families"]:
            for repeat in range(PROTOCOL["drop_runs_per_family"]):
                rows.append({"role": role, "block": PROTOCOL["blocks"], "family": family, "sack": 1,
                    "impairment": "drop", "expected": "unresolved", "id": f"{role}-v{family}-drop-{repeat}"})
    for index, entry in enumerate(rows):
        entry.update(seed=PROTOCOL["seed_start"] + index, platform="FreeBSD")
    return rows


def control(scope, request="TRUTH"):
    if request not in ("TRUTH", "STOP", "CLEAN0", "CLEAN1", "IMPAIR0", "IMPAIR1", "DROP1"):
        raise ValueError("unregistered fixture control")
    with socket.socket(socket.AF_INET) as sock:
        sock.settimeout(10)
        sock.bind((scope["source_v4"], 0))
        sock.connect((scope["target_v4"], 18067))
        sock.sendall((request + "\n").encode())
        data = b""
        while not data.endswith(b"\n"):
            part = sock.recv(65536)
            if not part or len(data) + len(part) > 262144:
                raise ValueError("missing/oversized BSD study truth")
            data += part
    return json.loads(data)


def validate_truth(state, scope, entry=None):
    bsd.validate_truth(state, scope, entry["sack"] if entry else None, scope.get("fixture"))
    if state.get("jailed") != 1:
        raise ValueError("BSD study endpoint is not jailed")
    firewall = state.get("firewall", {})
    if firewall.get("exit_status") != 0:
        raise ValueError("BSD native firewall snapshot failed")
    text = firewall.get("text", "")
    for setting in ("net.inet.ip.fw.enable", "net.inet6.ip6.fw.enable"):
        if not re.search(re.escape(setting) + r":\s*1\b", text):
            raise ValueError("BSD VNET firewall disabled")
    if "allow ip from any to any" not in text:
        raise ValueError("BSD VNET default allow rule missing")
    condition = entry["impairment"] if entry else state.get("condition")
    if state.get("condition") != condition:
        raise ValueError("BSD impairment differs from registration")
    rules = [line for line in text.splitlines() if re.match(r"6006[67]\s", line)]
    if condition == "clean":
        if rules or re.search(r"0?6066:", text):
            raise ValueError("unexpected clean BSD shaping rule or pipe")
    else:
        action = "pipe 6066" if condition == "loss-jitter" else "deny"
        if len(rules) != 2 or not all(action in line and "tcpflags" in line and "syn,ack" in line for line in rules):
            raise ValueError("BSD response-only shaping rules missing")
        for family, number in ((4, 60066), (6, 60067)):
            line = next(line for line in rules if line.startswith(str(number)))
            if f"from {scope[f'target_v{family}']} 443 to {scope[f'source_v{family}']}" not in line or " out" not in line:
                raise ValueError("BSD shaping rules exceed explicit response scope")
        if condition == "loss-jitter" and ("6066" not in text or "nyxr66-uniform-15-25" not in text):
            raise ValueError("BSD native dummynet delay profile missing")
        if condition == "loss-jitter":
            if not re.search(r"\bplr\s+0\.050000\b", text):
                raise ValueError("BSD native dummynet loss probability differs")
            if not re.search(r"\b0?6066:\s+100\.000\s+Mbit/s\b", text):
                raise ValueError("BSD native dummynet bandwidth differs")
            if not re.search(r'profile:\s+name\s+"nyxr66-uniform-15-25"\s+loss\s+1\.000000\s+samples\s+128\b', text):
                raise ValueError("BSD native dummynet sample distribution differs")
    return state["fixture"]


def shaping_counter(state, family):
    number = 60066 if family == 4 else 60067
    match = re.search(r"^" + str(number) + r"\s+(\d+)\s+\d+\s", state["firewall"]["text"], re.M)
    if not match: raise ValueError("BSD native shaping counter missing")
    return int(match[1])


def diagnostics(rows):
    values = [r["rtt_ms_p50"] for r in rows if not r.get("error") and r.get("rtt_ms_p50") is not None]
    if len(values) < 4:
        return {"samples": len(values), "sufficient": False, "iid_established": False}
    n = len(values)
    mean = sum(values) / n
    denominator = sum((v - mean) ** 2 for v in values)
    lag = sum((a - mean) * (b - mean) for a, b in zip(values, values[1:])) / denominator if denominator else None
    early = sum(values[:n // 2]) / (n // 2)
    late = sum(values[n // 2:]) / (n - n // 2)
    drift = (late - early) / early if early else None
    return {"samples": n, "sufficient": True, "first_half_mean_rtt_ms": early, "second_half_mean_rtt_ms": late,
        "relative_rtt_drift": drift, "lag_one_rtt_correlation": lag,
        "drift_flag": drift is not None and abs(drift) > PROTOCOL["diagnostics"]["split_half_rtt_relative_drift_flag"],
        "lag_flag": lag is not None and abs(lag) > PROTOCOL["diagnostics"]["absolute_lag_one_rtt_correlation_flag"],
        "iid_established": False, "stationarity_established": False}


def sack_option(encoded):
    options = base64.b64decode(encoded, validate=True)
    index = 0
    found = False
    while index < len(options):
        kind = options[index]
        if kind == 0: break
        if kind == 1:
            index += 1; continue
        if index + 1 >= len(options) or options[index + 1] < 2 or index + options[index + 1] > len(options):
            raise ValueError("truncated canonical TCP options")
        if kind == 4:
            if options[index + 1] != 2: raise ValueError("invalid SACK-permitted length")
            found = True
        index += options[index + 1]
    return found


def analyze(out, binary):
    manifest = json.loads((out / "manifest.json").read_text())
    if json.loads((out / "protocol.json").read_text()) != PROTOCOL or manifest["protocol_sha256"] != lab.digest(out / "protocol.json"):
        raise ValueError("BSD study protocol differs from registration")
    planned = planned_runs()
    if manifest["planned"] != planned:
        raise ValueError("BSD study all-planned denominator/order/seed changed")
    for scope in manifest["fixtures"].values():
        bsd.validate_scope(scope)
    rows, seen = [], set()
    indexed = {entry["id"]: entry for entry in planned}
    for result in manifest["results"]:
        entry = indexed.get(result["id"])
        if not entry or entry["id"] in seen:
            raise ValueError("unknown/duplicate BSD study run")
        seen.add(entry["id"])
        scope = manifest["fixtures"][entry["role"]]
        target, source = scope[f"target_v{entry['family']}"], scope[f"source_v{entry['family']}"]
        directory = out / entry["id"]
        row = dict(entry)
        try:
            truths = {}
            for when in ("before", "after"):
                truths[when] = json.loads((directory / f"truth-{when}.json").read_text())
                validate_truth(truths[when], scope, entry)
            if entry["impairment"] != "clean":
                row["shaping_packets_before"] = shaping_counter(truths["before"], entry["family"])
                row["shaping_packets_after"] = shaping_counter(truths["after"], entry["family"])
                if row["shaping_packets_after"] <= row["shaping_packets_before"]:
                    raise ValueError("BSD response path did not traverse the registered shaping rule")
            envelope = json.loads((directory / "horizon" / "report.json").read_text())
            replay = json.loads(lab.command(binary, "horizon", "replay", str(directory / "horizon" / "report.json")))
            if replay != envelope:
                raise ValueError("BSD canonical replay changed saved report")
            report = replay["report"]
            if report["backend"].startswith("synthetic"):
                raise ValueError("synthetic BSD study evidence")
            expected_experiment = lab.experiment(target, entry["seed"])
            if report["experiment"] != expected_experiment or json.loads((directory / "experiment.json").read_text()) != expected_experiment:
                raise ValueError("BSD study experiment differs from frozen plan")
            row.update(lab.metrics(report))
            row["complete_pairs"] = report["comparison"]["completePairs"]
            scanner = lab.scan_result(directory / "scan" / "stdout.txt", target)
            row.update(scan_state=scanner["state"], scan_correct=scanner["state"] == ("filtered" if entry["impairment"] == "drop" else "open"))
            for trial in report["trials"]:
                features = trial["features"]
                if features["responseClass"] == "syn-ack":
                    expected_sack = bool(entry["sack"] and trial["arm"] == "treatment")
                    if sack_option(features.get("tcpOptions", "")) != expected_sack:
                        raise ValueError("BSD native ground truth contradicts canonical SACK reply")
            for mode in ("scan", "horizon"):
                run = directory / mode
                resources = json.loads((run / "resources.json").read_text())
                row[mode + "_resources"] = resources
                traffic, frames = lab.pcap(run / "traffic.pcap")
                row[mode + "_traffic"] = traffic
                drops = re.search(r"(\d+) packets dropped by kernel", (run / "capture.log").read_text())
                if not drops or int(drops[1]) or resources["exit_code"] or resources["wall_seconds"] > 90 or (run / "traffic.pcap").stat().st_size > 1048576:
                    raise ValueError("BSD child/capture failure or budget exceeded")
                if mode == "scan":
                    windows.validate_scan_capture(frames, source, target, scanner.get("packets_tx"))
                else:
                    sent = collections.Counter(base64.b64decode(e["frame"], validate=True)
                        for trial in report["trials"] for e in trial["evidence"] if e["direction"] != "rx")
                    if sent - frames:
                        raise ValueError("BSD study HORIZON TX absent from independent capture")
            if not row["completed"] or row["backend_drops"] or row["runner_tx_packets"] > PROTOCOL["max_packets"]:
                raise ValueError("incomplete/drop/budget-invalid BSD study report")
        except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
            row["error"] = str(error)
        rows.append(row)
    strata = {}
    for role in PROTOCOL["roles"]:
        for family in PROTOCOL["families"]:
            for condition, sack in [(c, s) for c in PROTOCOL["conditions"] for s in (0, 1)] + [("drop", 1)]:
                group = [e for e in planned if (e["role"], e["family"], e["impairment"], e["sack"]) == (role, family, condition, sack)]
                selected = [r for r in rows if r["id"] in {e["id"] for e in group}]
                expected = group[0]["expected"]
                value = lab.stratum(selected, len(group), expected)
                value["conditional_numerical_null_gate_pass"] = value.pop("null_gate_pass")
                value["conditional_numerical_clean_effect_gate_pass"] = bool(condition == "clean" and sack == 1
                    and value["planned"] >= 12 and value["accuracy_all_planned"] >= .9
                    and value["invalid"] == 0 and value["missing"] == 0)
                value["null_gate_pass"] = False  # Independence/stationarity not established.
                value["temporal_diagnostics"] = diagnostics(selected)
                strata[f"{role}-v{family}-{condition}-sack{sack}"] = value
    summary = {"version": PROTOCOL["version"], "rows": rows, "strata": strata,
        "cleanup_verified": manifest.get("cleanup_verified", False), "issue_66_complete": False,
        "independence_established": False, "limitations": PROTOCOL["limitations"]}
    lab.save(out / "summary.json", summary)
    return summary


def measure_one(binary, interface, scope, entry, directory):
    target, source = scope[f"target_v{entry['family']}"], scope[f"source_v{entry['family']}"]
    lab.save(directory / "experiment.json", lab.experiment(target, entry["seed"]))
    common = [binary, "horizon", "resolve", "--experiment", str(directory / "experiment.json"), "--allow-targets", target, "--allow-ports", "443"]
    (directory / "plan.json").write_text(lab.command(*common, "--dry-run"))
    for mode in ("scan", "horizon"):
        run = directory / mode; run.mkdir()
        with (run / "capture.log").open("wb") as log:
            capture = subprocess.Popen(["tcpdump", "--immediate-mode", "-i", interface, "-U", "-s", "0", "-w",
                str(run / "traffic.pcap"), f"host {target} and host {source} and tcp port 443"], stderr=log)
            try:
                for _ in range(100):
                    if "listening on" in (run / "capture.log").read_text(): break
                    if capture.poll() is not None: raise RuntimeError("BSD independent BPF capture failed")
                    time.sleep(.02)
                else: raise RuntimeError("BSD capture readiness deadline")
                if mode == "horizon":
                    cmd = common + ["--interface", interface, "--source-ip", source, "--next-hop-mac", scope["next_hop_mac"], "--output", str(run / "report.json")]
                else:
                    cmd = [binary, "scan", "--no-db", "--no-last-pcapng", "--profile", "custom", "--protocols", "tcp",
                        "--tcp-mode", "syn" if entry["family"] == 4 else "connect", "--interface", interface,
                        "--source-ip", source, "--next-hop-mac", scope["next_hop_mac"], "--ports", "443", "--workers", "1",
                        "--timeout", "800ms", "--rate", "3", "--json", target]
                measure(cmd, run)
                time.sleep(.15)
            finally:
                if capture.poll() is None:
                    capture.send_signal(signal.SIGINT)
                    try: capture.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        capture.kill(); capture.wait(); raise RuntimeError("BSD capture did not flush")


def measure(args, directory, seconds=90):
    """Per-child accounting and an external deadline, including worker threads."""
    start = time.monotonic()
    with (directory / "stdout.txt").open("wb") as out, (directory / "stderr.txt").open("wb") as err:
        pid = os.posix_spawnp(args[0], args, os.environ, setpgroup=0, file_actions=[
            (os.POSIX_SPAWN_DUP2, out.fileno(), 1), (os.POSIX_SPAWN_DUP2, err.fileno(), 2)])
        timed_out = False
        while True:
            finished, status, usage = os.wait4(pid, os.WNOHANG)
            if finished == pid: break
            if time.monotonic() - start >= seconds:
                timed_out = True
                try: os.killpg(pid, signal.SIGINT)
                except ProcessLookupError: pass
                deadline = time.monotonic() + 3
                while True:
                    finished, status, usage = os.wait4(pid, os.WNOHANG)
                    if finished == pid: break
                    if time.monotonic() >= deadline:
                        try: os.killpg(pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                        _, status, usage = os.wait4(pid, 0); break
                    time.sleep(.01)
                break
            time.sleep(.01)
    resources = {"command": args, "exit_code": os.waitstatus_to_exitcode(status),
        "wall_seconds": time.monotonic() - start, "user_cpu_seconds": usage.ru_utime,
        "system_cpu_seconds": usage.ru_stime,
        "peak_rss_kib": usage.ru_maxrss / 1024 if platform.system() == "Darwin" else usage.ru_maxrss,
        "external_deadline_reached": timed_out}
    lab.save(directory / "resources.json", resources)
    return resources


def collect(args):
    if platform.system() != "Darwin":
        raise RuntimeError("BSD study requires macOS Ethernet BPF source")
    fixtures = json.loads(Path(args.fixtures).read_text())
    if set(fixtures) != set(PROTOCOL["roles"]):
        raise ValueError("both independently allocated configuration roles required")
    if any(fixtures["development"][key] == fixtures["reserved"][key] for key in ("target_v4", "target_v6", "next_hop_mac")):
        raise ValueError("BSD reserved configuration not distinct")
    assigned = lab.command("ifconfig", args.interface)
    for scope in fixtures.values():
        bsd.validate_scope(scope)
        if not all(scope[f"source_v{family}"] in assigned for family in (4, 6)):
            raise ValueError("BSD study source addresses not assigned")
    out = Path(args.output).resolve(); out.mkdir(mode=0o700); os.umask(0o077)
    binary = str(Path(args.binary).resolve())
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    lab.save(out / "protocol.json", PROTOCOL)
    manifest = {"fixtures": fixtures, "planned": planned_runs(), "results": [], "completed": False,
        "protocol_sha256": lab.digest(out / "protocol.json"), "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    lock = threading.Lock()
    def persist():
        temporary = out / "manifest.json.tmp"
        lab.save(temporary, manifest); temporary.replace(out / "manifest.json")
    persist()  # Denominators, order and protocol frozen before collector traffic.
    lab.save(out / "environment.json", {"platform": platform.platform(), "nyxr_sha256": lab.digest(Path(binary)),
        "buildinfo": lab.command("go", "version", "-m", binary), "interface": assigned,
        "collector_sha256": lab.digest(Path(__file__)), "helper_sha256": lab.digest(HERE / "bsd-study-endpoint.c"),
        "concurrent_fixtures": 2})
    def worker(role):
        scope = fixtures[role]
        for entry in (p for p in manifest["planned"] if p["role"] == role):
            if stop.is_set(): break
            directory = out / entry["id"]; directory.mkdir()
            with lock:
                manifest["results"].append({"id": entry["id"], "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()})
                persist()
            request = ("CLEAN" if entry["impairment"] == "clean" else "IMPAIR" if entry["impairment"] == "loss-jitter" else "DROP") + str(entry["sack"])
            before = control(scope, request)
            lab.save(directory / "truth-before.json", before)
            validate_truth(before, scope, entry)
            measure_one(binary, args.interface, scope, entry, directory)
            after = control(scope)
            lab.save(directory / "truth-after.json", after)
            validate_truth(after, scope, entry)
            print(entry["id"], "collected", flush=True)
    try:
        for role, scope in fixtures.items():
            state = control(scope)
            lab.save(out / f"truth-initial-{role}.json", state)
            scope["fixture"] = validate_truth(state, scope)
            scope["original_sack"] = state["original_sack"]
        if fixtures["development"]["fixture"] == fixtures["reserved"]["fixture"]:
            raise ValueError("BSD fixture identities are not distinct")
        persist()
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(worker, role) for role in PROTOCOL["roles"]]
            for future in as_completed(futures):
                try: future.result()
                except BaseException:
                    stop.set(); raise
        manifest["completed"] = not stop.is_set() and len(manifest["results"]) == len(manifest["planned"])
    except BaseException as error:
        manifest["collection_error"] = str(error); raise
    finally:
        cleanups = {}
        for role, scope in fixtures.items():
            try:
                state = control(scope, "STOP")
                lab.save(out / f"cleanup-{role}.json", state)
                cleanups[role] = state.get("fixture") == scope.get("fixture") and state.get("listeners_closed") is True and state.get("sack") == scope.get("original_sack") and state.get("condition") == "clean"
            except Exception as error:
                cleanups[role] = False; manifest[f"cleanup_error_{role}"] = str(error)
        manifest["cleanup_verified"] = all(cleanups.values())
        persist()
    summary = analyze(out, binary)
    print(json.dumps(summary["strata"], indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "analyze"))
    parser.add_argument("--binary", required=True); parser.add_argument("--output", required=True)
    parser.add_argument("--fixtures"); parser.add_argument("--interface")
    args = parser.parse_args()
    if args.command == "run":
        if not args.fixtures or not args.interface: parser.error("run requires explicit fixture scopes and source interface")
        collect(args)
    else: print(json.dumps(analyze(Path(args.output), args.binary)["strata"], indent=2))
