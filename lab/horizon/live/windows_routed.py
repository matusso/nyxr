"""Native Windows endpoint behind a routed FreeBSD hop, with a SackOpts null attempt.

The guest runs windows-endpoint.ps1 -StudyControl; the router runs bsd-router.sh,
reachable only through an SSH forced command accepting TRUTH/CLEAN/DROP.
Each phase/family is a separate collection with its own frozen denominator.
"""
import argparse
import base64
import collections
import datetime
import ipaddress
import json
import os
from pathlib import Path
import platform
import random
import re
import signal
import subprocess

import bsd_study
import lab
import windows
import windows_study

HERE = Path(__file__).resolve().parent
PROTOCOL = json.loads((HERE / "windows-routed-protocol.json").read_text())
PHASES = sorted(PROTOCOL["phases"], key=lambda name: PROTOCOL["phases"][name]["order"])
REQUESTS = {"clean": "CLEAN", "drop": "DROP"}
for key in ("replicates", "window_ms", "washout_ms", "packets_per_second", "max_packets", "max_duration_seconds",
            "alpha", "confidence", "maximum_false_positive_rate", "null_runs_per_stratum"):
    if lab.PROTOCOL[key] != PROTOCOL[key]:
        raise RuntimeError(f"routed protocol {key} differs from the shared experiment settings")


def interface_routes(interface):
    """Only the measurement segment's routes; the full table exposes unrelated networks."""
    return "\n".join(line for line in lab.command("netstat", "-rn").splitlines()
                     if interface in line.split() or not line.strip() or line.endswith(":") or line.startswith("Destination"))


def plan(phase, family):
    spec = PROTOCOL["phases"][phase]
    rng = random.Random(PROTOCOL["order_seed"] + 10 * spec["order"] + family)
    rows = []
    if "blocks" in spec:
        for block in range(spec["blocks"]):
            batch = [{"condition": condition, "block": block, "repeat": repeat}
                     for condition, count in spec["per_block"].items() for repeat in range(count)]
            rng.shuffle(batch)
            rows.extend(batch)
        rows.extend({"condition": "drop", "block": spec["blocks"], "repeat": repeat} for repeat in range(spec["drop_runs"]))
    else:
        rows = [{"condition": "clean", "block": 0, "repeat": repeat} for repeat in range(spec["clean_runs"])]
    for index, row in enumerate(rows):
        row.update(id=f"windows-routed-{phase}-v{family}-{row['condition']}-{row['block']:02d}-{row['repeat']}",
                   seed=spec["seed_start"][str(family)] + index, phase=phase, family=family, platform="Windows",
                   impairment=row["condition"], expected=spec["expected"][row["condition"]], sackopts=spec["sackopts"])
    return rows


def topology(family):
    scope = PROTOCOL["topology"][str(family)]
    for name in ("source", "router_source_side", "router_target_side", "target"):
        windows.private_address(scope[name])
    source = ipaddress.ip_network(f"{scope['source']}/{scope['prefix_length']}", strict=False)
    target = ipaddress.ip_network(f"{scope['target']}/{scope['prefix_length']}", strict=False)
    if source == target or ipaddress.ip_address(scope["router_source_side"]) not in source \
            or ipaddress.ip_address(scope["router_target_side"]) not in target:
        raise ValueError("routed source and target must use distinct prefixes joined by the router")
    return dict(scope, source_prefix=str(source), target_prefix=str(target))


def router(args, request):
    if request not in ("TRUTH", "CLEAN", "DROP"):
        raise ValueError("unregistered router control")
    text = subprocess.run(["ssh", "-i", args.router_key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
        "-o", f"UserKnownHostsFile={args.router_known_hosts}", "-o", "ConnectTimeout=10",
        f"root@{args.router}", request], capture_output=True, text=True, timeout=60, check=True).stdout
    return parse_router(text)


def parse_router(text):
    header, _, body = text.partition("--- system\n")
    state = dict(line.split("=", 1) for line in header.splitlines() if "=" in line)
    if not body.rstrip().endswith("--- end"):
        raise ValueError("truncated router truth")
    state["text"] = "--- system\n" + body
    return state


def sysctl(state, name):
    match = re.search(r"^" + re.escape(name) + r":\s*(.+)$", state["text"], re.M)
    if not match:
        raise ValueError(f"router {name} missing")
    return match[1].strip()


def router_rules(state):
    section = state["text"].split("--- ipfw\n", 1)[1].split("--- modules\n", 1)[0]
    rules = collections.defaultdict(list)
    for line in section.splitlines():
        match = re.match(r"(\d{5})\s+(\d+)\s+(\d+)\s+(.*)$", line.strip())
        if match:
            rules[int(match[1])].append({"packets": int(match[2]), "bytes": int(match[3]), "rule": match[4]})
    return rules


def validate_router(state, condition, fixture=None, boottime=None, interface=None):
    if not state.get("fixture") or (fixture is not None and state["fixture"] != fixture):
        raise ValueError("router fixture identity changed")
    if not re.fullmatch(r"[a-z]+[0-9]+", state.get("interface", "")) or interface not in (None, state["interface"]):
        raise ValueError("router interface differs from the recorded fixture")
    if state.get("condition") != condition:
        raise ValueError("router condition differs from registration")
    if boottime is not None and sysctl(state, "kern.boottime") != boottime:
        raise ValueError("router rebooted during collection")
    expected = {"net.inet.ip.forwarding": "1", "net.inet6.ip6.forwarding": "1", "net.inet.ip.redirect": "0",
                "net.inet6.ip6.redirect": "0", "net.inet.ip.fw.enable": "1", "net.inet6.ip6.fw.enable": "1"}
    for name, value in expected.items():
        if sysctl(state, name) != value:
            raise ValueError(f"router {name} differs from routed fixture")
    rules = router_rules(state)
    # FreeBSD 15 also lists an orphaned-dynamic-state counter under 65535.
    if not any(r["rule"] == "allow ip from any to any" for r in rules.get(65535, [])):
        raise ValueError("router default allow rule missing")
    if any(len(value) != 1 for number, value in rules.items() if number != 65535):
        raise ValueError("router rule number duplicated")
    owned = {number: value[0] for number, value in rules.items() if number != 65535}
    denied = {"clean": set(), "drop": {60066, 60067}}[condition]
    if set(owned) != {60064, 60065} | denied:
        raise ValueError("router rules exceed registered set")
    for family, numbers in ((4, (60064, 60066)), (6, (60065, 60067))):
        scope = PROTOCOL["topology"][str(family)]
        clause = f"tcp from {scope['target']} 443 to {scope['source']} out xmit {state['interface']} tcpflags syn,ack"
        if owned[numbers[0]]["rule"] != "count " + clause:
            raise ValueError("router path counter scope differs")
        if numbers[1] in denied and owned[numbers[1]]["rule"] != "deny " + clause:
            raise ValueError("router drop rule exceeds explicit response scope")
    # v1's dummynet shaping panicked this router; v2 forwards without it.
    if re.search(r"\bdummynet\.ko\b", state["text"].split("--- modules\n", 1)[1]):
        raise ValueError("router dummynet loaded")
    return state["fixture"]


def counter(state, number):
    rules = router_rules(state)
    if len(rules.get(number, [])) != 1:
        raise ValueError("router counter missing")
    return rules[number][0]["packets"]


def validate_windows(state, entry, scope, target_mac, fixture=None, boot=None, change=None):
    windows_study.validate_truth(state, scope["target"], scope["source"], target_mac, fixture, False)
    present, value = state.get("sackopts_registry_present"), state.get("sackopts_registry_value")
    if entry["sackopts"] is None and present:
        raise ValueError("Windows SackOpts present in native phase")
    if entry["sackopts"] is not None and (present is not True or value != entry["sackopts"]):
        raise ValueError("Windows SackOpts differs from registered control")
    if boot is not None and state.get("last_boot_utc") != boot:
        raise ValueError("Windows rebooted during collection")
    if change is not None and not state.get("last_boot_utc", "") > change:
        raise ValueError("Windows has not restarted since the SackOpts change")
    routes = state.get("routes", [])
    if not any(r.get("DestinationPrefix") == scope["source_prefix"] and r.get("NextHop") == scope["router_target_side"]
               for r in routes):
        raise ValueError("Windows route to the source prefix does not use the router")
    return state


def sack_counts(report):
    counts = collections.Counter()
    for trial in report["trials"]:
        features = trial["features"]
        if features["responseClass"] == "syn-ack":
            counts[trial["arm"] + "_synack"] += 1
            counts[trial["arm"] + "_sack"] += bsd_study.sack_option(features.get("tcpOptions", ""))
    return {name: counts[name] for name in ("treatment_synack", "treatment_sack", "control_synack", "control_sack")}


def feasibility_pass(summaries):
    rows = [row for summary in summaries for row in summary["rows"]]
    planned = sum(len(plan("feasibility", family)) for family in PROTOCOL["families"])
    return bool(len(summaries) == len(PROTOCOL["families"]) and len(rows) == planned
                and all(s["phase"] == "feasibility" for s in summaries)
                and {s["family"] for s in summaries} == set(PROTOCOL["families"])
                and all("error" not in row and row["outcome"] == "no-difference"
                        and row["treatment_sack"] == 0 and row["control_sack"] == 0 for row in rows))


def collect(args):
    if platform.system() != "Darwin":
        raise RuntimeError("collector requires macOS Ethernet BPF")
    family, phase = args.family, args.phase
    scope = topology(family)
    if scope["source"] not in lab.command("ifconfig", args.interface):
        raise ValueError("routed study source address not assigned")
    change = None
    if PROTOCOL["phases"][phase]["sackopts"] is not None or phase == "restore":
        if not args.sackopts_record:
            raise ValueError("SackOpts phases require the recorded native registry change")
        change = json.loads(Path(args.sackopts_record).read_text())
        if change.get("value") != PROTOCOL["phases"][phase]["sackopts"]:
            raise ValueError("SackOpts change record differs from phase")
    if phase == "null":
        gates = [analyze(Path(path), args.binary) for path in args.feasibility or []]
        if not feasibility_pass(gates):
            raise ValueError("feasibility stopping rule not passed; null phase is not executed")
    binary = str(Path(args.binary).resolve())
    out = Path(args.output).resolve()
    out.mkdir(mode=0o700)
    os.umask(0o077)
    lab.save(out / "protocol.json", PROTOCOL)
    manifest = {"version": PROTOCOL["version"], "phase": phase, "family": family,
                "protocol_sha256": lab.digest(out / "protocol.json"), "planned": plan(phase, family), "results": [],
                "scope": scope, "router_mac": args.router_mac, "target_mac": args.target_mac,
                "interface": args.interface, "completed": False,
                "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    if change is not None:
        lab.save(out / "sackopts-change.json", change)
        manifest["sackopts_change_utc"] = change["changed_utc"]
    lab.save(out / "manifest.json", manifest)  # Denominator frozen before traffic.
    lab.save(out / "environment.json", {"platform": platform.platform(), "nyxr_sha256": lab.digest(Path(binary)),
        "buildinfo": lab.command("go", "version", "-m", binary), "interface": lab.command("ifconfig", args.interface),
        "routes": interface_routes(args.interface), "collector_sha256": lab.digest(Path(__file__)),
        "helper_sha256": lab.digest(HERE / "windows-endpoint.ps1"),
        "router_sha256": lab.digest(HERE / "bsd-router.sh"),
        "setup_sha256": lab.digest(HERE / "windows-routed-setup.ps1")})

    def terminate(_signal, _frame):
        raise KeyboardInterrupt("routed collection cancelled")
    signal.signal(signal.SIGTERM, terminate)
    try:
        initial_router = router(args, "CLEAN")
        lab.save(out / "router-initial.json", initial_router)
        manifest["router_fixture"] = validate_router(initial_router, "clean")
        manifest["router_boottime"] = sysctl(initial_router, "kern.boottime")
        manifest["router_interface"] = initial_router["interface"]
        initial = windows_study.control(scope["target"], scope["source"])
        lab.save(out / "truth-initial.json", initial)
        manifest["fixture"] = initial.get("fixture")
        validate_windows(initial, manifest["planned"][0], scope, args.target_mac, manifest["fixture"], None,
                         manifest.get("sackopts_change_utc"))
        manifest["windows_boot_utc"] = initial["last_boot_utc"]
        lab.save(out / "manifest.json", manifest)
        for entry in manifest["planned"]:
            directory = out / entry["id"]
            directory.mkdir()
            manifest["results"].append({"id": entry["id"], "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()})
            lab.save(out / "manifest.json", manifest)
            states = {"router-before": router(args, REQUESTS[entry["condition"]]),
                      "truth-before": windows_study.control(scope["target"], scope["source"])}
            for name, state in states.items():
                lab.save(directory / f"{name}.json", state)
            validate_router(states["router-before"], entry["condition"], manifest["router_fixture"], manifest["router_boottime"],
                            manifest["router_interface"])
            validate_windows(states["truth-before"], entry, scope, args.target_mac, manifest["fixture"], manifest["windows_boot_utc"])
            bsd_study.measure_one(binary, args.interface, {f"target_v{family}": scope["target"],
                f"source_v{family}": scope["source"], "next_hop_mac": args.router_mac}, entry, directory)
            states = {"truth-after": windows_study.control(scope["target"], scope["source"]),
                      "router-after": router(args, "TRUTH")}
            for name, state in states.items():
                lab.save(directory / f"{name}.json", state)
            validate_windows(states["truth-after"], entry, scope, args.target_mac, manifest["fixture"], manifest["windows_boot_utc"])
            validate_router(states["router-after"], entry["condition"], manifest["router_fixture"], manifest["router_boottime"],
                            manifest["router_interface"])
            print(entry["id"], "collected", flush=True)
        manifest["completed"] = True
    except BaseException as error:
        manifest["collection_error"] = str(error)
        raise
    finally:
        try:
            lab.save(out / "router-final.json", router(args, "CLEAN"))
        except Exception as error:
            manifest["router_cleanup_error"] = str(error)
        if manifest.get("fixture"):
            try:
                cleanup = windows_study.control(scope["target"], scope["source"], "STOP")
                lab.save(out / "cleanup.json", cleanup)
                manifest["cleanup_verified"] = cleanup.get("fixture") == manifest["fixture"] and not any(
                    cleanup.get(name) for name in ("fixture_rule_present", "control_rule_present", "block_rule_present"))
            except Exception as error:
                manifest["cleanup_error"] = str(error)
        lab.save(out / "manifest.json", manifest)
    print(json.dumps(analyze(out, binary)["strata"], indent=2))


def analyze(out, binary):
    manifest = json.loads((out / "manifest.json").read_text())
    if manifest.get("version") != PROTOCOL["version"] or json.loads((out / "protocol.json").read_text()) != PROTOCOL \
            or manifest.get("protocol_sha256") != lab.digest(out / "protocol.json"):
        raise ValueError("routed study protocol differs from registration")
    phase, family = manifest["phase"], manifest["family"]
    planned = plan(phase, family)
    scope = topology(family)
    if manifest["planned"] != planned or manifest["scope"] != scope:
        raise ValueError("routed study denominator/seed/scope differs")
    indexed, rows, seen = {entry["id"]: entry for entry in planned}, [], set()
    for result in manifest["results"]:
        entry = indexed.get(result["id"])
        if entry is None or entry["id"] in seen:
            raise ValueError("unknown/duplicate routed study run")
        seen.add(entry["id"])
        directory = out / entry["id"]
        row = dict(entry)
        try:
            truths = {name: json.loads((directory / f"{name}.json").read_text())
                      for name in ("router-before", "truth-before", "truth-after", "router-after")}
            for name in ("router-before", "router-after"):
                validate_router(truths[name], entry["condition"], manifest["router_fixture"], manifest["router_boottime"],
                            manifest["router_interface"])
            for name in ("truth-before", "truth-after"):
                validate_windows(truths[name], entry, scope, manifest["target_mac"], manifest["fixture"],
                                 manifest["windows_boot_utc"], manifest.get("sackopts_change_utc"))
            path_rule, drop_rule = (60064, 60066) if family == 4 else (60065, 60067)
            row["routed_synack_packets"] = counter(truths["router-after"], path_rule) - counter(truths["router-before"], path_rule)
            if row["routed_synack_packets"] <= 0:
                raise ValueError("Windows replies did not traverse the registered router path")
            if entry["condition"] != "clean":
                row["dropped_packets"] = counter(truths["router-after"], drop_rule) - counter(truths["router-before"], drop_rule)
                if row["dropped_packets"] <= 0:
                    raise ValueError("Windows replies did not traverse the registered drop rule")
            envelope = json.loads((directory / "horizon" / "report.json").read_text())
            replay = json.loads(lab.command(binary, "horizon", "replay", str(directory / "horizon" / "report.json")))
            if replay != envelope:
                raise ValueError("routed canonical replay changed saved report")
            report = replay["report"]
            if report["backend"].startswith("synthetic"):
                raise ValueError("synthetic routed evidence rejected")
            expected = lab.experiment(scope["target"], entry["seed"])
            if report["experiment"] != expected or json.loads((directory / "experiment.json").read_text()) != expected:
                raise ValueError("routed experiment differs from frozen plan")
            row.update(lab.metrics(report))
            row.update(sack_counts(report))
            row["complete_pairs"] = report["comparison"]["completePairs"]
            scanner = lab.scan_result(directory / "scan" / "stdout.txt", scope["target"])
            row.update(scan_state=scanner["state"],
                       scan_correct=scanner["state"] == ("filtered" if entry["condition"] == "drop" else "open"))
            for mode in ("scan", "horizon"):
                run = directory / mode
                resources = json.loads((run / "resources.json").read_text())
                row[mode + "_resources"] = resources
                traffic, frames = lab.pcap(run / "traffic.pcap")
                row[mode + "_traffic"] = traffic
                drops = re.search(r"(\d+) packets dropped by kernel", (run / "capture.log").read_text())
                if (not drops or int(drops[1]) or resources["exit_code"] or resources["external_deadline_reached"]
                        or resources["wall_seconds"] > PROTOCOL["max_duration_seconds"]
                        or (run / "traffic.pcap").stat().st_size > 1048576):
                    raise ValueError(f"{mode}: child/capture failure or budget exceeded")
                if mode == "scan":
                    windows.validate_scan_capture(frames, scope["source"], scope["target"], scanner.get("packets_tx"))
                else:
                    sent = collections.Counter(base64.b64decode(e["frame"], validate=True)
                        for trial in report["trials"] for e in trial["evidence"] if e["direction"] != "rx")
                    if sent - frames:
                        raise ValueError("routed HORIZON TX absent from independent capture")
            if not row["completed"] or row["backend_drops"] or row["runner_tx_packets"] > PROTOCOL["max_packets"]:
                raise ValueError("incomplete/drop/budget-invalid routed report")
        except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
            row["error"] = str(error)
        rows.append(row)
    strata = {}
    for condition in dict.fromkeys(entry["condition"] for entry in planned):
        group = [entry for entry in planned if entry["condition"] == condition]
        ids = {entry["id"] for entry in group}
        selected = [row for row in rows if row["id"] in ids]
        expected = group[0]["expected"]
        value = lab.stratum(selected, len(group), expected)
        value["expected"] = expected
        value["conditional_numerical_null_gate_pass"] = value.pop("null_gate_pass")
        value["conditional_numerical_clean_effect_gate_pass"] = bool(
            condition == "clean" and expected == "difference" and value["planned"] >= PROTOCOL["effect_runs_per_stratum"]
            and value["accuracy_all_planned"] >= PROTOCOL["minimum_clean_effect_accuracy"]
            and value["invalid"] == 0 and value["missing"] == 0)
        value["scanner_correct"] = sum(bool(row.get("scan_correct")) for row in selected)
        value["temporal_diagnostics"] = bsd_study.diagnostics(selected)
        strata[f"{phase}-v{family}-{condition}"] = value
    summary = {"version": PROTOCOL["version"], "phase": phase, "family": family, "rows": rows, "strata": strata,
               "completed": manifest.get("completed", False), "cleanup_verified": manifest.get("cleanup_verified", False),
               "independence_established": False, "issue_66_complete": False, "limitations": PROTOCOL["limitations"]}
    lab.save(out / "summary.json", summary)
    return summary


def combine(outputs, binary):
    """All-planned accounting across phases, including phases stopped by the registered rule."""
    summaries = {(s["phase"], s["family"]): s for s in (analyze(Path(path), binary) for path in outputs)}
    feasible = feasibility_pass([summaries[key] for key in summaries if key[0] == "feasibility"])
    strata, not_executed = {}, {}
    for phase in PHASES:
        for family in PROTOCOL["families"]:
            if (phase, family) in summaries:
                strata.update(summaries[(phase, family)]["strata"])
            else:
                not_executed[f"{phase}-v{family}"] = {"planned": len(plan(phase, family)),
                    "reason": "stopped by feasibility rule" if phase == "null" and not feasible else "missing collection"}
    if feasible is False and any(key[0] == "null" for key in summaries):
        raise ValueError("null phase executed despite failed feasibility rule")
    return {"version": PROTOCOL["version"], "feasibility_pass": feasible, "strata": strata,
            "not_executed": not_executed, "independence_established": False, "issue_66_complete": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "analyze", "combine"))
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", nargs="+", required=True)
    parser.add_argument("--phase", choices=PHASES)
    parser.add_argument("--family", type=int, choices=PROTOCOL["families"])
    parser.add_argument("--interface")
    parser.add_argument("--router")
    parser.add_argument("--router-key")
    parser.add_argument("--router-known-hosts")
    parser.add_argument("--router-mac")
    parser.add_argument("--target-mac")
    parser.add_argument("--sackopts-record")
    parser.add_argument("--feasibility", nargs="*")
    args = parser.parse_args()
    if args.command == "run":
        if len(args.output) != 1 or not all((args.phase, args.family, args.interface, args.router, args.router_key,
                                              args.router_known_hosts, args.router_mac, args.target_mac)):
            parser.error("run requires one output and explicit phase/family/interface/router/MAC scope")
        args.output = args.output[0]
        collect(args)
    elif args.command == "analyze":
        for path in args.output:
            print(json.dumps(analyze(Path(path), args.binary)["strata"], indent=2))
    else:
        print(json.dumps(combine(args.output, args.binary), indent=2))
