"""HORIZON Phase 3 (#69) live environmental-control campaign.

Reuses lab.py's isolated namespace topology, impairments and independent
capture checks. HZ-001 (SACK treatment) and HZ-002 (A/A) both carry
interleaved reference probes and declared confounders. Only `run` sends
traffic, inside private namespaces; `analyze` is offline.
"""
import argparse
import base64
import collections
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import time

import lab

HERE = Path(__file__).resolve().parent
PROTOCOL = json.loads((HERE / "phase3-protocol.json").read_text())


def experiment(kind, target, seed):
    def arm(profile):
        return {"steps": [{"send": {"protocol": "tcp", "flags": ["SYN"], "dstPort": 443, "optionsProfile": profile}},
                          {"observe": {"windowMs": PROTOCOL["window_ms"]}}]}
    variable = PROTOCOL["experiments"][kind]["changed_variable"]
    return {"apiVersion": "horizon.nyxr.io/v1alpha2", "kind": "Experiment",
            "metadata": {"name": f"{kind}-phase3-live"},
            "spec": {"scope": {"targets": [target], "tcpPorts": [443]},
                     "changedVariable": variable, "confounders": PROTOCOL["confounders"],
                     "control": arm("baseline"),
                     "treatment": arm("sack-permitted" if variable == "sackPermitted" else "baseline"),
                     "execution": {"replicates": PROTOCOL["replicates"], "randomizedOrder": True, "seed": seed,
                                   "washoutMs": PROTOCOL["washout_ms"], "referenceEvery": PROTOCOL["reference_every"]},
                     "limits": {"maxPackets": PROTOCOL["max_packets"], "maxDurationSeconds": PROTOCOL["max_duration_seconds"],
                                "packetsPerSecond": PROTOCOL["packets_per_second"], "maxConcurrentFlows": 1,
                                "maxReceiveFrames": 64, "maxMemoryBytes": 2097152},
                     "capture": {"maxBytes": 1048576}}}


def collect(args):
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise RuntimeError("live collection requires root on an isolated Linux host/container")
    binary = str(Path(args.binary).resolve())
    out = Path(args.output).resolve()
    out.mkdir(mode=0o700)
    os.umask(0o077)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt("cancelled")))
    lab.save(out / "protocol.json", PROTOCOL)
    lab.save(out / "environment.json", {"platform": platform.platform(), "nyxr_version": lab.command(binary, "version").strip(),
                                        "nyxr_sha256": lab.digest(Path(binary)), "collector_sha256": lab.digest(HERE / "phase3.py"),
                                        "topology_sha256": lab.digest(HERE / "lab.py"), "endpoint_sha256": lab.digest(HERE / "endpoint.py"),
                                        "image_id": os.environ.get("HORIZON_LAB_IMAGE_ID")})
    planned = []
    for case in PROTOCOL["cases"]:
        for family in (4, 6):
            for impairment in ("clean", "loss-jitter"):
                for kind in PROTOCOL["experiments"]:
                    for repeat in range(args.runs):
                        planned.append({"id": f"{kind}-{case}-v{family}-{impairment}-{repeat:03d}", "kind": kind, "case": case,
                                        "family": family, "impairment": impairment, "seed": PROTOCOL["seed_start"] + repeat,
                                        "expected": PROTOCOL["expected"].get(f"{kind}/{case}/{impairment}")})
    manifest = {"version": PROTOCOL["version"], "protocol_sha256": lab.digest(out / "protocol.json"),
                "planned": planned, "results": [], "completed": False}
    lab.save(out / "manifest.json", manifest)  # freeze denominators before traffic
    topology = None
    try:
        for entry in planned:
            directory = out / entry["id"]
            directory.mkdir()
            result = {"id": entry["id"]}
            manifest["results"].append(result)
            lab.save(out / "manifest.json", manifest)
            if topology is None or topology.case != entry["case"]:
                if topology:
                    topology.close()
                topology = lab.Topology(entry["case"])
                topology.setup(directory)
            topology.impair(entry["impairment"])
            lab.save(directory / "truth-before.json", topology.truth())
            target, source = ("10.77.0.2", "10.77.0.1") if entry["family"] == 4 else ("fd77:1::2", "fd77:1::1")
            lab.save(directory / "experiment.json", experiment(entry["kind"], target, entry["seed"]))
            common = [binary, "horizon", "resolve", "--experiment", str(directory / "experiment.json"), "--policy", "lab",
                      "--allow-targets", target, "--allow-ports", "443"]
            (directory / "plan.json").write_text(lab.command(*common, "--dry-run"))
            run = directory / "horizon"
            run.mkdir()
            capture = topology.launch(0, ["tcpdump", "--immediate-mode", "-i", "front", "-U", "-s", "0", "-w",
                                         str(run / "traffic.pcap"), "tcp port 443"], run / "capture.log")
            try:
                for _ in range(100):
                    if "listening on" in (run / "capture.log").read_text():
                        break
                    time.sleep(.02)
                else:
                    raise RuntimeError("independent capture readiness timed out")
                cmd = common + ["--interface", "front", "--source-ip", source, "--next-hop-mac", "02:00:00:00:00:02",
                                "--output", str(run / "report.json")]
                result["horizon"] = lab.measure(["ip", "netns", "exec", topology.names[0], *cmd], run)
                time.sleep(.15)
            finally:
                if capture.poll() is None:
                    capture.send_signal(signal.SIGINT)
                    capture.wait(timeout=5)
            lab.save(directory / "truth-after.json", topology.truth())
            lab.save(out / "manifest.json", manifest)
            print(entry["id"], "collected", flush=True)
        manifest["completed"] = True
    except BaseException as error:
        manifest["collection_error"] = str(error) + ("\n" + str(error.output or "") if isinstance(error, subprocess.CalledProcessError) else "")
        raise
    finally:
        if topology:
            topology.close()
        lab.save(out / "manifest.json", manifest)
    analyze(out, binary)


def analyze(out, binary):
    manifest = json.loads((out / "manifest.json").read_text())
    if manifest["version"] != PROTOCOL["version"] or json.loads((out / "protocol.json").read_text()) != PROTOCOL:
        raise ValueError("protocol identity mismatch")
    plans = {p["id"]: p for p in manifest["planned"]}
    rows = []
    for result in manifest["results"]:
        entry = plans[result["id"]]
        directory = out / entry["id"]
        row = {**entry}
        try:
            report_path = directory / "horizon" / "report.json"
            report = json.loads(lab.command(binary, "horizon", "replay", str(report_path)))["report"]
            target = "10.77.0.2" if entry["family"] == 4 else "fd77:1::2"
            if report["backend"].startswith("synthetic") or report["experiment"] != experiment(entry["kind"], target, entry["seed"]):
                raise ValueError("report differs from the registered live experiment")
            sack = PROTOCOL["cases"][entry["case"]]["sack"]
            for when in ("before", "after"):
                truth = json.loads((directory / f"truth-{when}.json").read_text())
                hosts = [h for name, h in truth.items() if name.endswith("-dst")]
                if len(hosts) != 1 or hosts[0]["sack"].strip() != f"net.ipv4.tcp_sack = {sack}":
                    raise ValueError("recorded kernel SACK setting contradicts ground truth")
            traffic, frames = lab.pcap(directory / "horizon" / "traffic.pcap")
            drops = re.search(r"(\d+) packets dropped by kernel", (directory / "horizon" / "capture.log").read_text())
            if not drops or int(drops[1]) != 0:
                raise ValueError("independent capture drops or missing drop counters")
            sent = collections.Counter(base64.b64decode(e["frame"], validate=True)
                                       for t in report["trials"] for e in t["evidence"] if e["direction"] != "rx")
            if sent - frames:
                raise ValueError("runner transmissions missing from independent capture")
            if not report["completed"] or report["backendDrops"] or report["packetsTx"] > PROTOCOL["max_packets"]:
                raise ValueError("incomplete run, backend drops or budget violation")
            env = report["environment"]
            lat = env["latency"]
            row.update({"outcome": lab.outcome(report), "conclusion": report["comparison"]["conclusion"],
                        "p_value": report["comparison"]["pValue"], "packets_tx": report["packetsTx"],
                        "independent_packets": traffic["packets"],
                        "timeouts": sum(t["features"]["responseClass"] == "no-response" for t in report["trials"]),
                        "gating_flags": env["gatingFlags"], "quality_flags": env["qualityFlags"],
                        "references": [env["responses"]["referencesAnswered"], env["responses"]["references"]],
                        "throttling_p": env["responses"]["throttlingPValue"], "carryover_p": env["carryover"]["pValue"],
                        "paired_rtt_ms": None if lat["pairedDifferenceMedianNs"] is None else lat["pairedDifferenceMedianNs"] / 1e6,
                        "paired_rtt_interval_ms": None if lat["pairedDifferenceLowerNs"] is None else
                            [lat["pairedDifferenceLowerNs"] / 1e6, lat["pairedDifferenceUpperNs"] / 1e6],
                        "report_sha256": lab.digest(report_path)})
        except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
            row["error"] = str(error)
        rows.append(row)
    strata = collections.defaultdict(list)
    for entry in manifest["planned"]:
        strata[f'{entry["kind"]}/{entry["case"]}/v{entry["family"]}/{entry["impairment"]}'].append(entry["id"])
    by_id = {r["id"]: r for r in rows}
    summary = {}
    for key, ids in strata.items():
        got = [by_id[i] for i in ids if i in by_id]
        valid = [r for r in got if "error" not in r]
        kind, case = key.split("/")[:2]
        null = kind == "hz-002" or case == "null"
        expected = plans[ids[0]]["expected"]
        summary[key] = {"planned": len(ids), "invalid": len(got) - len(valid), "missing": len(ids) - len(got),
                        "outcomes": dict(collections.Counter(r["outcome"] for r in valid)),
                        "gating_flags": dict(collections.Counter(f for r in valid for f in r["gating_flags"])),
                        "quality_flags": dict(collections.Counter(f for r in valid for f in r["quality_flags"])),
                        "expected": expected,
                        "correct_all_planned": sum(r["outcome"] == expected for r in valid) / len(ids) if expected else None,
                        "false_positives": sum(r["outcome"] in ("difference", "reverse-difference") for r in valid) if null else None}
    fps = sum(s["false_positives"] or 0 for s in summary.values())
    effects = [s for k, s in summary.items() if s["expected"] == "difference"]
    complete = all(not s["missing"] and not s["invalid"] for s in summary.values())
    output = {"version": PROTOCOL["version"], "completed": manifest["completed"], "rows": rows, "strata": summary,
              "false_positives": fps,
              "gates": {"zero_false_positives": complete and fps <= PROTOCOL["gates"]["false_positives_allowed"],
                        "clean_effect_accuracy": complete and all(s["correct_all_planned"] >= PROTOCOL["gates"]["clean_effect_minimum_accuracy_all_planned"] for s in effects)},
              "limitations": PROTOCOL["limitations"]}
    lab.save(out / "summary.json", output)
    print(json.dumps({k: v for k, v in output.items() if k != "rows"}, indent=2))
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--binary", required=True)
    run.add_argument("--output", required=True)
    run.add_argument("--runs", type=int, default=1)
    offline = commands.add_parser("analyze")
    offline.add_argument("--binary", required=True)
    offline.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "run":
        if not 1 <= args.runs <= 60:
            parser.error("runs must be between 1 and 60")
        collect(args)
    else:
        analyze(Path(args.output).resolve(), str(Path(args.binary).resolve()))


if __name__ == "__main__":
    main()
