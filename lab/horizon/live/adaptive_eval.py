"""HORIZON adaptive planner and behavior profiles (#72): retrospective evaluation.

Replays the recorded #70 cross-port corpus through `nyxr horizon adapt
--replay` and compares adaptive configurations with the fixed (full-coverage)
study of the same recorded roles, under the registered adaptive-protocol.json.
Offline: it never sends traffic.
"""
import argparse
import datetime
import json
from pathlib import Path
import re
import subprocess
import tempfile

import crossport

HERE = Path(__file__).resolve().parent
PROTOCOL = json.loads((HERE / "adaptive-protocol.json").read_text())
TRUTH = {name: t["truth"] for name, t in crossport.PROTOCOL["topologies"].items()}
STATEMENTS = ("classification", "direction", "cooldown", "rate-limiter")
STUDY = re.compile(r"^(?P<topology>[a-z-]+)-(?P<family>v[46])-(?P<index>\d{3})$")


def discover(corpus):
    """Every study directory with a recorded main report, in name order."""
    out = []
    for main in sorted(Path(corpus).glob("*/*/main/report.json")):
        d = main.parent.parent
        m = STUDY.match(d.name)
        if not m:
            continue
        roles = {r: str(d / r / "report.json") for r in crossport.PROTOCOL["roles"] if (d / r / "report.json").exists()}
        started = json.loads(main.read_text())["report"]["startedAt"]
        out.append({"id": d.name, "topology": m["topology"], "family": m["family"], "index": int(m["index"]),
                    "truth": TRUTH[m["topology"]], "roles": roles, "started": started})
    return out


def replay_spec(study):
    return ",".join(f"{role}={path}" for role, path in study["roles"].items())


def nyxr(binary, *args):
    p = subprocess.run([binary, "horizon", *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"nyxr horizon {' '.join(args[:2])}: {p.stderr.strip()}")
    return json.loads(p.stdout)


def summarize(adaptive):
    """The fields the gates and tables need from one AdaptiveStudy."""
    statements = {s["statement"]: s for s in adaptive["statements"]}
    return {"stop": adaptive["stopReason"], "packets": adaptive["spent"]["packets"], "duration_ms": adaptive["spent"]["durationMs"],
            "roles": [s["role"] for s in adaptive["steps"]], "curtailed": sum(s["curtailed"] for s in adaptive["steps"]),
            "study_classification": adaptive["study"]["classification"],
            "statements": {k: {"value": v["value"], "coverage": v["coverage"], "evidence": v["evidence"]} for k, v in statements.items()},
            "ports": {p["port"]: p for p in adaptive["ports"]},
            "profile": adaptive.get("profile")}


def honest(row):
    """G3: tested statements cite only run roles; untested ones carry no
    value unless a profile supplied it; tested ports were measured."""
    ran = set(row["roles"])
    for s in row["statements"].values():
        if s["coverage"] == "tested" and any(e.split(":", 1)[0] not in ran for e in s["evidence"]):
            return False
        if s["coverage"] == "not-tested" and s["value"] != "untested":
            return False
    for p in row["ports"].values():
        if (p["coverage"] in ("tested", "tested-unresolved")) != bool(set(p["roles"]) & ran):
            return False
    return True


def counterexamples(name, study, row, fixed):
    out = []
    for key in STATEMENTS:
        a, b = row["statements"].get(key), fixed["statements"].get(key)
        if a is None or b is None or a["value"] == b["value"]:
            continue
        out.append({"configuration": name, "study": study["id"], "statement": key, "value": a["value"], "coverage": a["coverage"], "fixed": b["value"]})
    return out


def count(values):
    out = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items()))


def evaluate(rows, studies, profile_rows):
    """Apply the registered gates to per-study results."""
    by_id = {s["id"]: s for s in studies}
    fixed = rows["fixed"]

    def correct(row, study_id):
        return row["statements"]["classification"]["value"] == by_id[study_id]["truth"]

    result = {"configurations": {}, "counterexamples": [], "gates": {}}
    for name, results in rows.items():
        k = sum(correct(r, i) for i, r in results.items())
        lo, hi = crossport.clopper_pearson(k, len(results))
        result["configurations"][name] = {"studies": len(results), "correct": k, "interval": [lo, hi],
                                          "packets": sum(r["packets"] for r in results.values()),
                                          "duration_ms": sum(r["duration_ms"] for r in results.values()),
                                          "roles_run": sum(len(r["roles"]) for r in results.values()),
                                          "curtailed_roles": sum(r["curtailed"] for r in results.values()),
                                          "stops": count(r["stop"] for r in results.values())}
        if name != "fixed":
            for i, r in results.items():
                result["counterexamples"] += counterexamples(name, by_id[i], r, fixed[i])
    for p in profile_rows:
        if p["valid"]:
            result["counterexamples"] += counterexamples("profile:" + p["profile"], by_id[p["study"]], p["row"], fixed[p["study"]])
    adaptive = [n for n in rows if n != "fixed"]
    gates = result["gates"]
    gates["G1_no_accuracy_loss"] = all(correct(rows[n][i], i) or not correct(fixed[i], i) for n in adaptive for i in rows[n]) and \
        all(correct(p["row"], p["study"]) or not correct(fixed[p["study"]], p["study"]) for p in profile_rows)
    gates["G2_traffic"] = result["configurations"]["adaptive-curtailed"]["packets"] < result["configurations"]["fixed"]["packets"]
    gates["G3_honest_coverage"] = all(honest(r) for n in rows for r in rows[n].values()) and all(honest(p["row"]) for p in profile_rows) and \
        all(sorted(fixed[i]["roles"]) == sorted(by_id[i]["roles"]) for i in fixed)
    gates["G4_profile_invalidation"] = bool(profile_rows) and all(p["valid"] == p["same_topology"] for p in profile_rows)
    gates["G5_profile_inference"] = all(s["value"] == fixed[p["study"]]["statements"][key]["value"]
                                        for p in profile_rows if p["valid"]
                                        for key, s in p["row"]["statements"].items() if s["coverage"] == "profile-inferred")
    result["passed"] = all(gates.values())
    return result


def run(args):
    studies = discover(args.corpus)
    if not studies:
        raise SystemExit("no studies found under " + args.corpus)
    rows = {name: {} for name in PROTOCOL["configurations"] if name != "profile"}
    for s in studies:
        for name in rows:
            rows[name][s["id"]] = summarize(nyxr(args.binary, "adapt", "--replay", replay_spec(s), *PROTOCOL["configurations"][name]["args"]))
    profile_rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for source in [s for s in studies if s["index"] == 0]:
            path = Path(tmp) / f"{source['id']}.json"
            nyxr(args.binary, "profile", "build", "--study", replay_spec(source), "--class", source["topology"],
                 "--ttl", PROTOCOL["profile_ttl"], "--now", finished(source), "--output", str(path))
            for s in studies:
                if s["family"] != source["family"] or s["id"] == source["id"]:
                    continue
                adaptive = nyxr(args.binary, "adapt", "--replay", replay_spec(s), *PROTOCOL["configurations"]["profile"]["args"], str(path),
                                "--now", second_after(s["started"]))
                row = summarize(adaptive)
                profile_rows.append({"profile": source["id"], "study": s["id"], "same_topology": s["topology"] == source["topology"],
                                     "valid": row["profile"]["valid"], "reasons": row["profile"]["reasons"], "row": row})
    result = evaluate(rows, studies, profile_rows)
    result["protocol"] = PROTOCOL["version"]
    valid = [p for p in profile_rows if p["valid"]]
    result["profile"] = {"applications": len(profile_rows), "valid": len(valid),
                         "packets_valid": sum(p["row"]["packets"] for p in valid),
                         "fixed_packets_same_studies": sum(rows["fixed"][p["study"]]["packets"] for p in valid),
                         "refined_packets_same_studies": sum(rows["adaptive-refined"][p["study"]]["packets"] for p in valid),
                         "invalidation_reasons": count(re.split(r"[:(]", r)[0].strip() for p in profile_rows for r in p["reasons"])}
    result["per_topology"] = {}
    for s in studies:
        t = result["per_topology"].setdefault(f"{s['topology']}-{s['family']}", {name: {"packets": 0, "correct": 0, "studies": 0} for name in rows})
        for name in rows:
            t[name]["packets"] += rows[name][s["id"]]["packets"]
            t[name]["correct"] += rows[name][s["id"]]["statements"]["classification"]["value"] == s["truth"]
            t[name]["studies"] += 1
    if args.output:
        Path(args.output).write_text(json.dumps({"result": result, "detail": {"rows": rows, "profile_rows": profile_rows}}, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


def second_after(timestamp):
    """The next whole second after an RFC 3339 timestamp, for --now."""
    t = datetime.datetime.strptime(timestamp[:19], "%Y-%m-%dT%H:%M:%S") + datetime.timedelta(seconds=1)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def finished(study):
    """Just after the latest role finished: the build time of its profile."""
    return second_after(max(json.loads(Path(p).read_text())["report"]["finishedAt"] for p in study["roles"].values()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="nyxr binary under evaluation")
    parser.add_argument("--corpus", required=True, help="extracted raw-corpus directory")
    parser.add_argument("--output", help="write results and per-study detail JSON")
    raise SystemExit(run(parser.parse_args()))


if __name__ == "__main__":
    main()
