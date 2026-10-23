"""HORIZON cross-port (#70) live ground-truth collection and analysis.

Builds isolated namespace topologies with known shared, per-port or absent SYN
rate limiting and runs the HZ-003/HZ-004 study roles from
lab/horizon/cross-port against them. Only `run` sends traffic, inside private
namespaces with no default route; `analyze` is offline.
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
PROTOCOL = json.loads((HERE / "crossport-protocol.json").read_text())
EXPERIMENTS = HERE.parent / "cross-port"
PORTS = PROTOCOL["ports"]


class Topology(lab.Topology):
    """src -> dst, or src -> mid -> dst for the router-hosted limiter."""

    def __init__(self, name):
        super().__init__(name)
        self.names = [f"hz70-{os.getpid()}-{n}" for n in ("src", "mid", "dst")]

    def setup(self, directory):
        for name in self.names:
            lab.command("ip", "netns", "add", name)
            self.created.append(name)
        for i in range(3):
            self.ip(i, "link", "set", "lo", "up")
        routed = PROTOCOL["topologies"][self.case]["limiter"] == "router-shared"
        peer = 1 if routed else 2
        self.ip(0, "link", "add", "front", "type", "veth", "peer", "name", "peer")
        self.ip(0, "link", "set", "peer", "netns", self.names[peer])
        self.ip(peer, "link", "set", "peer", "name", "front")
        links = [(0, "front", "10.77.0.1/24", "fd77:1::1/64", "01"), (peer, "front", "10.77.0.2/24", "fd77:1::2/64", "02")]
        target = 2
        if routed:
            self.ip(1, "link", "add", "back", "type", "veth", "peer", "name", "peer")
            self.ip(1, "link", "set", "peer", "netns", self.names[2])
            self.ip(2, "link", "set", "peer", "name", "back")
            links += [(1, "back", "10.78.0.1/24", "fd77:2::1/64", "03"), (2, "back", "10.78.0.2/24", "fd77:2::2/64", "04")]
        for index, link, ipv4, ipv6, mac in links:
            self.ip(index, "link", "set", link, "address", f"02:00:00:00:00:{mac}")
            self.ip(index, "addr", "add", ipv4, "dev", link)
            self.ip(index, "-6", "addr", "add", ipv6, "dev", link, "nodad")
            self.ip(index, "link", "set", link, "up")
        if routed:
            # The router forwards to the endpoint by DNAT on its own front address,
            # so the IPv4 target stays 10.77.0.2 in every topology. Routed studies
            # are IPv4-only (see crossport-protocol.json).
            self.sysctl(1, "net.ipv4.ip_forward=1")
            self.ns(1, "iptables", "-t", "nat", "-A", "PREROUTING", "-i", "front", "-d", "10.77.0.2", "-p", "tcp", "-j", "DNAT", "--to-destination", "10.78.0.2")
            self.ip(2, "route", "add", "10.77.0.0/24", "via", "10.78.0.1")
            self.ip(2, "-6", "route", "add", "fd77:1::/64", "via", "fd77:2::1")
        for tool in ("iptables", "ip6tables"):
            self.ns(0, tool, "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP")
        server = self.launch(target, ["python3", str(HERE / "crossport-endpoint.py"), str(PORTS["b"]), str(PORTS["a"])], directory / "endpoint.log")
        for _ in range(100):
            try:
                for address in ("10.77.0.2", "fd77:1::2"):
                    for port in (PORTS["b"], PORTS["a"]):
                        self.ns(0, "python3", "-c", "import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),.2); "
                                "assert s.recv(128)==b'horizon-lab\\n'; s.close()", address, str(port))
                break
            except subprocess.CalledProcessError:
                if server.poll() is not None:
                    raise RuntimeError("lab listener failed")
                time.sleep(.05)
        else:
            raise RuntimeError("lab listener readiness timed out")
        limiter = PROTOCOL["topologies"][self.case]["limiter"]
        if limiter:
            index, chain = (1, "FORWARD") if limiter == "router-shared" else (2, "INPUT")
            groups = [[PORTS["a"], PORTS["b"]]] if limiter.endswith("shared") else [[PORTS["a"]], [PORTS["b"]]]
            for tool in ("iptables", "ip6tables"):
                for ports in groups:
                    match = ["-p", "tcp", "--syn", "-m", "multiport", "--dports", ",".join(map(str, ports))]
                    self.ns(index, tool, "-A", chain, *match, "-m", "limit", "--limit", PROTOCOL["limit"]["rate"],
                            "--limit-burst", str(PROTOCOL["limit"]["burst"]), "-j", "ACCEPT")
                    self.ns(index, tool, "-A", chain, *match, "-j", "DROP")

    def truth(self):
        value = {}
        for index, name in enumerate(self.names):
            value[name] = {"addresses": json.loads(self.ip(index, "-j", "addr")), "routes_v4": json.loads(self.ip(index, "-j", "route")),
                           "routes_v6": json.loads(self.ip(index, "-6", "-j", "route")),
                           "firewall_v4": self.ns(index, "iptables-save", "-c"), "firewall_v6": self.ns(index, "ip6tables-save", "-c")}
        return value


def experiment(role, target, seed):
    text = (EXPERIMENTS / f"{role}.yaml").read_text()
    text = re.sub(r'targets: \["[^"]+"\]', f'targets: ["{target}"]', text)
    return re.sub(r"seed: \d+", f"seed: {seed}", text)


def plan():
    planned = []
    roles = PROTOCOL["roles"]
    for topo in PROTOCOL["topologies"]:
        studies = [(4, roles, n) for n in range(PROTOCOL["studies_per_topology"])]
        if topo in PROTOCOL["ipv6_topologies"]:
            studies += [(6, PROTOCOL["ipv6_roles"], n) for n in range(PROTOCOL["ipv6_studies_per_topology"])]
        for family, study_roles, n in studies:
            planned.append({"id": f"{topo}-v{family}-{n:03d}", "topology": topo, "family": family, "roles": study_roles,
                            "seed": PROTOCOL["seed_start"] + 10 * n, "truth": PROTOCOL["topologies"][topo]["truth"]})
    return planned


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
                                        "nyxr_sha256": lab.digest(Path(binary)), "collector_sha256": lab.digest(HERE / "crossport.py"),
                                        "endpoint_sha256": lab.digest(HERE / "crossport-endpoint.py"),
                                        "experiments_sha256": {p.name: lab.digest(p) for p in sorted(EXPERIMENTS.glob("*.yaml"))},
                                        "image_id": os.environ.get("HORIZON_LAB_IMAGE_ID")})
    planned = plan()
    manifest = {"version": PROTOCOL["version"], "protocol_sha256": lab.digest(out / "protocol.json"), "planned": planned, "results": [], "completed": False}
    lab.save(out / "manifest.json", manifest)
    allow = f'{PORTS["b"]},{PORTS["a"]},{PORTS["unrelated"]}'
    try:
        for entry in planned:
            study = out / entry["id"]
            study.mkdir()
            result = {"id": entry["id"], "roles": {}}
            manifest["results"].append(result)
            lab.save(out / "manifest.json", manifest)
            topology = Topology(entry["topology"])  # fresh state for every study
            try:
                topology.setup(study)
                lab.save(study / "truth-before.json", topology.truth())
                target, source = ("10.77.0.2", "10.77.0.1") if entry["family"] == 4 else ("fd77:1::2", "fd77:1::1")
                for i, role in enumerate(entry["roles"]):
                    run = study / role
                    run.mkdir()
                    (run / "experiment.yaml").write_text(experiment(role, target, entry["seed"] + i))
                    common = [binary, "horizon", "resolve", "--experiment", str(run / "experiment.yaml"), "--policy", "lab",
                              "--permit", "cross-port", "--allow-targets", target, "--allow-ports", allow]
                    (run / "plan.json").write_text(lab.command(*common, "--dry-run"))
                    capture = topology.launch(0, ["tcpdump", "--immediate-mode", "-i", "front", "-U", "-s", "0", "-w", str(run / "traffic.pcap"),
                                                  "tcp"], run / "capture.log")
                    try:
                        for _ in range(100):
                            if "listening on" in (run / "capture.log").read_text():
                                break
                            time.sleep(.02)
                        else:
                            raise RuntimeError("independent capture readiness timed out")
                        cmd = common + ["--interface", "front", "--source-ip", source, "--next-hop-mac", "02:00:00:00:00:02", "--output", str(run / "report.json")]
                        result["roles"][role] = lab.measure(["ip", "netns", "exec", topology.names[0], *cmd], run)
                        time.sleep(.15)
                    finally:
                        if capture.poll() is None:
                            capture.send_signal(signal.SIGINT)
                            capture.wait(timeout=5)
                    time.sleep(1)  # let every token bucket refill between roles
                lab.save(study / "truth-after.json", topology.truth())
            finally:
                topology.close()
            lab.save(out / "manifest.json", manifest)
            print(entry["id"], "collected", flush=True)
        manifest["completed"] = True
    except BaseException as error:
        manifest["collection_error"] = str(error) + ("\n" + str(error.output or "") if isinstance(error, subprocess.CalledProcessError) else "")
        raise
    finally:
        lab.save(out / "manifest.json", manifest)
    analyze(out, binary)


def clopper_pearson(k, n, alpha=0.05):
    """Two-sided exact interval by bisection on the binomial CDF."""
    from math import comb

    def cdf(x, p):
        return sum(comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(x + 1))

    def bisect(below):
        lo, hi = 0.0, 1.0
        for _ in range(60):
            mid = (lo + hi) / 2
            lo, hi = (mid, hi) if below(mid) else (lo, mid)
        return (lo + hi) / 2
    lower = 0.0 if k == 0 else bisect(lambda p: 1 - cdf(k - 1, p) < alpha / 2)
    upper = 1.0 if k == n else bisect(lambda p: cdf(k, p) > alpha / 2)
    return [lower, upper]


def analyze(out, binary):
    manifest = json.loads((out / "manifest.json").read_text())
    if manifest["version"] != PROTOCOL["version"] or json.loads((out / "protocol.json").read_text()) != PROTOCOL:
        raise ValueError("protocol identity mismatch")
    plans = {p["id"]: p for p in manifest["planned"]}
    rows = []
    for entry in manifest["planned"]:
        study = out / entry["id"]
        row = {"id": entry["id"], "topology": entry["topology"], "family": entry["family"], "truth": entry["truth"]}
        try:
            if entry["id"] not in {r["id"] for r in manifest["results"]}:
                raise ValueError("study not started")
            target = "10.77.0.2" if entry["family"] == 4 else "fd77:1::2"
            args = []
            for i, role in enumerate(entry["roles"]):
                run = study / role
                if (run / "experiment.yaml").read_text() != experiment(role, target, entry["seed"] + i):
                    raise ValueError(f"{role}: experiment differs from the registered template")
                report = json.loads(lab.command(binary, "horizon", "replay", str(run / "report.json")))["report"]
                if report["backend"].startswith("synthetic") or not report["completed"] or report["backendDrops"]:
                    raise ValueError(f"{role}: synthetic, incomplete or dropped evidence")
                _, frames = lab.pcap(run / "traffic.pcap")
                drops = re.search(r"(\d+) packets dropped by kernel", (run / "capture.log").read_text())
                if not drops or int(drops[1]) != 0:
                    raise ValueError(f"{role}: independent capture drops")
                sent = collections.Counter(base64.b64decode(e["frame"], validate=True) for t in report["trials"] for e in t["evidence"] if e["direction"] != "rx")
                if sent - frames:
                    raise ValueError(f"{role}: runner transmissions missing from independent capture")
                args += [f"--{role}", str(run / "report.json")]
            result = json.loads(lab.command(binary, "horizon", "cross-port", *args))
            lab.save(study / "study.json", result)
            candidate = result["candidates"][0] if result["candidates"] else None
            row.update({"classification": result["classification"], "isolated": result["isolatedClassification"],
                        "reasons": result["reasons"],
                        "roles": {r["role"]: {"status": r["status"], "suppressed": r["suppressed"], "enabled": r["enabled"],
                                              "p": r["pValue"], "control": r["controlAnswered"], "treatment": r["treatmentAnswered"]} for r in result["roles"]},
                        "candidate": None if not candidate else {"direction": candidate["direction"], "signals": candidate["orthogonalSignals"],
                                                                  "hypotheses": [(h["family"], h["status"], h.get("location")) for h in candidate["hypotheses"]]}})
        except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
            row["error"] = str(error) + (("\n" + error.output[-300:]) if isinstance(error, subprocess.CalledProcessError) and error.output else "")
        rows.append(row)
    n = len(rows)
    cross = sum(r.get("classification") == r["truth"] for r in rows)
    isolated = sum(r.get("isolated") == r["truth"] for r in rows)
    cross_ci, isolated_ci = clopper_pearson(cross, n), clopper_pearson(isolated, n)
    by_topology = {}
    for topo in PROTOCOL["topologies"]:
        group = [r for r in rows if r["topology"] == topo]
        by_topology[topo] = {"planned": len(group), "errors": sum("error" in r for r in group),
                             "classifications": dict(collections.Counter(r.get("classification", "error") for r in group)),
                             "isolated": dict(collections.Counter(r.get("isolated", "error") for r in group)),
                             "correct": sum(r.get("classification") == r["truth"] for r in group),
                             "correct_ci": clopper_pearson(sum(r.get("classification") == r["truth"] for r in group), len(group)),
                             "candidates": sum(bool(r.get("candidate")) for r in group),
                             "signals": dict(collections.Counter(s for r in group if r.get("candidate") for s in r["candidate"]["signals"])),
                             "elevated": dict(collections.Counter(f"{h[0]}@{h[2]}" for r in group if r.get("candidate") for h in r["candidate"]["hypotheses"] if h[1] == "hypothesis"))}
    false_candidates = sum(bool(r.get("candidate")) for r in rows if r["truth"] != "shared-state")
    unsupported = sum(1 for r in rows if r.get("candidate") and not r["candidate"]["signals"] and any(h[1] == "hypothesis" for h in r["candidate"]["hypotheses"]))
    locations = {r["topology"]: {h[2] for h in r["candidate"]["hypotheses"] if h[1] == "hypothesis"} for r in rows if r.get("candidate")}
    output = {"version": PROTOCOL["version"], "completed": manifest["completed"], "rows": rows, "topologies": by_topology,
              "cross_port_accuracy": {"correct": cross, "planned": n, "ci95": cross_ci},
              "isolated_accuracy": {"correct": isolated, "planned": n, "ci95": isolated_ci},
              "gates": {"go": cross_ci[0] > isolated_ci[1],
                        "zero_candidate_false_positives": false_candidates <= PROTOCOL["gates"]["candidate_false_positives_allowed"],
                        "no_unsupported_infrastructure_hypothesis": unsupported == 0,
                        "confounded_location_unresolved": locations.get("shared-endpoint", set()) <= {"endpoint-or-path-unresolved"} and locations.get("shared-path", set()) <= {"endpoint-or-path-unresolved"}},
              "limitations": PROTOCOL["limitations"]}
    lab.save(out / "summary.json", output)
    print(json.dumps({k: v for k, v in output.items() if k != "rows"}, indent=2))
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "analyze"):
        sub = commands.add_parser(name)
        sub.add_argument("--binary", required=True)
        sub.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "run":
        collect(args)
    else:
        analyze(Path(args.output).resolve(), str(Path(args.binary).resolve()))


if __name__ == "__main__":
    main()
