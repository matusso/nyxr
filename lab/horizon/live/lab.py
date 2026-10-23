"""Isolated Linux live collection and portable offline baseline analysis.

No third-party Python dependencies. Every child command is an argument vector.
Only the run subcommand opens namespaces or sends traffic.
"""
import argparse
import base64
import collections
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import struct
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
PROTOCOL = json.loads((HERE / "protocol.json").read_text())


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def command(*args):
    return subprocess.check_output(list(args), text=True, stderr=subprocess.STDOUT)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def measure(args, directory):
    """wait4 supplies this child's CPU and peak RSS, without cross-run maxima."""
    start = time.monotonic()
    with (directory / "stdout.txt").open("wb") as out, (directory / "stderr.txt").open("wb") as err:
        pid = os.posix_spawnp(args[0], args, os.environ, setpgroup=0, file_actions=[
            (os.POSIX_SPAWN_DUP2, out.fileno(), 1),
            (os.POSIX_SPAWN_DUP2, err.fileno(), 2),
        ])
        interrupted = None
        try:
            _, status, usage = os.wait4(pid, 0)
        except BaseException as error:
            interrupted = error
            # Give Nyxr a chance to seal partial evidence, then bound shutdown.
            # The process group contains only this measurement's own children.
            try:
                os.killpg(pid, signal.SIGINT)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 3
            while True:
                finished, status, usage = os.wait4(pid, os.WNOHANG)
                if finished == pid:
                    break
                if time.monotonic() >= deadline:
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    _, status, usage = os.wait4(pid, 0)
                    break
                time.sleep(.01)
    result = {"command": args, "exit_code": os.waitstatus_to_exitcode(status),
              "wall_seconds": time.monotonic() - start,
              "user_cpu_seconds": usage.ru_utime, "system_cpu_seconds": usage.ru_stime,
              "peak_rss_kib": usage.ru_maxrss / 1024 if platform.system() == "Darwin" else usage.ru_maxrss}
    save(directory / "resources.json", result)
    if interrupted is not None:
        raise interrupted
    return result


class Topology:
    def __init__(self, case):
        self.case = case
        self.names = [f"hz66-{os.getpid()}-{n}" for n in ("src", "mid", "dst")]
        self.created = []
        self.children = []
        self.logs = []

    def ns(self, index, *args):
        return command("ip", "netns", "exec", self.names[index], *args)

    def ip(self, index, *args):
        return command("ip", "-n", self.names[index], *args)

    def sysctl(self, index, *assignments):
        args = ["sysctl", "-qw", *assignments]
        if os.statvfs("/proc/sys").f_flag & os.ST_RDONLY:
            # Docker mounts /proc/sys read-only. ip netns exec gives this
            # invocation its own mount namespace; the writable remount dies
            # with it. Only the selected private network namespace is changed.
            args = ["sh", "-ec", 'mount -o remount,rw /proc/sys; exec "$@"', "--", *args]
        return self.ns(index, *args)

    def launch(self, index, args, log):
        stream = log.open("wb")
        self.logs.append(stream)
        child = subprocess.Popen(["ip", "netns", "exec", self.names[index], *args],
                                 stdout=stream, stderr=subprocess.STDOUT)
        self.children.append(child)
        return child

    def setup(self, directory):
        # No link is created in the host namespace and no default route is added.
        for name in self.names:
            command("ip", "netns", "add", name)
            self.created.append(name)
        for i in range(3):
            self.ip(i, "link", "set", "lo", "up")
        routed = self.case in ("nat", "proxy")
        peer = 1 if routed else 2
        self.ip(0, "link", "add", "front", "type", "veth", "peer", "name", "peer")
        self.ip(0, "link", "set", "peer", "netns", self.names[peer])
        self.ip(peer, "link", "set", "peer", "name", "front")
        links = [(0, "front", "10.77.0.1/24", "fd77:1::1/64", "01"),
                 (peer, "front", "10.77.0.2/24", "fd77:1::2/64", "02")]
        if routed:
            self.ip(1, "link", "add", "back", "type", "veth", "peer", "name", "peer")
            self.ip(1, "link", "set", "peer", "netns", self.names[2])
            self.ip(2, "link", "set", "peer", "name", "back")
            links += [(1, "back", "10.78.0.1/24", "fd77:2::1/64", "03"),
                      (2, "back", "10.78.0.2/24", "fd77:2::2/64", "04")]
        for index, link, ipv4, ipv6, mac in links:
            self.ip(index, "link", "set", link, "address", f"02:00:00:00:00:{mac}")
            self.ip(index, "addr", "add", ipv4, "dev", link)
            self.ip(index, "-6", "addr", "add", ipv6, "dev", link, "nodad")
            self.ip(index, "link", "set", link, "up")
            # Kernel SYN/ACKs on veth otherwise carry partial (offloaded) TCP
            # checksums, which HORIZON correlation rejects as invalid.
            self.ns(index, "ethtool", "-K", link, "tx", "off")
        if routed:
            self.sysctl(1, "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
            self.ip(0, "route", "add", "10.78.0.0/24", "via", "10.77.0.2")
            self.ip(0, "-6", "route", "add", "fd77:2::/64", "via", "fd77:1::2")
            self.ip(2, "route", "add", "10.77.0.0/24", "via", "10.78.0.1")
            self.ip(2, "-6", "route", "add", "fd77:1::/64", "via", "fd77:2::1")
        # suppress the source kernel's unsolicited RSTs; runner cleanup is AF_PACKET
        for tool in ("iptables", "ip6tables"):
            self.ns(0, tool, "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP")
        if self.case == "nat":
            self.ns(1, "iptables", "-t", "nat", "-A", "PREROUTING", "-i", "front", "-p", "tcp",
                    "--dport", "443", "-j", "DNAT", "--to-destination", "10.78.0.2:443")
            self.ns(1, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "back", "-p", "tcp",
                    "--dport", "443", "-j", "MASQUERADE")
        sack = PROTOCOL["cases"][self.case]["sack"]
        self.sysctl(2, f"net.ipv4.tcp_sack={sack}")
        server = self.launch(2, ["python3", str(HERE / "endpoint.py")], directory / "endpoint.log")
        if self.case == "proxy":
            self.sysctl(2, "net.ipv4.tcp_sack=1")
            self.sysctl(1, "net.ipv4.tcp_sack=0")
            server = self.launch(1, ["python3", str(HERE / "endpoint.py"), "10.78.0.2"], directory / "proxy.log")
        # A full handshake confirms the listener/proxy before measurements.
        for _ in range(100):
            try:
                for address in ("10.77.0.2", "fd77:1::2"):
                    if self.case == "nat" and ":" in address:
                        continue
                    self.ns(0, "python3", "-c",
                            "import socket,sys; s=socket.create_connection((sys.argv[1],443),.2); "
                            "assert s.recv(128)==b'horizon-lab\\n'; s.close()", address)
                break
            except subprocess.CalledProcessError:
                if server.poll() is not None:
                    raise RuntimeError("lab listener failed; inspect endpoint/proxy logs")
                time.sleep(.05)
        else:
            raise RuntimeError("lab listener readiness timed out")
        if self.case == "firewall":
            for tool in ("iptables", "ip6tables"):
                self.ns(2, tool, "-A", "INPUT", "-p", "tcp", "--dport", "443", "-j", "DROP")

    def impair(self, impairment):
        index = 1 if self.case == "proxy" else 2
        link = "back" if self.case == "nat" else "front"
        args = PROTOCOL["impairments"][impairment]
        if args:
            self.ns(index, "tc", "qdisc", "replace", "dev", link, "root", "netem", *args)
        else:
            # Only this harness's own fresh namespace/interface is touched.
            subprocess.run(["ip", "netns", "exec", self.names[index], "tc", "qdisc", "del",
                            "dev", link, "root"], capture_output=True)

    def truth(self):
        value = {}
        for index, name in enumerate(self.names):
            value[name] = {
                "addresses": json.loads(self.ip(index, "-j", "addr")),
                "routes_v4": json.loads(self.ip(index, "-j", "route")),
                "routes_v6": json.loads(self.ip(index, "-6", "-j", "route")),
                "links": json.loads(self.ip(index, "-j", "-s", "link")),
                "qdiscs": self.ns(index, "tc", "-s", "qdisc", "show"),
                "sack": self.ns(index, "sysctl", "net.ipv4.tcp_sack"),
                "tx_checksum_offload": {link: self.ns(index, "ethtool", "-k", link).split("tx-checksumming:")[1].split()[0]
                                        for link in ("front", "back") if f'"{link}"' in self.ip(index, "-j", "link", "show")},
                "firewall_v4": self.ns(index, "iptables-save", "-c"),
                "firewall_v6": self.ns(index, "ip6tables-save", "-c"),
            }
        return value

    def close(self):
        for child in reversed(self.children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        for stream in self.logs:
            stream.close()
        for name in reversed(self.created):
            subprocess.run(["ip", "netns", "del", name], capture_output=True)


def experiment(target, seed):
    def arm(profile):
        return {"steps": [{"send": {"protocol": "tcp", "flags": ["SYN"], "dstPort": 443,
                                    "optionsProfile": profile}},
                          {"observe": {"windowMs": PROTOCOL["window_ms"]}}]}
    return {"apiVersion": "horizon.nyxr.io/v1alpha1", "kind": "Experiment",
            "metadata": {"name": "hz-001-live-baseline"},
            "spec": {"scope": {"targets": [target], "tcpPorts": [443]},
                     "changedVariable": "sackPermitted", "control": arm("baseline"),
                     "treatment": arm("sack-permitted"),
                     "execution": {"replicates": PROTOCOL["replicates"], "randomizedOrder": True,
                                   "seed": seed, "washoutMs": PROTOCOL["washout_ms"]},
                     "limits": {"maxPackets": PROTOCOL["max_packets"],
                                "maxDurationSeconds": PROTOCOL["max_duration_seconds"],
                                "packetsPerSecond": PROTOCOL["packets_per_second"], "maxConcurrentFlows": 1},
                     "capture": {"maxBytes": 1048576}}}


def collect(args):
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise RuntimeError("live collection requires root on an isolated Linux host/container")
    for tool in ("ip", "tc", "tcpdump", "iptables", "ip6tables", "sysctl", "ethtool"):
        if not shutil.which(tool):
            raise RuntimeError(f"missing {tool}")
    binary = str(Path(args.binary).resolve())
    out = Path(args.output).resolve()
    out.mkdir(mode=0o700)  # refuse reuse, including failed/partial corpora
    os.umask(0o077)
    def terminate(_signal, _frame):
        raise KeyboardInterrupt("live collection cancelled")
    signal.signal(signal.SIGTERM, terminate)
    save(out / "protocol.json", PROTOCOL)
    save(out / "environment.json", {"platform": platform.platform(), "python": sys.version,
                                    "nyxr_version": command(binary, "version").strip(),
                                    "nyxr_sha256": digest(Path(binary)),
                                    "collector_sha256": digest(HERE / "lab.py"),
                                    "endpoint_sha256": digest(HERE / "endpoint.py"),
                                    "image_id": os.environ.get("HORIZON_LAB_IMAGE_ID"),
                                    "packages": command("dpkg-query", "-W", "iproute2", "iptables", "python3", "tcpdump", "procps")
                                                if shutil.which("dpkg-query") else None,
                                    "iproute2": command("ip", "-Version").strip(),
                                    "tcpdump": command("tcpdump", "--version").strip()})
    planned = []
    for case in args.cases.split(","):
        if case not in PROTOCOL["cases"]:
            raise ValueError(f"unknown case {case}")
        for family in (4, 6):
            if case == "nat" and family == 6:
                continue
            for impairment in args.impairments.split(","):
                if impairment not in PROTOCOL["impairments"]:
                    raise ValueError(f"unknown impairment {impairment}")
                for repeat in range(args.runs):
                    planned.append({"id": f"{case}-v{family}-{impairment}-{repeat:03d}", "case": case,
                                    "family": family, "impairment": impairment,
                                    "seed": PROTOCOL["seed_start"] + repeat,
                                    "expected": PROTOCOL["cases"][case]["expected"], "platform": "Linux"})
    manifest = {"version": PROTOCOL["version"], "protocol_sha256": digest(out / "protocol.json"),
                "planned": planned, "results": [], "completed": False}
    save(out / "manifest.json", manifest)  # freeze denominators/thresholds before traffic
    topology = None
    try:
        for entry in planned:
            directory = out / entry["id"]
            directory.mkdir()
            result = {"id": entry["id"]}
            manifest["results"].append(result)
            save(out / "manifest.json", manifest)
            if topology is None or topology.case != entry["case"]:
                if topology:
                    topology.close()
                topology = Topology(entry["case"])
                topology.setup(directory)
            topology.impair(entry["impairment"])
            save(directory / "truth-before.json", topology.truth())
            target = "10.77.0.2" if entry["family"] == 4 else "fd77:1::2"
            source = "10.77.0.1" if entry["family"] == 4 else "fd77:1::1"
            save(directory / "experiment.json", experiment(target, entry["seed"]))
            common = [binary, "horizon", "resolve", "--experiment", str(directory / "experiment.json"),
                      "--allow-targets", target, "--allow-ports", "443"]
            (directory / "plan.json").write_text(command(*common, "--dry-run"))
            for mode in ("scan", "horizon"):
                run = directory / mode
                run.mkdir()
                capture = topology.launch(0, ["tcpdump", "--immediate-mode", "-i", "front", "-U", "-s", "0", "-w",
                                             str(run / "traffic.pcap"), "tcp port 443"], run / "capture.log")
                try:
                    for _ in range(100):
                        if "listening on" in (run / "capture.log").read_text():
                            break
                        if capture.poll() is not None:
                            raise RuntimeError("independent capture failed")
                        time.sleep(.02)
                    else:
                        raise RuntimeError("independent capture readiness timed out")
                    if mode == "horizon":
                        cmd = common + ["--interface", "front", "--source-ip", source,
                                        "--next-hop-mac", "02:00:00:00:00:02", "--output", str(run / "report.json")]
                    else:
                        # The existing raw SYN scanner is IPv4-only. Its IPv6
                        # baseline is explicitly a connect scan, not raw SYN.
                        scan_mode = "syn" if entry["family"] == 4 else "connect"
                        cmd = [binary, "scan", "--no-db", "--no-last-pcapng", "--profile", "custom",
                               "--protocols", "tcp", "--tcp-mode", scan_mode, "--interface", "front",
                               "--next-hop-mac", "02:00:00:00:00:02", "--ports", "443", "--workers", "1",
                               "--timeout", "800ms", "--rate", "3", "--json", target]
                    result[mode] = measure(["ip", "netns", "exec", topology.names[0], *cmd], run)
                    # Flush libpcap even for sub-second one-port scanner baselines.
                    time.sleep(.15)
                finally:
                    if capture.poll() is None:
                        capture.send_signal(signal.SIGINT)
                        capture.wait(timeout=5)
            save(directory / "truth-after.json", topology.truth())
            save(out / "manifest.json", manifest)
            print(entry["id"], "collected", flush=True)
        manifest["completed"] = True
    except BaseException as error:
        details = str(error)
        if isinstance(error, subprocess.CalledProcessError):
            details += "\n" + str(error.output or "")
        manifest["collection_error"] = details
        raise
    finally:
        if topology:
            topology.close()
        save(out / "manifest.json", manifest)
    analyze(out, binary)


def pcap(path):
    """Validate classic Ethernet PCAP and count captured frames/bytes independently."""
    frames = collections.Counter()
    size = 0
    with path.open("rb") as stream:
        header = stream.read(24)
        orders = {b"\xd4\xc3\xb2\xa1": "<", b"\x4d\x3c\xb2\xa1": "<",
                  b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">"}
        order = orders.get(header[:4])
        if (len(header) != 24 or not order
                or struct.unpack(order + "HH", header[4:8]) != (2, 4)
                or struct.unpack(order + "I", header[20:24])[0] != 1):
            raise ValueError("expected classic Ethernet PCAP")
        while True:
            record = stream.read(16)
            if not record:
                break
            if len(record) != 16:
                raise ValueError("truncated PCAP record")
            _, _, included, original = struct.unpack(order + "IIII", record)
            if included > 1 << 20 or included != original:
                raise ValueError("truncated or oversized captured frame")
            frame = stream.read(included)
            if len(frame) != included:
                raise ValueError("truncated PCAP frame")
            frames[frame] += 1
            size += original
    return {"packets": sum(frames.values()), "bytes": size, "sha256": digest(path)}, frames


def outcome(report):
    c = report["comparison"]
    if c["status"] != "inferred":
        return "unresolved"
    if c["pValue"] > PROTOCOL["alpha"]:
        return "no-difference"
    return "difference" if c["treatmentOnlySack"] > c["controlOnlySack"] else "reverse-difference"


def metrics(report):
    trials = report["trials"]
    rtts = sorted(t["features"]["rttNs"] / 1e6 for t in trials if t["features"].get("rttNs", 0) > 0)
    transmitted = [base64.b64decode(e["frame"], validate=True) for t in trials for e in t["evidence"]
                   if e["direction"] != "rx"]
    return {"outcome": outcome(report), "completed": report["completed"],
            "runner_tx_packets": report["packetsTx"], "runner_tx_bytes": sum(map(len, transmitted)),
            "raw_evidence_bytes": report["captureBytes"], "backend_drops": report["backendDrops"],
            "trials": len(trials), "timeouts": sum(t["features"]["responseClass"] == "no-response" for t in trials),
            "quality_flags": dict(collections.Counter(f for t in trials for f in t["qualityFlags"])),
            "rtt_ms_p50": rtts[len(rtts) // 2] if rtts else None,
            "rtt_ms_p95": rtts[math.ceil(.95 * len(rtts)) - 1] if rtts else None,
            "p_value": report["comparison"]["pValue"]}


def stratum(rows, planned, expected):
    # Exact one-sided 95% binomial upper bound for ZERO observed false positives.
    # With nonzero FP we decline the gate rather than publishing a false interval.
    nulls = expected == "no-difference"
    valid = [r for r in rows if not r.get("error")]
    resolved = [r for r in valid if r["outcome"] != "unresolved"]
    correct = sum(r["outcome"] == expected for r in valid)
    fp = sum(r["outcome"] in ("difference", "reverse-difference") for r in valid) if nulls else None
    n = len(resolved)
    upper = 1 - (1 - PROTOCOL["confidence"]) ** (1 / n) if nulls and n and fp == 0 else None
    return {"planned": planned, "collected": len(rows), "invalid": len(rows) - len(valid),
            "missing": planned - len(rows), "unresolved": len(valid) - n,
            "correct": correct, "accuracy_all_planned": correct / planned if planned else None,
            "resolved_accuracy": sum(r["outcome"] == expected for r in resolved) / n if n else None,
            "false_positives": fp, "resolved_null_trials": n if nulls else None,
            "false_positive_rate": fp / n if nulls and n else None,
            "zero_fp_upper_95": upper,
            "null_gate_pass": bool(nulls and len(valid) == planned and n == planned
                                   and n >= PROTOCOL["null_runs_per_stratum"] and upper is not None
                                   and upper <= PROTOCOL["maximum_false_positive_rate"])}


def scan_result(path, target):
    records = [json.loads(line) for line in path.read_text().splitlines()]
    ports = [r for r in records if r.get("kind") == "port"]
    finished = [r for r in records if r.get("kind") == "scan"]
    if len(ports) != 1 or len(finished) != 1 or len(records) != 2:
        raise ValueError("one-port baseline must retain one observation and one run summary")
    row = ports[0]
    if row.get("target") != target or row.get("port") != 443 or row.get("transport") != "tcp":
        raise ValueError("baseline observation outside registered scope")
    if finished[0].get("status") != "completed" or finished[0].get("observations") != 1:
        raise ValueError("baseline did not complete its one-port workload")
    return row


def analyze(out, binary):
    manifest = json.loads((out / "manifest.json").read_text())
    if manifest["version"] != PROTOCOL["version"] or manifest["protocol_sha256"] != digest(out / "protocol.json"):
        raise ValueError("protocol identity mismatch")
    if json.loads((out / "protocol.json").read_text()) != PROTOCOL:
        raise ValueError("recorded protocol differs from the registered protocol")
    rows = []
    seen = set()
    plans = {p["id"]: p for p in manifest["planned"]}
    if len(plans) != len(manifest["planned"]):
        raise ValueError("duplicate planned run ID")
    for result in manifest["results"]:
        run_id = result["id"]
        if run_id not in plans or run_id in seen or run_id in (".", "..") or Path(run_id).name != run_id:
            raise ValueError("unknown, duplicate or unsafe run ID")
        seen.add(run_id)
        entry = plans[run_id]
        if entry["case"] not in PROTOCOL["cases"] or entry["expected"] != PROTOCOL["cases"][entry["case"]]["expected"]:
            raise ValueError("unregistered ground-truth outcome")
        directory = out / run_id
        row = {**entry}
        try:
            truth = [json.loads((directory / f"truth-{when}.json").read_text()) for when in ("before", "after")]
            if not all(truth):
                raise ValueError("missing ground truth")
            report_path = directory / "horizon" / "report.json"
            replayed = json.loads(command(binary, "horizon", "replay", str(report_path)))["report"]
            if replayed["backend"].startswith("synthetic"):
                raise ValueError("synthetic evidence cannot satisfy the live gate")
            if replayed["experiment"] != json.loads((directory / "experiment.json").read_text()):
                raise ValueError("experiment differs from recorded plan")
            target = "10.77.0.2" if entry["family"] == 4 else "fd77:1::2"
            if replayed["experiment"] != experiment(target, entry["seed"]):
                raise ValueError("experiment differs from pre-registered settings")
            endpoint = "mid" if entry["case"] == "proxy" else "dst"
            sack = PROTOCOL["cases"][entry["case"]]["sack"]
            for state in truth:
                hosts = [host for name, host in state.items() if name.endswith("-" + endpoint)]
                if len(hosts) != 1 or hosts[0]["sack"].strip() != f"net.ipv4.tcp_sack = {sack}":
                    raise ValueError("recorded kernel SACK setting contradicts ground truth")
            row.update(metrics(replayed))
            row["report_sha256"] = digest(report_path)
            for mode in ("scan", "horizon"):
                run = directory / mode
                row[mode + "_resources"] = json.loads((run / "resources.json").read_text())
                traffic, frames = pcap(run / "traffic.pcap")
                row[mode + "_traffic"] = traffic
                drops = re.search(r"(\d+) packets dropped by kernel", (run / "capture.log").read_text())
                if not drops or int(drops[1]) != 0:
                    raise ValueError(f"{mode}: independent capture drops or missing drop counters")
                if mode == "horizon":
                    expected_frames = collections.Counter(base64.b64decode(e["frame"], validate=True)
                        for t in replayed["trials"] for e in t["evidence"] if e["direction"] != "rx")
                    if expected_frames - frames:
                        raise ValueError("runner transmissions missing from independent capture")
            scan = scan_result(directory / "scan" / "stdout.txt", target)
            row["scan_state"] = scan["state"]
            row["scan_method"] = "syn" if entry["family"] == 4 else "connect"
            row["scan_correct"] = scan["state"] == PROTOCOL["cases"][entry["case"]]["scan_state"]
            if row["horizon_resources"]["exit_code"] or row["scan_resources"]["exit_code"]:
                raise ValueError("child command failed; partial evidence retained")
            if row["runner_tx_packets"] > PROTOCOL["max_packets"] or row["backend_drops"]:
                raise ValueError("budget violation or backend capture drops")
            if not row["completed"]:
                raise ValueError("incomplete HORIZON run; partial evidence retained")
        except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
            row["error"] = str(error)
        rows.append(row)
    groups = {}
    for entry in manifest["planned"]:
        key = f'{entry["platform"]}/{entry["case"]}/v{entry["family"]}/{entry["impairment"]}'
        groups.setdefault(key, []).append(entry)
    summary = {key: stratum([r for r in rows if r["id"] in {p["id"] for p in planned}],
                           len(planned), planned[0]["expected"]) for key, planned in groups.items()}
    for key, planned in groups.items():
        group = summary[key]
        group["clean_effect_gate_pass"] = bool(planned[0]["expected"] == "difference"
            and planned[0]["impairment"] == "clean"
            and len(planned) >= PROTOCOL["clean_effect_minimum_runs"]
            and not group["missing"] and not group["invalid"]
            and group["accuracy_all_planned"] >= PROTOCOL["clean_effect_minimum_accuracy_all_planned"])
    output = {"version": PROTOCOL["version"], "completed": manifest["completed"], "rows": rows,
              "strata": summary, "issue_66_complete": False,
              "remaining": ["Windows/BSD live ground truth and held-out corpus",
                            "60 resolved null trials per stratum and validated independence",
                            "review accuracy, failure and resource baselines before extending inference"],
              "limitations": PROTOCOL["limitations"]}
    save(out / "summary.json", output)
    print(json.dumps(summary, indent=2))
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--binary", required=True)
    run.add_argument("--output", required=True)
    run.add_argument("--runs", type=int, default=1, help="1 is a smoke run; registered null gate needs 60")
    run.add_argument("--cases", default="linux,null,proxy,nat,firewall")
    run.add_argument("--impairments", default="clean,loss-jitter")
    offline = commands.add_parser("analyze")
    offline.add_argument("--binary", required=True, help="host nyxr used only for offline replay")
    offline.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "run":
        if not 1 <= args.runs <= 100:
            parser.error("runs must be between 1 and 100")
        collect(args)
    else:
        analyze(Path(args.output).resolve(), str(Path(args.binary).resolve()))


if __name__ == "__main__":
    main()
