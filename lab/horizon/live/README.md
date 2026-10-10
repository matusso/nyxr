# HORIZON live baseline collection

This harness implements the Linux collection portion of [issue #66](https://github.com/matusso/nyxr/issues/66).
It does not turn synthetic demonstrations into live evidence. Windows/BSD
targets and sufficient independent null repetitions remain required.

The [2026-10-10 Linux corpus](../corpus/2026-10-10-linux-arm64/RESULTS.md)
records live clean/netem cases, exploratory repeated null baselines, raw
reports/captures, configuration snapshots and negative outcomes. It is a
partial research baseline; no population false-positive or cross-platform
acceptance claim follows from this small study.

`protocol.json` pre-registers the primary outcome, thresholds, denominators,
order seeds, scopes and budgets. The collector copies it and writes the full
planned run manifest **before sending traffic**. The default single repetition
is a smoke test, not statistical acceptance.

## Topologies and ground truth

The collector creates three uniquely named network namespaces. Interfaces are
created inside those namespaces, never on a host interface. There is no default
route or external destination; targets are `10.77.0.2:443` and
`[fd77:1::2]:443` only. Namespace deletion and listener/capture shutdown run on
exit, cancellation and failure. Existing resources are never reused.

| Case | Path and independently configured truth | Primary expected result |
| --- | --- | --- |
| linux | Source → Linux listener, `tcp_sack=1` | SACK difference |
| null | Source → Linux listener, `tcp_sack=0` | No SACK difference |
| proxy | Source → Linux TCP proxy with `tcp_sack=0` → separate SACK-enabled listener | No SACK difference at frontend |
| nat | Source → IPv4 DNAT/MASQUERADE router → Linux listener | SACK difference; mechanism remains unknown to HZ-001 |
| firewall | Source → Linux listener behind INPUT DROP | Unresolved |

All cases except IPv4-only NAT run in both address families. Clean and response
path `netem delay 20ms 5ms loss 5%` conditions are separate strata. Experiment
seeds reproduce arm order, not the kernel's netem random loss. Namespace SACK
settings, addresses, routes, qdiscs, firewall rules/counters and interface
counters are retained before and after every run. The source kernel's own RSTs
are suppressed; HORIZON's raw Ethernet cleanup remains enabled. Independent
captures include target retransmissions and all other port-443 traffic.

The proxy readiness check completes an application handshake through the
frontend to its backend. HZ-001 sends only SYNs; its measurement cannot observe
backend forwarding or identify a proxy. Containers all share the same Linux
kernel and are not independent operating-system ground truths.

## Run on an isolated Linux lab host

Requires root, Python 3, iproute2 (`ip`, `tc`), iptables/ip6tables, procps
(`sysctl`), tcpdump, and a built Linux `nyxr`. Build outside the measured run.
The output directory must not exist. Reports, captures and logs are private.

```sh
make build
sudo python3 lab/horizon/live/lab.py run --binary "$PWD/nyxr" \
  --output "$PWD/lab/horizon/live/results/smoke" --runs 1
```

Use `--cases linux,null` or `--impairments clean` for a shorter preflight.
The full matrix contains 18 strata. A single full smoke pass takes about ten
minutes; `--runs 60` takes several hours and must be planned on a stable lab.
Do not combine selectively successful repetitions from different protocols.
Repeat campaigns on distinct days/hosts to assess stationarity/dependence.

## Container preparation

The Dockerfile supplies tools, not the Nyxr binary. Cross-build for the Docker
engine's architecture, then build the image:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /tmp/nyxr-hz66-linux ./cmd/nyxr
docker build -t nyxr-horizon-lab:issue-66 lab/horizon/live
```

Use `GOARCH=amd64` for an amd64 engine. Running this **namespace-based** harness
inside a container additionally needs NET_ADMIN, NET_RAW, SYS_ADMIN (namespace
mounts) and an AppArmor policy permitting namespace mounts. These capabilities
must be approved by the operator. Use a network-disconnected disposable
container, read-only lab/binary mounts and a dedicated writable results mount;
do not mount the Docker socket, host network or the entire writable host `/tmp`.
A Linux host/VM can run the harness directly without changing container
confinement. Image tags are not reproducible: retain the resolved image ID and
package versions alongside the recorded kernel/build environment.

After operator approval, the disconnected container invocation is:

```sh
mkdir -p /tmp/hz66-results
docker run --rm --network none \
  --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined \
  -v "$PWD/lab/horizon/live:/lab:ro" \
  -v /tmp/nyxr-hz66-linux:/nyxr:ro \
  -v /tmp/hz66-results:/results \
  nyxr-horizon-lab:issue-66 --binary /nyxr --output /results/new-smoke --runs 1
```

When Docker exposes `/proc/sys` read-only, each settings write remounts it only
inside the temporary mount namespace created by `ip netns exec`. The remount
expires with that invocation and changes only the selected private network
namespace's settings. The host/container-root network settings are not changed.

## Evidence and offline analysis

Each planned repetition retains:

- A frozen experiment and compiled dry-run plan; environment and binary hash.
- A versioned HORIZON report with raw correlated TX/RX frames, order seed,
  quality flags, timeouts and inference. Failed/partial evidence is retained.
- Independent classic Ethernet PCAP and capture drop counters for both HORIZON
  and a one-port existing-scanner baseline. Analysis checks that all recorded
  runner transmissions appear in the independent capture.
- Per-child wall time, user/system CPU time, and peak RSS in KiB from Linux
  `wait4`, including the namespace-exec wrapper. RTT percentiles describe the
  HORIZON userspace clock, not a calibrated wire latency.
- HORIZON TX packets/bytes including cleanup, independent total wire
  packets/bytes, capture bytes, timeout count and response/quality outcomes.

The existing raw SYN scanner is IPv4-only, so the explicit IPv6 baseline uses
connect mode. The scanner tests one-port discovery; HORIZON tests 12 randomized
pairs. Their tasks and traffic budgets differ. No throughput advantage or
information-gain multiplier is inferred from these measurements.

Offline analysis opens no network transport and uses the host `nyxr` only for
integrity/correlation-checked replay:

```sh
python3 lab/horizon/live/lab.py analyze --binary "$PWD/nyxr" \
  --output lab/horizon/live/results/smoke
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s lab/horizon/live
```

`summary.json` retains each run and each platform/case/family/impairment stratum.
Accuracy uses **all planned runs** as its denominator; resolved accuracy and
unresolved/invalid/missing counts are separate. Capture failures and missing
runs cannot become successful null trials. Publish the entire summary,
including unresolved, wrong-direction, failed and missing outcomes. Never
select only positive evidence for publication.

## Pre-registered acceptance

The primary test remains the runner's exact two-sided paired sign test at
alpha 0.05. A null false positive is an inferred SACK difference with alpha
≤0.05 on a SACK-disabled endpoint/frontend. Every null stratum needs at least
60 **resolved**, complete, independently captured repetitions, zero false
positives, and no missing/invalid/unresolved planned run. With zero false
positives in 60 trials, the exact one-sided 95% binomial upper bound is
`1 - 0.05^(1/60) = 4.8703%`, below the registered 5% ceiling. Nonzero false
positives fail this conservative gate; the analyzer does not invent an
interval for them. This bound assumes independent stationary trials; repeated
measurements on one host do not establish those assumptions.

Clean SACK-enabled cases require at least 12 repetitions and ≥90% correct
treatment-only SACK effects over **all planned** runs. A significant effect in
the reverse direction is incorrect, and either direction is a false positive
on a null endpoint. Under loss/jitter, missing or duplicate replies should remain
unresolved; they must not be silently removed. Timeouts, capture drops,
budget violations and negative results are published with raw evidence.
Source/target and runner budgets must remain in scope for every transmission.

## Windows/BSD gate

This collector does not provision or authorize an external host. Collect on
operator-owned Windows and BSD VMs in an isolated, explicitly allowlisted lab,
retaining OS build, interface addresses, routes, native SACK configuration,
firewall rules, capture/drop counters and resource measurements. Use the same
12-pair, 800ms-window, 300ms-washout, 3-packets/s, 48-packet/90s protocol;
reserve independent scoped evidence for both IPv4 and IPv6. Record each known
SACK outcome before looking at reports. When SACK cannot be independently
configured/verified, label the fixture unresolved, not a null control.

Store external fixtures separately with a manifest documenting every planned
and missing run. `lab.py analyze` currently validates only this harness's Linux
corpus; it must not accept fabricated Linux configuration as Windows/BSD truth.
The separate [Windows IPv4 collector](WINDOWS.md) implements an exploratory
native listener and macOS source measurement. The [2026-10-11 Windows corpus](../corpus/2026-10-11-windows-arm64/RESULTS.md)
retains three verified runs and an initial three-run scanner-capture failure.
It does not independently configure SACK or provide Windows IPv6/BSD or held-out
coverage. Issue #66 stays open until those fixtures and the measured acceptance
gates exist.
