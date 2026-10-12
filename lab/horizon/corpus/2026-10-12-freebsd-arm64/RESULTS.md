# Controlled FreeBSD live baseline, 2026-10-12

All 12 planned baselines passed on the operator-owned FreeBSD 15.1-RELEASE-p4
ARM64 VM: IPv4 and IPv6, each with three independently configured SACK-enabled
and three SACK-disabled repetitions. The enabled cases found the expected
negotiation difference; the disabled cases found no detectable difference.
All reports completed 12 pairs without timeouts, quality flags or capture drops.
Every ordinary scanner result was open. Issue #66 remains open for the wider
platform, held-out and statistical acceptance gates.

## Fixture, ground truth and registration

The native FreeBSD helper was compiled in the guest using its existing base
compiler with `-O2 -Wall -Wextra -Werror`. No packages were installed. It bound
TCP 443 on the adapter's private IPv4 and a temporary IPv6 ULA. It accepted
only fixed telemetry, SACK on/off and stop messages from the exact Mac peers;
there was no guest command execution interface. The adapter MAC, native
release/build, assigned addresses, routes, TCP settings and firewall context
were recorded. Firewall module unavailability is explicit in the snapshots;
no guest firewall rule or default route was changed.

Native `sysctlbyname` set and read `net.inet.tcp.sack.enable`. Before/after truth
and independent native TCP settings snapshots agreed with every registered
state. Canonical reply options additionally confirmed SACK absent in both arms
of every disabled run, and present only in treatment replies of enabled runs.
This supplies controlled BSD null truth, unlike the Windows default-SACK
hypothesis. It still does not identify an OS, topology or unique causal mechanism
from remote SACK behavior alone.

`horizon-freebsd-controlled-exploratory/v1` froze all 12 outcomes before collector
traffic: seeds 66300–66311, three runs per family/state, 12 pairs, 800ms windows,
300ms washout, 3pps, 48-packet/90s limit per run, alpha 0.05. Ordering was
effect/null IPv4 then effect/null IPv6 within each repetition. Existing Linux
and Windows protocols were unchanged. The IPv4 scanner used raw SYN; IPv6 used
kernel connect. Mac kernel RSTs remained enabled.

## Results and limits

| Stratum | Planned/completed | Valid | SACK differences | Null outcomes | Unresolved | Scanner open |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| IPv4 SACK enabled | 3/3 | 3 | 3 | 0 | 0 | 3/3 |
| IPv4 SACK disabled | 3/3 | 3 | 0 | 3 | 0 | 3/3 |
| IPv6 SACK enabled | 3/3 | 3 | 3 | 0 | 0 | 3/3 |
| IPv6 SACK disabled | 3/3 | 3 | 0 | 3 | 0 | 3/3 |

Each enabled report had 12 treatment-only SACK pairs, zero control-only pairs
and p=0.00048828125. Each disabled report had zero discordant pairs and p=1.
There were no missing, invalid, unresolved or reverse outcomes. Native state
agreed with all 288 canonical reply option records; 72 treatment replies carried
SACK permission and no control reply did. Independent captures retained all
576 runner transmissions and every scanner SYN, with zero kernel/backend drops.

Neither acceptance gate passes. Each null stratum has 0/3 false positives, with
an exact one-sided 95% upper bound of **63.16%**, rather than <=5%. Each effect
stratum has only three repeats, below the registered 12-repeat minimum. Strata
are not pooled, and repeated observations on one VM do not establish population
independence or stationarity.

An earlier setup reached its 15-minute deadline while waiting for the Mac's
administrator-only IPv6 setup. No experiment was started in that attempt. Its
separate native archive confirms original SACK restoration, no TCP 443 listeners
and guest address removal. That setup is preserved as an operational negative
outcome and is not counted as a successful measured run.

## Measured baseline

| Family | Runner TX packets/bytes | Independent HZ packets/bytes | Scanner packets/bytes | HZ wall s/run | Peak HZ RSS KiB |
| --- | --- | --- | --- | --- | --- |
| IPv4, six runs | 288 / 16,416 | 450 / 25,956 | 12 / 672 | 27.227038–27.233269 | 30,128–30,368 |
| IPv6, six runs | 288 / 22,176 | 432 / 33,552 | 42 / 3,732 | 27.219315–27.252685 | 29,936–30,560 |

Total runner traffic was 576 packets / 38,592 bytes; independent HORIZON
captures contained 882 packets / 59,508 bytes including endpoint/kernel traffic.
HORIZON user CPU was 0.236239–0.244004s/run for IPv4 and 0.222437–0.241963s/run
for IPv6; system CPU was 0.479445–0.495651s and 0.446953–0.492019s respectively.
Received-reply RTT p50 ranged 1.391–1.417ms for IPv4 and 1.395–1.533ms for IPv6;
p95 ranged 1.489–1.557ms and 1.507–1.645ms. These are userspace timings over
received replies, not calibrated wire latency.

Scanner wall time was 0.357056–0.363626s/run for IPv4 and 0.041819–0.051507s/run
for IPv6; peak RSS was 29,600–35,568 KiB and 28,480–29,232 KiB respectively.
Connect scanner capture includes its kernel handshake/teardown, not merely its
reported single connect-probe TX. Resources describe Mac children, not the BSD
server; Darwin RSS bytes are normalized to KiB. The one-port scanner and paired
experiment solve different tasks and these measurements establish no speedup.

## Cleanup, archive and verification

The original SACK value **1** was restored. Native stop telemetry and separate
post-exit guest evidence confirm both listeners closed, no remaining TCP 443
listener, and guest ULA removal. A source interface snapshot confirms the Mac
ULA was removed. The temporary helper HTTP endpoint closed, and the guest
console returned to its root prompt. The VM remains running for its operator.
Guest test files remain in their unique temporary evidence directory.

`raw-corpus.tar.gz` preserves 508 files: manifests/protocols, all reports and
independent PCAPs, resource/log records, native context and cleanup, frozen
collector/helper/setup sources, native compiled helper and compiler log, the
earlier expired setup, verification records and an archival Go source snapshot.
`raw-artifact-hashes.json` covers each raw file and `SHA256SUMS` covers all six
delivery files. Archive size: 691,301 bytes. SHA-256:

`933ffe0cf653f1cb1560985b22aa0186179c1ce0f68ab2b913707f155dafcc1a`

The measured Darwin ARM64 Go 1.27.2 binary has SHA-256
`951278fab4e04baf80d54cf74fab0cd96b6ae5a2e3b3898f02824f3137d22991`.
The native guest helper binary has SHA-256
`dd2e3ece16a8af1ce68b209f225b49570d33f59c3cf990b71b0ed22521129090`;
its compiled C source matches the frozen collector environment's source hash.
Dirty Go VCS build metadata is preserved; copying source at archival is not a
claim of a reproducible clean-commit binary. The Go executable is not included.

All 508 extracted raw hashes and six delivery checksums passed; all 12 reports
replayed identically and frozen-source re-analysis reproduced the stored
summary. The 20-test offline suite passed on macOS with two Linux-only tests
skipped (18 executed). C syntax checks passed on macOS and the actual FreeBSD
guest build passed all compiler warnings as errors. Both family dry-run plans
admitted 24 trials and 48 packets. Replay and analysis open no network transport:

```sh
nyxr horizon replay freebsd-v4-null-000/horizon/report.json
python3 frozen-source/bsd.py analyze --binary /path/to/nyxr --output .
```

Windows controlled nulls, FreeBSD impairment/fixture breadth, independently
held-out coverage and full registered confidence/effect samples remain
outstanding. Direct attached private IPv4 and temporary ULA IPv6 do not measure
NAT traversal, routed IPv6 or network disconnection. This is a FreeBSD endpoint
fixture, not FreeBSD Nyxr backend validation. Issue #66 remains open.
