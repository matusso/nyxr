# Sequential FreeBSD VNET study, 2026-10-12

The separately registered study collected all 588 planned reports. There were
588 valid full baselines, 0 invalid and
0 missing. Valid outcomes: 313 null,
63 SACK difference and 212 unresolved.
All planned invalid,
missing and unresolved outcomes remain in their original strata. Issue #66
remains open; configuration separation on one kernel does not establish
physically independent held-out performance or population independence.

## Registration and native ground truth

`horizon-freebsd-vnet-config-reserved-sequential/v2` froze seeds 67400–67987,
588 outcomes and balanced randomized blocks before probes. Two fresh VNET
configurations supplied separate TCP stacks, interfaces and private IPv4/IPv6
addresses. Each role/family/clean-or-impaired combination had 60 native
SACK-disabled nulls and 12 SACK-enabled effects, plus three known DROP checks
per role/family. The binary, analysis policy and thresholds stayed frozen;
reserved results were not used for tuning.

One worker limited combined probes to 3pps. Each run retained 12 pairs, 800ms
windows, 300ms washout, a 48-packet cap and 90s external deadline. Outgoing
measurement SYN-ACKs alone received an empirical uniform 15–25ms dummynet
profile, 5% loss and 100Mbit/s cap, or a fixed DROP rule. Control traffic bypassed
shaping. Native settings, counters, release/build, physical memory and boot time
were recorded. Canonical SACK options must agree with before/after native
state, and impaired paths must advance the owned native rule counters.

Protocol source SHA-256: `c21b424dba24189166be443062eada606a7a73adc267f35def5fdab2e6dd5328`.
The captured serialized protocol has a separate formatting checksum in the
manifest. The guest was FreeBSD 15.1-RELEASE-p4 ARM64 with 2048MB configured
RAM. The prior 256MB concurrent attempt suffered a kernel panic and remains
in its [separate failed corpus](../2026-10-12-freebsd-vnet-failed-arm64/RESULTS.md).
Memory and concurrency both changed: this study cannot identify a causal fix.

## Outcomes and acceptance limits

| Stratum | Planned | Collected | Invalid | Missing | Unresolved valid | Correct | False positives |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| development-v4-clean-sack0 | 60 | 60 | 0 | 0 | 0 | 60 | 0 |
| development-v4-clean-sack1 | 12 | 12 | 0 | 0 | 0 | 12 | — |
| development-v4-loss-jitter-sack0 | 60 | 60 | 0 | 0 | 42 | 18 | 0 |
| development-v4-loss-jitter-sack1 | 12 | 12 | 0 | 0 | 9 | 3 | — |
| development-v4-drop-sack1 | 3 | 3 | 0 | 0 | 3 | 3 | — |
| development-v6-clean-sack0 | 60 | 60 | 0 | 0 | 0 | 60 | 0 |
| development-v6-clean-sack1 | 12 | 12 | 0 | 0 | 0 | 12 | — |
| development-v6-loss-jitter-sack0 | 60 | 60 | 0 | 0 | 40 | 20 | 0 |
| development-v6-loss-jitter-sack1 | 12 | 12 | 0 | 0 | 10 | 2 | — |
| development-v6-drop-sack1 | 3 | 3 | 0 | 0 | 3 | 3 | — |
| reserved-v4-clean-sack0 | 60 | 60 | 0 | 0 | 0 | 60 | 0 |
| reserved-v4-clean-sack1 | 12 | 12 | 0 | 0 | 0 | 12 | — |
| reserved-v4-loss-jitter-sack0 | 60 | 60 | 0 | 0 | 43 | 17 | 0 |
| reserved-v4-loss-jitter-sack1 | 12 | 12 | 0 | 0 | 9 | 3 | — |
| reserved-v4-drop-sack1 | 3 | 3 | 0 | 0 | 3 | 3 | — |
| reserved-v6-clean-sack0 | 60 | 60 | 0 | 0 | 0 | 60 | 0 |
| reserved-v6-clean-sack1 | 12 | 12 | 0 | 0 | 0 | 12 | — |
| reserved-v6-loss-jitter-sack0 | 60 | 60 | 0 | 0 | 42 | 18 | 0 |
| reserved-v6-loss-jitter-sack1 | 12 | 12 | 0 | 0 | 5 | 7 | — |
| reserved-v6-drop-sack1 | 3 | 3 | 0 | 0 | 3 | 3 | — |

The four clean null strata and four clean effect strata passed their conditional
numerical gates (4 and 4 of four).
Each numerical gate retains the full registered denominator and is conditional
on IID sampling. No scientific null gate or physical held-out gate is claimed.
Split-half RTT drift and lag-one correlation are descriptive diagnostics, not
proof of stationarity. Loss-related incomplete pairs stay unresolved; no
inference threshold was relaxed and no successful-only retry was substituted.
Scanner misses, timeouts and quality flags remain recorded alongside the
primary SACK outcome in `baseline-summary.json`.

## Measured baseline

The following measurements cover valid full baselines, including unresolved
ones. Every raw attempt remains archived separately from validity decisions.

| Family / condition | Valid | Runner TX packets / bytes | Independent HZ packets / bytes | HZ wall s/run | Peak HZ RSS KiB | Arm timeouts | Scanner correct |
| --- | ---: | ---: | ---: | --- | --- | ---: | ---: |
| v4 / clean | 144 | 6912 / 393984 | 10807 / 621050 | 27.224–27.276 | 29584–30448 | 0 | 144/144 |
| v4 / loss-jitter | 144 | 6676 / 411808 | 10875 / 626066 | 27.017–27.267 | 29360–30544 | 236 | 141/144 |
| v4 / drop | 6 | 144 / 8640 | 144 / 8640 | 26.471–26.495 | 29520–29808 | 144 | 6/6 |
| v6 / clean | 144 | 6912 / 532224 | 10378 / 803724 | 27.227–27.261 | 29632–30400 | 0 | 144/144 |
| v6 / loss-jitter | 144 | 6658 / 556582 | 10481 / 813334 | 26.972–27.260 | 29312–30544 | 254 | 133/144 |
| v6 / drop | 6 | 144 / 11520 | 144 / 11520 | 26.467–26.485 | 29408–30224 | 144 | 6/6 |

Per-child user/system CPU, scanner wall/RSS/traffic, reply RTT p50/p95, native
shaping counters and quality flags are retained in the machine-readable
summary. Resources describe Mac children, not guest CPU/RSS; Darwin RSS bytes
are normalized to KiB. Captures include endpoint/kernel traffic. RTT measures
userspace timing over received replies, not calibrated wire latency. The
one-port scanner and paired experiment solve different tasks and establish
no speedup. IPv4 scanner mode was raw SYN; IPv6 used kernel connect.

## Cleanup and verification

Native STOP truth verifies each fixture restored its original SACK value,
cleared owned shaping and closed its listeners. The bootstrap removed its
jails, nullfs/devfs mounts, bridge/epairs and newly loaded modules, and restored
the previous IPFW tunable. Separate native post-exit evidence records original
host SACK value 1, routes and adapter state. The source's owned IPv6 alias and
helper HTTP endpoint were removed.

The VM panicked and rebooted roughly one minute *after* the native teardown
and artifact upload. The console recorded another kernel fault and saved a
local memory dump; the dump was not exported. The post-run panic does not
invalidate reports already sealed and verified, but it defeats any claim of
durable VM stability. Post-reboot root state has not been independently
checked; the retained native snapshot is from before this later reboot.

The temporary restricted root SSH key expired and a new key-only login was
denied. Its local private/public files were deleted. Guest-side key-line
removal status: operator-confirmed.

The operator VM remains running. Its 2048MB allocation and operator-authorized
GDB/dependency packages remain as intentional lab changes. Guest fixture
evidence was uploaded before the reboot. No kernel memory dump, SSH key or
VM configuration file is included in this corpus.

The archive retains 9161 regular files, all 588 reports, plans,
truth, independent PCAPs, resource/capture logs, frozen collector/Go sources,
native compiled helper and cleanup evidence. All raw hashes passed after safe
extraction. Every saved report replayed identically; frozen-source analysis
reproduced the stored summary exactly. All delivery checksums passed.

Archive size: 9,049,768 bytes; SHA-256:
`497eec35c02987a29b878174978afc9ec682de65fe139a9ec032001bcd2a41ac`.
Measured Darwin ARM64 Go 1.27.2 binary SHA-256:
`951278fab4e04baf80d54cf74fab0cd96b6ae5a2e3b3898f02824f3137d22991`.
Native helper SHA-256: `7fd04644307162bd75131a7c85e16c14fc250a3119389d8aa7dc916515c33ed3`.
The native source hash matches the frozen source and recorded environment.
Dirty binary VCS metadata is preserved; archival source copying does not
claim a reproducible clean-commit binary. The 26-test offline suite passed
in an unprivileged network-disconnected Linux container; macOS executed 24,
with two Linux-only tests skipped. Native C compilation used warnings as errors.

Offline analysis opens no network transport:

```sh
nyxr horizon replay development-v4-clean-sack0-00-1/horizon/report.json
python3 frozen-source/live/bsd_study_sequential.py analyze --binary /path/to/nyxr --output .
```

Direct private IPv4 and IPv6 do not validate BSD NAT, proxies, routed IPv6 or
a native FreeBSD Nyxr backend. Linux supplies separately recorded proxy/NAT
fixtures. Controlled Windows nulls/impairments and the wider statistical and
independence gates remain outstanding. Do not close #66 from these counts alone.
