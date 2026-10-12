# Interrupted concurrent FreeBSD VNET study, 2026-10-12

The separately registered 588-report study was interrupted by a native kernel
panic and reboot. Sixteen runs started: 12 valid full baselines, four invalid
and 572 unstarted/missing. Valid outcomes were six null results, two expected
SACK differences and four unresolved reports. No acceptance gate passed.
The subsequent sequential study is a new registration and is not pooled with
this attempt.

## Registration and native ground truth

`horizon-freebsd-vnet-config-reserved/v1` froze the full plan before probes:
two fresh development/reserved VNET configurations, IPv4/IPv6, clean or
loss-jitter, native SACK disabled/enabled. Each role/family/condition had 60
null and 12 effect repetitions, followed by three DROP checks per role/family.
Seeds were 66400–66987, with twelve balanced randomized blocks per role.
Two workers could run concurrently, at most 6pps combined. Each run retained
the existing 12-pair, 800ms window, 300ms washout, 3pps, 48-packet and 90s bounds.

The operator-owned FreeBSD 15.1-RELEASE-p4 ARM64 VM had 256MB configured RAM.
Read-only jail runtime mounts, separate TCP stacks, adapters and private
IPv4/IPv6 addresses supplied configuration separation on one shared kernel.
Native SACK sysctls, assigned interfaces, routes and fixed firewall/dummynet
rules/counters were recorded before and after each sealed run. The impairment
was an empirical uniform 15–25ms delay, 5% loss and 100Mbit/s cap, applied only
to outgoing measurement SYN-ACKs. The fixed-message control path bypassed it.
This is endpoint fixture coverage, not native FreeBSD Nyxr backend validation.

Protocol source SHA-256:
`431328acfcdbec0d7f6062e4c6ac2c57dd906a7587423eddaca2b2e4449264cd`.
The collector's serialized protocol has a distinct formatting checksum,
recorded in the manifest and runtime context; semantic equality is verified.

## Outcomes and failure retention

| Role / family / condition / SACK | Planned | Started | Invalid | Missing | Unresolved valid | Correct |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Development / v4 / clean / off | 60 | 1 | 0 | 59 | 0 | 1 |
| Development / v4 / clean / on | 12 | 1 | 0 | 11 | 0 | 1 |
| Development / v4 / loss-jitter / off | 60 | 1 | 0 | 59 | 0 | 1 |
| Development / v4 / loss-jitter / on | 12 | 1 | 0 | 11 | 1 | 0 |
| Development / v6 / clean / off | 60 | 2 | 0 | 58 | 0 | 2 |
| Development / v6 / clean / on | 12 | 0 | 0 | 12 | 0 | 0 |
| Development / v6 / loss-jitter / off | 60 | 1 | 1 | 59 | 0 | 0 |
| Development / v6 / loss-jitter / on | 12 | 1 | 1 | 11 | 0 | 0 |
| Reserved / v4 / clean / off | 60 | 1 | 0 | 59 | 0 | 1 |
| Reserved / v4 / clean / on | 12 | 0 | 0 | 12 | 0 | 0 |
| Reserved / v4 / loss-jitter / off | 60 | 3 | 1 | 57 | 2 | 0 |
| Reserved / v4 / loss-jitter / on | 12 | 1 | 0 | 11 | 0 | 1 |
| Reserved / v6 / clean / off | 60 | 2 | 1 | 58 | 0 | 1 |
| Reserved / v6 / clean / on | 12 | 0 | 0 | 12 | 0 | 0 |
| Reserved / v6 / loss-jitter / off | 60 | 1 | 0 | 59 | 1 | 0 |
| Reserved / v6 / loss-jitter / on | 12 | 0 | 0 | 12 | 0 | 0 |
| Each of four role/family DROP strata | 3 | 0 | 0 | 3 | 0 | 0 |

Two sealed baselines had runner backend drops (29 and 35), despite zero drops
reported by their independent kernel captures. They remain invalid. Two final
started runs lack post-run truth and also remain invalid. All 16 raw HORIZON
reports are retained and replayable; replayability does not make a baseline
valid. No repeat replaces any failed or missing outcome. Raw/resource metrics
and every stratum's denominator are in `baseline-summary.json`.

The panic was recorded at 18:08:26 UTC; the native boot timestamp records a
reboot at 18:08:56 UTC. Local symbol inspection places the fault address in
`if_getafdata`; the available backtrace does not establish a specific dummynet
bug or causal mechanism. No kernel fix is claimed. The memory dump is excluded
from this corpus. Later native storage health evidence is retained without
claiming an identified hardware failure or repair.

The collector's stop requests timed out. **Cleanup traps were not verified.**
Separate post-reboot evidence records original host SACK value 1, original
interface flags/capabilities/routes and no surviving study jails or modules.
Reboot recovery is not normal trap-based cleanup. The source alias remained
owned by its bounded helper for the subsequent study.

Three earlier bootstrap preflights stopped before experimental probes: a jail
inventory header, a newer IPFW counter format and missing jail protocol-name
database each caused conservative setup rejection. Their native archives and
accounting remain separate. The corrected bootstrap supplies the read-only
protocol-name database and passed CLEAN, IMPAIR and DROP control preflights.

## Archive and verification

`raw-corpus.tar.gz` retains 583 regular files, including all reports/captures,
native helper binary/source, truth, resources, failure/recovery logs, preflight
archives and frozen collector/Go source. It excludes VM configuration files,
SSH keys, credentials and kernel memory dumps. Archive size: 833,181 bytes;
SHA-256:
`4c444dca17bca8dd8f71f0acf6952910db8004108590136140f00d11ee77fee1`.

All extracted raw-file hashes passed. All 16 reports replayed identically.
Frozen v1 re-analysis reproduced the stored summary, allowing only relocation
of absolute paths in the two missing-file error strings. The frozen 26-test
offline suite passed in an unprivileged network-disconnected Linux container;
macOS executed 24 with two Linux-only tests skipped. Native C compilation used
warnings as errors. The measured Darwin ARM64 Go 1.27.2 binary SHA-256 is
`951278fab4e04baf80d54cf74fab0cd96b6ae5a2e3b3898f02824f3137d22991`.
Dirty VCS build metadata is retained; the source snapshot does not claim a
reproducible clean-commit binary.

Offline replay and analysis open no network transport:

```sh
nyxr horizon replay development-v4-clean-sack0-00-1/horizon/report.json
python3 frozen-source/live/bsd_study.py analyze --binary /path/to/nyxr --output .
```

Issue #66 remains open. Shared-kernel reserved configurations cannot establish
physically independent held-out coverage or population independence. All
confidence bounds are conditional on IID assumptions. Missing/invalid and
unresolved results prevent numerical acceptance in this interrupted attempt.
