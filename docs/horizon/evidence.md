# HORIZON evidence, ablations and negative results

One index of what the HORIZON lab corpora show, what they do not show, and
every failure kept on record. Paths are relative to the repository root. Each
corpus directory has `RESULTS.md` and `SHA256SUMS` (SHA-256 detects corruption;
reports are **not** signed). All results are from private lab namespaces and
VMs. No production or third-party traffic was used.

## Corpora

| Corpus (`lab/horizon/corpus/…`) | Result | Status |
| --- | --- | --- |
| `2026-10-10-linux-arm64` | 44 HZ-001 reports. 18-row matrix: 4 SACK differences, 5 no difference, 9 unresolved; all 9 clean rows agree. Null/proxy: 15 no-difference, 9 unresolved, 0 false positives | Exploratory. Registered null gate **not passed** (0/3 per clean stratum) |
| `2026-10-11-windows-arm64` | 3 valid IPv4 baselines with the expected SACK difference | 3 earlier runs invalid (empty scanner captures). No Windows null |
| `2026-10-11-windows-ipv6-arm64` | 3/3 IPv6 runs with the expected difference | SACK not toggled, so no null |
| `2026-10-12-freebsd-arm64` | 12/12: 6 SACK-on differences, 6 SACK-off no-difference (IPv4/IPv6) | Controlled native toggles, small n |
| `2026-10-12-freebsd-vnet-failed-arm64` | Concurrent 588-run study: 16 started, 12 valid, 572 missing | **Kernel panic.** Kept, not pooled |
| `2026-10-12-freebsd-vnet-sequential-arm64` | 588/588 valid: 313 null, 63 difference, 212 unresolved; **0 false positives** | One shared kernel, so strata are not independent hosts. VM panic after teardown |
| `2026-10-13-windows-study-ipv{4,6}-arm64` | Each: 12/12 clean SACK difference, 3/3 firewall DROP unresolved | No SACK null |
| `2026-10-19-windows-routed-v1-failed-arm64` | 7/27 runs | **Router panic under dummynet.** Kept, not pooled |
| `2026-10-19-windows-routed-arm64` | 38 valid. Clean 12/12 per family, DROP 3/3 | `SackOpts` null control ineffective, so the 120 null runs were stopped by rule |
| `2026-10-23-phase3-linux-arm64` | 160/160; 0 false positives in 120 A/A or SACK-off runs (one-sided 95% bound 3.82%); clean effect 40/40; 53 unresolved, all netem loss | Two failed attempts kept (binary change, veth checksum offload) |
| `2026-10-23-cross-port-linux-arm64` | 30 studies, 132 role runs; see ablation (b) | Campaign 1 collector bug kept |
| `2026-10-23-adaptive-replay` | Retrospective over the 30 cross-port studies; see ablations (d), (e) | First run failed G5; kept as `without-g5-fix-summary.json` |

Synthetic calibration (`lab/horizon/calibration/hz-phase3-protocol.json`,
seed 69000, 1,000 runs per scenario): all registered gates pass; null
false-positive rate 0–1.6%; clean detection 100%; detection under 5% loss 24.5%.

## Ablations (roadmap §9)

**(a) Randomized controls: not run.** No campaign without randomized order or
controls exists, so randomization's contribution is unmeasured.

**(b) Cross-port vs matched isolated controls.** Source:
`2026-10-23-cross-port-linux-arm64/RESULTS.md`, protocol
`lab/horizon/live/crossport-protocol.json`.

| Ground truth | Studies | Cross-port correct | Isolated correct |
| --- | ---: | ---: | ---: |
| independent | 9 | 9 | 9 |
| per-port state | 6 | 6 | 0 |
| shared endpoint | 9 | 9 | 0 |
| shared path | 6 | 6 | 0 |
| **Total** | 30 | **30/30** (95% CI 88.4–100%) | **9/30** (14.7–49.4%) |

12 randomized pairs per role, 100 ms windows, 600 ms washout, 10 pps; limiter
`iptables -m limit --limit 2/second --limit-burst 1`. The isolated rule can never
output shared or per-port state, so 9/30 is just the share of independent
studies. This shows the precondition design adds information. It does **not**
show superiority over a stronger isolated method at equal packet cost.

**(c) Orthogonal corroboration: partial.** `rate-limiter` was elevated in 12/12
IPv4 shared studies, which had the time-separated role, and not elevated in 3/3
IPv6 shared studies, which lacked it. This is a natural contrast, not a designed
ablation. `firewall-tracking` never fired.

**(d) Adaptive selection, retrospective.** Source:
`2026-10-23-adaptive-replay/RESULTS.md`, evaluator
`lab/horizon/live/adaptive_eval.py`.

| Configuration | Correct | Packets | Roles | Duration |
| --- | ---: | ---: | ---: | ---: |
| fixed | 30/30 | 8,640 | 132 | 59.0 min |
| adaptive | 30/30 | 3,708 (−57%) | 57 | 19.4 min |
| + exact curtailment | 30/30 | 2,682 (−69%) | 57 | 14.2 min |
| + curtailment + direction/cooldown | 30/30 | 3,858 (−55%) | 81 | 25.3 min |

Curtailed durations are upper bounds. All figures replay recorded pairs; no
prospective adaptive run exists.

**(e) Profile compression.** Same-topology applications: 24/24 valid, 2,162
packets vs 3,142 without a profile and 7,068 fixed; every inferred value matched
the fixed measurement. Different-topology applications: 0/78 valid (drift or
path change detected). Profiles were built and applied within one corpus on one
day, never on held-out hosts or later periods.

## Negative results and failures

1. Adaptive G5: IPv6 profiles that never tested cooldown reported
   `rate-limiter: not-elevated` as inferred. Fixed; failing run kept.
2. 72 classification-only gaps: the adaptive planner reports direction,
   cooldown and rate-limiter as `not-tested` where fixed runs measured them.
   `--refine` removes them.
3. Out-of-model case: dependence only on the null port makes the adaptive planner
   report `no-coupling` where the fixed design says `unresolved`. Unit test only.
4. Endpoint- and path-hosted limiters give identical candidates and graphs.
5. Cross-port campaign 1 collector bug (IPv6 readiness on an IPv4-only topology).
6. veth checksum offload made all 160 first Phase 3 runs unresolved.
7. Phase 3 attempt aborted after a mid-campaign binary change.
8. FreeBSD VNET concurrent study: kernel panic, 572/588 missing.
9. FreeBSD sequential study: VM panic after teardown, cause unknown.
10. Windows routed v1: router panic under dummynet shaping.
11. Windows `SackOpts` null control ineffective; no controlled Windows null.
12. Windows IPv4 initial study: 3 invalid baselines.
13. Linux Phase 0 null gate not passed; the ordinary scanner reported a
    known-open port as `filtered` under loss.
14. Any loss makes a run unresolved (24.5% detection at 5% loss; 53/80
    Phase 3 loss/jitter runs unresolved).
15. Carryover gate: 1–2% of calibration null runs made unresolved.
16. RTT is not discriminative: the paired interval contained zero in 696/713
    historical and 152/160 Phase 3 runs.
17. A SACK sysctl change is not auto-detected; it must be declared.

## Not supported by this evidence

- Results on deployed or third-party networks.
- Discrimination of NAT, proxy, load balancer or connection tracking (`notEvaluated`).
- Endpoint vs path localization (the TTL-divergence branch never fired live).
- Cross-port advantage at a matched packet budget.
- Prospective adaptive savings, or curtailment exactness under real impairment.
- Randomization's contribution (ablation a).
- Population false-positive rates (repeated runs share a kernel; calibration is synthetic).
- Windows null behavior.
- Causal mechanisms: reports state dependence and association only.
- Profile generalization across hosts or time.

## Reproduce

```sh
(cd lab/horizon/corpus/<dir> && shasum -a 256 -c SHA256SUMS)
nyxr horizon replay report.json            # offline, no traffic
python3 lab/horizon/live/crossport.py analyze --output campaign-1 --output campaign-2
nyxr horizon calibrate --protocol lab/horizon/calibration/hz-phase3-protocol.json
```
