# HORIZON Phase 3: environmental controls and calibrated HZ-001/HZ-002

Issue [#69](https://github.com/matusso/nyxr/issues/69). This phase adds
controls that make an HZ-001 comparison either credible or explicitly
unresolved: one declared treatment, recorded confounders, interleaved
reference probes, an A/A stability experiment (HZ-002), a deterministic
environment assessment, and a pre-registered calibration of the decision rules.
Nothing here identifies an OS, middlebox or topology.

## DSL additions (v1alpha2)

| Field | Meaning |
| --- | --- |
| `changedVariable: none` | HZ-002 A/A run. Both arms must expand to identical baseline probes; arm order is the only difference. |
| `confounders: [...]` | Declared unavoidable confounders from a closed vocabulary: `ambient-load`, `path-routing`, `remote-state-reuse`, `source-port-reuse`, `middlebox-normalization`, `clock-resolution`, `rate-limiting`. Unknown or duplicate values are rejected. |
| `execution.referenceEvery: N` | After every N pairs, send one baseline reference probe (same port/window as the first control probe). References use reserved probe slot 31, share the packet/rate/capture budgets and are excluded from the comparison. |

`sackPermitted` still allows only SACK permission to differ between arms, so
the single declared treatment is checked by the compiler. v1alpha1 rejects the
new fields. Samples: [`hz-001-environment.yaml`](../../lab/horizon/hz-001-environment.yaml)
and [`hz-002.yaml`](../../lab/horizon/hz-002.yaml).

```sh
./nyxr horizon resolve --experiment lab/horizon/hz-002.yaml --policy lab \
  --allow-targets 192.0.2.0/24 --allow-ports 443 --simulate stable --output aa.json
./nyxr horizon explain aa.json
./nyxr horizon environment aa.json
```

## Environment assessment (`horizon-environment/v1`)

Every new report has an `environment` object, computed from retained trials
after the run. Replay recomputes it and rejects a mismatch. Older reports have
no saved assessment; `horizon environment REPORT` replays them and assesses
them offline without changing their saved comparison.

The rules were fixed before any live Phase 3 data was collected:

| Check | Rule | Effect |
| --- | --- | --- |
| Confounders | Declared plus inherent `ambient-load`, `sequence-and-ip-id-tokens` (and `cross-port-state` for cross-port scope) | Recorded |
| Throttling | Answered trials, second half versus first half of the schedule; one-sided Fisher exact p ≤ 0.05 | **Gating** `throttling-suspected` |
| Reference loss | Any interleaved reference probe unanswered | **Gating** `reference-loss` |
| Clock reliability | Any trial flagged `clock-instability` or `invalid-backend-timing` | **Gating** `clock-unreliable` |
| Carryover (washout) | First-probe pairs: discordance in control-first versus treatment-first pairs; two-sided Fisher exact p ≤ 0.05 | **Gating** `carryover-suspected` |
| RTT drift | ≥8 answered RTTs; half-medians differ by >10 ms and >50% | Descriptive `rtt-drift` |
| Paired stability | TTL, response class or non-SACK options (ignoring NOP/EOL padding) differ within a pair | Descriptive `paired-response-instability` |
| Clock precision | Evidence without measured precision (userspace clock) | Descriptive `clock-precision-unknown` |

Gating flags make the comparison `unresolved` with the conclusion
`environmental quality gate: …`. They never turn a run into a null result.

Latency is reported as per-arm medians and the median paired difference
(treatment − control) with a distribution-free order-statistic interval for
the median: the widest symmetric order-statistic pair whose exact binomial
coverage is at least 95%. The interval is omitted when fewer than six pairs
are available. It is userspace RTT that includes backend queueing,
and it assumes independent pairs.

## Pre-registered calibration

[`hz-phase3-protocol.json`](../../lab/horizon/calibration/hz-phase3-protocol.json)
(registered 2026-10-23, seed 69000, SHA-256
`7ea57d4d127bd4f7e25458781243ae7bba5d78f61928258a4cb6dbe89f33e7fe`) fixes:
1,000 runs per scenario, 12 pairs plus three reference probes per run, alpha
0.05, a false-positive ceiling of 5% on the exact one-sided 95%
Clopper–Pearson upper bound, and ≥90% detection of a clean injected effect
over all planned runs with no wrong-direction result.

```sh
./nyxr horizon calibrate --protocol lab/horizon/calibration/hz-phase3-protocol.json
```

The harness fills the **exact compiled schedule** with seeded generated trials
and runs the real `Assess`/`Compare` code. It opens no transport. The command
exits nonzero if any registered gate fails. Every planned run stays in its
denominator. Result (all registered gates pass):

| Scenario | Gate | Difference | No difference | Unresolved | Rate | Exact bound | Gating flags | Result |
| --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- |
| null-no-sack | false-positive | 0 | 1000 | 0 | 0.0% | 0.30% (upper) | — | pass |
| null-sack-both | false-positive | 0 | 1000 | 0 | 0.0% | 0.30% (upper) | — | pass |
| null-intermittent-sack | false-positive | 12 | 971 | 17 | 1.2% | 1.94% (upper) | carryover 17 | pass |
| aa-intermittent-sack | false-positive | 15 | 972 | 13 | 1.5% | 2.30% (upper) | carryover 13 | pass |
| null-jitter | false-positive | 0 | 1000 | 0 | 0.0% | 0.30% (upper) | — | pass |
| null-drift | false-positive | 16 | 972 | 12 | 1.6% | 2.42% (upper) | carryover 12 | pass |
| null-loss-5pct | false-positive | 1 | 246 | 753 | 0.1% | 0.47% (upper) | carryover 10, reference-loss 146 | pass |
| null-throttle | false-positive | 0 | 0 | 1000 | 0.0% | 0.30% (upper) | carryover 7, reference-loss 953, throttling 999 | pass |
| effect-clean | power | 1000 | 0 | 0 | 100.0% | 99.70% (lower) | — | pass |
| effect-jitter | power | 1000 | 0 | 0 | 100.0% | 99.70% (lower) | — | pass |
| effect-partial-70pct | descriptive | 947 | 36 | 17 | 94.7% | — | carryover 17 | — |
| effect-loss-5pct | descriptive | 245 | 0 | 755 | 24.5% | — | reference-loss 155 | — |
| effect-carryover | descriptive | 3 | 6 | 991 | 0.3% | — | carryover 991 | — |
| effect-throttle | descriptive | 0 | 0 | 1000 | 0.0% | — | reference-loss 964, throttling 1000 | — |

The intermittent-SACK nulls show the actual size of the exact sign test
(1.2–1.6%, below the nominal 5%). The injected carryover and throttling effects
are gated in more than 99% of runs. The carryover gate also fires in 1–2% of
null and partial-effect runs, which makes those runs unresolved, not wrong.
Any loss makes a run unresolved because every planned pair must complete. That
is conservative and costs detection power under loss (24.5% at 5% loss).

This calibrates the **decision rules** against a generative model whose runs
are independent by construction. It is not evidence about live networks.

## Review of earlier HZ-001 live evidence

All 744 retained live reports from the ten Phase 0 corpora (Linux, FreeBSD and
Windows, including failed and partial attempts) replay with the current code.
Assessed offline under `horizon-environment/v1`, **no existing inferred
conclusion would change**: no inferred run carries a gating flag. Nine FreeBSD
loss/jitter runs that were already unresolved are additionally flagged
`throttling-suspected`. After NOP/EOL padding is excluded, no run shows paired
TTL, response-class or non-SACK option instability.

The paired RTT difference interval contained zero in 696 of the 713 runs that
had one. Median interval widths were 0.18–0.32 ms in the clean corpora
(including the routed Windows study) and 2.0–7.0 ms in the corpora containing
loss/jitter strata. RTT therefore does not separate the SACK arms beyond
userspace timing noise, and it remains descriptive. Every report in the newer
corpora uses the userspace clock (`clock-precision-unknown`).

This review was required before cross-port work (#70) started.

## Live Phase 3 campaign

The [2026-10-23 Phase 3 corpus](../../lab/horizon/corpus/2026-10-23-phase3-linux-arm64/RESULTS.md)
ran 160 registered HZ-001/HZ-002 runs with reference probes, on SACK-enabled
and SACK-disabled Linux endpoints, over IPv4/IPv6, clean and under netem loss/jitter
([`phase3.py`](../../lab/horizon/live/phase3.py)). Every run completed and
matched its independent capture. There were zero false positives in 120 A/A
or SACK-disabled runs (77 resolved; exact one-sided 95% bound 3.82%), and the
clean effect was detected 40/40. All 53 unresolved runs came from netem loss,
and 9 of them were also gated by reference loss. A failed first attempt found
that veth TX checksum offload made HORIZON drop kernel SYN/ACKs as
invalid-checksum frames. That attempt is retained, and the lab now disables
the offload.

## Limitations

- Assessment rules are fixed heuristics with exact small-sample tests; they
  detect gross throttling, carryover and loss, not every nonstationarity.
- The A/A experiment is a null control for this decision rule on one target.
  It does not prove stack equivalence or independence.
- The calibration's generative model cannot represent dependent live trials,
  capture loss or kernel behavior. Population false-positive rates remain
  unknown.
