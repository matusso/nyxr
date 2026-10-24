# HORIZON adaptive planning and profiles: retrospective comparison, 2026-10-23

**Status: complete for issue #72. All five registered gates pass.** Over the
30 recorded [#70 cross-port studies](../2026-10-23-cross-port-linux-arm64/RESULTS.md),
adaptive role selection with exact curtailment kept 30/30 correct
classifications (exact 95% interval 88.4–100%, the same as the fixed design)
and transmitted 2,682 packets instead of 8,640 (−69%). This is a
**retrospective** comparison: every configuration draws each role it asks for
from the same recorded report. It sends no traffic, and it supports no claim
about prospective runs, other mechanisms or deployed networks.

## Protocol and inputs

- Protocol [`adaptive-protocol.json`](../../live/adaptive-protocol.json)
  (sha256 `01449ed4…`), registered before any corpus-wide run; one study was
  replayed earlier as a smoke test. Evaluator
  [`adaptive_eval.py`](../../live/adaptive_eval.py).
- Corpus: the #70 `raw-corpus.tar.gz` (sha256 `c31c454e…`), 30 studies on four
  known topologies: 24 IPv4 studies with all five roles and 6 IPv6 studies with
  main and same-port only.
- Binary: built from commit `046b5e8` ([`binary-buildinfo.txt`](binary-buildinfo.txt)).

## Classification and traffic

| Configuration | Correct | Packets | Roles run | Duration | Stops |
| --- | ---: | ---: | ---: | ---: | --- |
| fixed: every recorded role (`--full-coverage`) | 30/30 | 8,640 | 132 | 59.0 min | full-coverage 30 |
| adaptive, classification | 30/30 | 3,708 (−57%) | 57 | 19.4 min | sufficient 27, indistinguishable 3 |
| adaptive + exact curtailment | 30/30 | 2,682 (−69%) | 57 | 14.2 min | sufficient 27, indistinguishable 3 |
| adaptive + curtailment + direction/cooldown | 30/30 | 3,858 (−55%) | 81 | 25.3 min | sufficient 27, indistinguishable 3 |

Packets are the transmitted SYNs plus RST cleanup that each configuration
used. Retrospective curtailment ends a role's duration at the next pair's first
send, which is an upper bound. The three `indistinguishable` stops are the
IPv6 shared-endpoint studies: without a recorded null control, no available
role separates shared state from nonspecific dependence. Their
classification matches the fixed design over the same two roles.

| Topology | fixed | adaptive + curtailment | + direction/cooldown |
| --- | ---: | ---: | ---: |
| independent IPv4 (6) | 2,088 | 576 | 576 |
| independent IPv6 (3) | 432 | 288 | 288 |
| per-port IPv4 (6) | 2,016 | 588 | 588 |
| shared-endpoint IPv4 (6) | 1,872 | 540 | 1,128 |
| shared-endpoint IPv6 (3) | 360 | 150 | 150 |
| shared-path IPv4 (6) | 1,872 | 540 | 1,128 |

The planner ran main, then null for shared state or same-port otherwise; with
refinements, it added reverse and time-separated only for shared state. In
this lab, effects were all-or-nothing, so exact curtailment decided every role
early: suppressed roles after 10 of 12 pairs, unaffected roles after 8.

## Behavior profiles

One profile was built from study 000 of each topology and address family
(TTL 24 h) and applied to every other study of the same family: 102
applications.

| | Applications | Valid |
| --- | ---: | ---: |
| same topology | 24 | 24 |
| different topology | 78 | 0 |

The 78 invalidations were behavior drift alone in 42, a path change alone in
12, and both in 24. In 39 of them the study also predates the profile, which
is a separate invalidation. A path change means the reply TTL differed: 64 at the
endpoint versus 63 behind the router. Shared-endpoint and shared-path profiles
therefore invalidate each other, even though both classify as shared state.
In the 24 valid applications, the refined task used 2,162 packets, against
3,142 without a profile and 7,068 for the fixed design. Direction and cooldown
were profile-inferred, and every inferred value equals what the fixed design
measured.

## Gates

| Gate | Result |
| --- | --- |
| G1 no accuracy loss | pass: no configuration or profile application is wrong where fixed is right |
| G2 traffic | pass: 2,682 < 8,640 packets |
| G3 honest coverage | pass: every tested statement cites only roles that were run, every not-tested statement is `untested`, and fixed ran every recorded role |
| G4 profile invalidation | pass: valid in 24/24 same-topology and 0/78 cross-topology applications |
| G5 profile inference | pass (after a fix, below) |

**First run: G5 failed.** The IPv6 shared-endpoint profiles never tested
cooldown, yet supplied `rate-limiter: not-elevated` as a profile-inferred
value in two applications. The fixed design reported that statement as
untested. A profile's limiter status only says that no orthogonal signal was
measured, so it must not stand in for a test. A code review then added
fail-closed checks (malformed change scopes, changes during a profile's
evidence window, future-dated profiles); the evaluation was re-run on the
amended commit with the same gate results. The fix makes a profile without
a tested cooldown supply no limiter status, and a unit test covers it.
[`without-g5-fix-summary.json`](without-g5-fix-summary.json) reproduces the
failing run: the same commit with only that condition reverted.

## Counterexamples

Every difference from the fixed design is listed in [`summary.json`](summary.json)
(72 entries). All 72 come from the classification-only configurations on the
12 shared-state IPv4 studies. They report direction, cooldown and rate-limiter
as `not-tested`/`untested`, where the fixed design measured `symmetric`,
`cooldown` and an elevated `rate-limiter` hypothesis. This is information
traded for traffic, not a wrong answer; the refined configuration has none.

The [operator guide](../../../../docs/horizon/adaptive-profiles.md) describes a
counterexample outside the declared model: dependence only on the unrelated
null port. A unit test reproduces it. No recorded study showed it, so this
corpus cannot measure how often it occurs.

## Files

- `summary.json`: gates, per-configuration and per-topology totals, profile
  statistics and every counterexample.
- `detail.json.gz`: per-study rows for each configuration and profile
  application.
- `without-g5-fix-summary.json`: the reproduced failing first run.
- `binary-buildinfo.txt`: binaries, corpus and protocol hashes.
