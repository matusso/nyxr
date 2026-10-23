# HORIZON Phase 6: adaptive planning and behavior profiles

Issue [#72](https://github.com/matusso/nyxr/issues/72). Phase 4 runs every
cross-port study role. Phase 6 runs only the roles that can still change the
answer, stops each role as soon as its decision is fixed, and can reuse an
earlier validated study as an expiring **behavior profile**. Coverage stays
explicit: every statement and port is `tested`, `profile-inferred` or
`not-tested`, and `--full-coverage` never skips a role.

The planner does not classify anything itself. The Phase 4 classifier
(`AnalyzeCrossPort`) still decides, using only the roles that were actually run.

## Exact curtailment within a role

`execution.stopRule: curtail` (v1alpha2 precondition experiments only) stops
a role after at least 8 complete pairs once no outcome of the remaining pairs
can change the fixed-n paired sign-test decision (α = 0.05). This is exact
curtailment, not a sequential test with a new error rate: the curtailed
decision always equals the fixed-n decision on those pairs. The report records
`curtailment` (rule, pairs, decision). Replay rejects a curtailment that the
recorded pairs do not support, a stop later than the first decisive pair, and
a curtail-rule run that kept going after a decisive pair.

With 12 pairs, all-or-nothing suppression is decided after 10 pairs and no
effect after 8. Exactness holds for the sign-test decision, **conditional on
the unrun pairs being clean**. The fixed-n design would also have required
every remaining pair to be complete, no backend drops and no environment gate.
A pair that would have broken or a gate that would have fired only later is
never observed, so the fixed-n run could have been `unresolved` where the
curtailed run is `inferred`.

## Role selection and stop rules

The planner holds a declared set of hypotheses, each predicting which roles
show dependence:

| Hypothesis | main | same-port | null | reverse | time-separated |
| --- | --- | --- | --- | --- | --- |
| `no-coupling` | – | – | – | – | – |
| `per-port-state` | – | ✓ | – | – | – |
| `shared-state/{symmetric,one-way}/{cooldown,persistent}` | ✓ | ✓ | – | symmetric | persistent |
| `nonspecific` (classifier: `unresolved`) | ✓ | ✓ | ✓ | ✓ | ✓ |

The prior is uniform over the four classifier outcomes, and the shared-state
mass is split evenly over its four variants. The task is always the
classification, plus optional `--refine direction,cooldown`. For each
remaining role the planner computes the expected information about the task in
bits, I(task; outcome), minus `--lambda` × the role's compiled worst-case
packets. This is the roadmap's selection criterion; it is a heuristic, not a
probability of the conclusion. `main` and any `--require` roles always run
first. Budgets are checked against each role's compiled worst case before it
starts, and `spent` is measured. Packets can never exceed the budget. Duration
can overshoot when a role runs past its compiled bound; each role's
`maxDurationSeconds` deadline still caps it. Stop reasons:

| Stop | When |
| --- | --- |
| `sufficient` | Every consistent hypothesis agrees on the task. |
| `budget` | An informative role remains, but its worst-case cost exceeds the remaining `--budget-packets`/`--budget-ms`, or its information is worth less than its cost at `--lambda`. |
| `indistinguishable` | No available role separates the remaining hypotheses (for example, IPv6 studies without a null control). |
| `model-inconsistent` | The outcomes contradict every declared hypothesis. |
| `main-unresolved` | The classifier cannot resolve a study whose main role is unresolved. |
| `full-coverage` | `--full-coverage` ran every available role. |
| `error` | A role failed or was cancelled. Completed steps are kept; statements and the study are empty or `unresolved`. |

A `budget` or `model-inconsistent` stop that leaves different classifier
outcomes open reports the classification statement as `unresolved`, even when
the classifier, which treats missing controls as optional, would name one.
An `indistinguishable` stop keeps the classifier's answer and states the open
alternative, because a fixed study of the same roles has the same limit.

## Behavior profiles

`horizon profile build --study role=R,... --class LABEL --ttl D` compresses a
resolved study into a versioned profile (`horizon.nyxr.io/profile/v1`). A
profile records the classification, direction, cooldown and infrastructure
hypotheses, the subjects, the vantage (source address, backend, correlation
version), the target's reply-TTL and non-SACK option fingerprint, and the
evidence runs. Its ID is the SHA-256 of the content, and its validity is
capped at 30 days. Every role must be resolved and agree on vantage and
fingerprint.

`horizon profile check` and every `adapt --profile` run check the profile
against current evidence. Any one of these reasons invalidates it:

- expiry, or an evaluation time before the profile was built;
- a declared `--change` for the host or network at any time after the
  profile's first run started (upgrades, reconfiguration). Scopes must be
  `network` or `host:<IP>`; addresses are compared canonically, and a
  malformed scope is rejected rather than ignored;
- a different vantage;
- a **path change** (disjoint reply TTLs);
- a **host change** (a different TCP option layout);
- **behavior drift** in any tested statement;
- an unresolved current classification.

A profile only ever replaces refinements (direction, cooldown and the
rate-limiter status that depends on cooldown); the classification is always
tested again. A profile that never tested cooldown cannot supply a limiter
status. If the profile fails its check, the planner tests the refinements
after all.

## Coverage

`statements` and `ports` in the `AdaptiveStudy` output
(`horizon.nyxr.io/adaptive/v1`) separate:

- `tested`: measured by a role run in this study (with its run IDs);
- `profile-inferred`: supplied only by a profile that passed its check;
- `not-tested`: neither, and the value is `untested`.

A port probed only by unresolved roles is `tested-unresolved`: traffic was
sent, but it supports no statement.

`--full-coverage` runs every available role whatever the profile predicts,
and refuses to start when the budget cannot cover all of them.

## Usage

```sh
# Synthetic (no traffic): main and null are enough to resolve shared state.
./nyxr horizon adapt --main lab/horizon/cross-port/main.yaml \
  --same-port lab/horizon/cross-port/same-port.yaml --null lab/horizon/cross-port/null.yaml \
  --reverse lab/horizon/cross-port/reverse.yaml --time-separated lab/horizon/cross-port/time-separated.yaml \
  --policy lab --permit cross-port --allow-targets 192.0.2.0/24 --allow-ports 443,8443,9443 \
  --simulate shared-limit --curtail --budget-packets 400

# Offline evaluation of a recorded study (no traffic).
./nyxr horizon adapt --replay main=m.json,same-port=s.json,null=n.json,... --retro-curtail
./nyxr horizon profile build --study main=m.json,... --class lab-shared --ttl 24h --output p.json
./nyxr horizon adapt --replay main=m2.json,... --refine direction,cooldown --profile p.json
```

Live mode takes the same link options as `resolve`; `--evidence-dir` saves
each role's sealed report. Existing `--output` or evidence files are refused
before any traffic is sent. `--retro-curtail` (replay only) evaluates
curtailment on recorded pairs. Those results are not replayable reports,
because the recorded experiment hash does not cover the stop rule.

## Measured comparison (retrospective)

The [registered protocol](../../lab/horizon/live/adaptive-protocol.json) and
[`adaptive_eval.py`](../../lab/horizon/live/adaptive_eval.py) replay the 30
recorded [#70 studies](../../lab/horizon/corpus/2026-10-23-cross-port-linux-arm64/RESULTS.md)
through each configuration. Results are in the
[adaptive replay corpus](../../lab/horizon/corpus/2026-10-23-adaptive-replay/RESULTS.md).

| Configuration | Correct | Packets | Roles run | Duration |
| --- | ---: | ---: | ---: | ---: |
| fixed (all recorded roles) | 30/30 | 8,640 | 132 | 59.0 min |
| adaptive | 30/30 | 3,708 (−57%) | 57 | 19.4 min |
| adaptive + curtailment | 30/30 | 2,682 (−69%) | 57 | 14.2 min |
| adaptive + curtailment + direction/cooldown | 30/30 | 3,858 (−55%) | 81 | 25.3 min |

All five registered gates pass. Profiles were valid in 24/24 applications to
their own topology and invalid in 78/78 applications to other topologies:
42 by behavior drift alone, 12 by a path change alone and 24 by both. In the
24 valid applications, the refined task used 2,162 packets instead of 3,142
without a profile, or 7,068 for the fixed design. Every profile-inferred value
equaled what the fixed design measured.

**Counterexamples (published):**

- With the classification-only task, the 12 shared-state IPv4 studies report
  direction, cooldown and rate-limiter as `not-tested`, where the fixed design
  measured `symmetric`, `cooldown` and an elevated `rate-limiter` hypothesis.
  This is information given up for traffic, not an error. `--refine` recovers
  it.
- **Outside the declared model:** dependence that appears only from the
  unrelated null port, with no main-role dependence, is classified
  `unresolved` by the fixed design. The adaptive planner stops after main and
  same-port and reports `no-coupling`. A unit test reproduces this, and
  `--require null` removes it at the cost of the null role. No recorded study
  showed this pattern.
- The first run of the evaluation failed G5: a profile without a tested
  cooldown supplied `rate-limiter: not-elevated` as an inference. This is
  fixed (see above); the failure is kept in the results.

## Limitations

- The comparison is retrospective. It replays recorded pairs and roles; a
  prospective adaptive run would observe different pairs.
- One shared-kernel Linux lab with SYN token-bucket limiters only.
  Repetitions are not independent hosts, so no claim covers other mechanisms
  or deployed networks.
- Role predictions are deterministic and the prior is declared, not
  calibrated. The planner trades information it does not need for traffic;
  it never raises confidence in a conclusion.
