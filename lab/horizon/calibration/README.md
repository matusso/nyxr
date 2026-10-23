# Ordinary confidence evaluation fixtures

`hz-phase3-protocol.json` is separate: it pre-registers the HORIZON Phase 3
decision-rule calibration run by `nyxr horizon calibrate` (see
[environmental controls](../../../docs/horizon/environment-controls.md)).
The rest of this page covers ordinary confidence fixtures.

This directory extends the shared HORIZON #66 lab with labeled ordinary
protocol, device, stack, port-state and identity cases. It does **not** change
HORIZON experimental statistics or provide a live accuracy claim.

`synthetic-v1.json` checks the evaluation pipeline. Its labels are synthetic,
and its tuning and held-out groups are disjoint. The held-out split tests code
behavior only; it is not representative of deployed networks. The `model` in
each case records the scoring rule revision. `label_source` records where truth
came from; `evidence_ref` names the observation or fixture used to form the
prediction. Cases from the same device or fixture must use the same `group`,
which cannot cross splits.

Run:

```sh
nyxr calibration evaluate --dataset lab/horizon/calibration/synthetic-v1.json
```

The versioned JSON report includes a SHA-256 of the exact dataset bytes,
counts and rates of correct, false and missed matches and unknown predictions,
plus transmitted packets and elapsed nanoseconds by split, claim kind and rule
version. Rates use every labeled case in that stratum as their denominator.
A wrong named label is both a false match and a missed true match. The ten-bin
expected calibration error and Brier score are diagnostics over cases
that have a numeric score and a named prediction. Unknowns stay in the
denominator and never turn into confident negatives. A missing numeric score
is unavailable, not zero. Packet and time totals are only as trustworthy as
their supplied measurement records.

Before using a measured corpus to tune or publish a calibration claim:

1. Register device and environment groups and a held-out assignment before
   fitting or adjusting rules. Keep repeats of one target in one split.
2. Retain independently checked protocol, device and identity truth plus raw
   observation references, counter quality and time provenance. Include
   negative, unknown, proxy and intermediary cases.
3. Evaluate each claim type and rule version separately. Do not pool device
   class, protocol, OS, port state, asset-link or HORIZON probabilities.
4. Report per-stratum denominators, unknowns, errors and uncertainty. Preserve
   failures and unresolved labels; do not silently discard them.

The shared #66 corpus measures HORIZON SACK trials and scanner baselines.
Its closure with limitations on 2026-10-19 does not supply independent held-out
service, device or asset-identity labels. The synthetic report must never be
described as population calibration.

## Measured datasets (v2)

Use `schema: "nyxr/calibration/v2"` for measured ordinary claims. The same CLI
accepts both versions. V1 remains supported for diagnostic fixtures; it does
not enforce measurement provenance. V2 adds a `registration` object:

```json
{
  "id": "ordinary-lab-study-1",
  "registered_at": "2026-10-20T12:00:00Z",
  "record_ref": "dated immutable record of this plan",
  "population": "exact machines, services and environments covered",
  "model_ref": "immutable source revision and scoring-rule configuration",
  "cases": [
    {"id":"linux-ssh-clean-1","group":"linux-machine-a","split":"tuning","kind":"protocol","model":"nyxr-planner/v1","stratum":"ipv4-clean"},
    {"id":"windows-http-clean-1","group":"windows-machine-b","split":"holdout","kind":"protocol","model":"nyxr-planner/v1","stratum":"ipv4-clean"}
  ]
}
```

This is a format illustration, **not a registered study or measured corpus**.
Freeze the actual plan in a dated external record before collection. Keep its
exact bytes and source revision. Do not edit the plan after seeing predictions.
Each planned ID, group, split, kind, model and stratum must match the observed
case. Missing or added cases reject evaluation; collect and retain failures
instead of excluding inconvenient outcomes. A failed scan with known truth is
an `unknown` prediction with its actual measured cost. An entirely unstarted
case blocks complete evaluation; preserve it separately as attrition and finish
collection or register a new study without erasing the failed attempt.

Each v2 case retains all v1 fields, adds a nonempty `stratum`, and records:

```json
"measurement": {
  "observed_at": "2026-10-20T12:30:00Z",
  "truth_ref": "retained native configuration or reviewed inventory record",
  "evidence_sha256": "sha256:<64 hex digits of the retained prediction artifact>",
  "counter_source": "scanner TX counter; capture loss and scope recorded separately",
  "clock_source": "monotonic elapsed time around scanner execution"
}
```

The truth reference must differ from the prediction's `evidence_ref`. The
measurement time must follow registration. Both `packets_tx` and `duration_ns`
must be supplied explicitly, including real zeros. Synthetic labels and fixture
references are rejected for v2. These structural checks cannot verify artifact
contents, labeling independence, representative sampling, or chronology; the
operator must review the underlying records. The report includes the exact
dataset hash and a hash of the registration serialized as compact Go JSON
(struct field order). Neither hash alone proves preregistration.

Results stay separate by split, claim kind, model and stratum. Each reports
observation and distinct-group counts, plus two-sided 95% Wilson intervals for
correct, false, missed and unknown rates. These are **conditional binomial
intervals**, assuming IID cases. Repeated observations of a machine do not
establish independent trials; the intervals are not cluster-adjusted and must
not be presented as population coverage. ECE and Brier remain diagnostics, with
no uncertainty claim attached to them. Costs are per claim: do not add costs
across claim kinds sharing one scan. Aggregate integer overflow is rejected.

## Collection checklist for operators

1. List the available machines/VMs, services and devices. Include native OS
   versions, service configurations, reviewed device models and known identity
   relationships. A service banner or scanner output is not independent truth.
2. Define the population and freeze the collection plan before scans. Reserve
   entire physical devices (and shared-kernel VM/namespace families where
   relevant) in one split. Different addresses of one machine stay together.
3. Include known open/closed/filtered ports, silent and unknown services,
   intermediary/proxy cases, the same asset at different addresses, and distinct
   assets with shared names/certificates. State unavailable strata explicitly.
4. Retain raw versioned observations, configuration/inventory truth, exact
   scanner source/settings, packet counter scope/quality, capture loss and
   monotonic durations. Hash each prediction artifact. Bound scan scope and
   traffic to the operator-authorized lab.
5. Adjust candidate rules using tuning cases only; freeze the selected revision
   before collecting a fresh registered holdout. If comparing versions, retain
   the baseline and candidate reports. Publish errors, unknowns, group counts
   and costs per stratum, including negative results. A small controlled lab
   supports only scoped lab conclusions; leave numeric scores heuristic until
   an adequately representative independent evaluation supports more.
