# Ordinary confidence evaluation fixtures

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

The shared #66 corpus presently measures HORIZON SACK trials and scanner
baselines, but does not supply independent held-out labels for these ordinary
claims. The synthetic report must never be described as population calibration.
