# HORIZON Phase 3 live campaign — 2026-10-23

**Status: complete for issue #69.** All 160 planned runs completed, replayed and
matched their independent captures. All 120 HZ-002 A/A and SACK-disabled runs
gave zero false positives. Clean SACK effects were detected 40/40. Both
registered gates pass. This is one shared-kernel Linux lab; no population
false-positive rate or cross-platform claim follows.

## Environment and protocol

- Docker engine 29.9.2, `7.0.14-linuxkit` aarch64, 18 CPUs, 8,317,267,968 bytes
  VM RAM. Image `sha256:811cab92fd63f50aa0cff07d7ca2a975606f364b119a83acd15ce8a9fce20d2a`
  (the issue-66 Dockerfile plus `ethtool`). Package versions are in
  [runtime-context.json](runtime-context.json), recorded right after the run.
- Network-disconnected container, private namespaces only, targets
  `10.77.0.2:443` / `[fd77:1::2]:443`. Binary build info is in
  [binary-buildinfo.txt](binary-buildinfo.txt).
- Collector [`phase3.py`](../../live/phase3.py) reuses the Phase 0 namespace
  topology. Its protocol [`phase3-protocol.json`](../../live/phase3-protocol.json)
  was registered before the collection and copied into the corpus before
  traffic. It fixes: 12 randomized pairs plus 3 interleaved reference probes,
  300 ms windows, 100 ms washout, 10 packets/s, 54 packets/90 s, seeds
  69100–69109, declared confounders `path-routing` and `remote-state-reuse`,
  and the two gates below.
- Strata: HZ-001 (SACK treatment) and HZ-002 (A/A) × Linux `tcp_sack=1` /
  `tcp_sack=0` × IPv4/IPv6 × clean / response-path `netem delay 20ms 5ms loss 5%`,
  10 runs each. Every run is in every denominator.

## Results

| Stratum | Planned | Outcomes | Gating flags |
| --- | ---: | --- | --- |
| HZ-001 linux v4 clean | 10 | difference 10 | — |
| HZ-001 linux v6 clean | 10 | difference 10 | — |
| HZ-001 null v4 clean | 10 | no-difference 10 | — |
| HZ-001 null v6 clean | 10 | no-difference 10 | — |
| HZ-002 linux v4 clean | 10 | no-difference 10 | — |
| HZ-002 linux v6 clean | 10 | no-difference 10 | — |
| HZ-002 null v4 clean | 10 | no-difference 10 | — |
| HZ-002 null v6 clean | 10 | no-difference 10 | — |
| HZ-001 linux v4 loss-jitter | 10 | difference 5, unresolved 5 | — |
| HZ-001 linux v6 loss-jitter | 10 | difference 5, unresolved 5 | — |
| HZ-001 null v4 loss-jitter | 10 | no-difference 3, unresolved 7 | reference-loss 1 |
| HZ-001 null v6 loss-jitter | 10 | no-difference 2, unresolved 8 | reference-loss 2 |
| HZ-002 linux v4 loss-jitter | 10 | no-difference 3, unresolved 7 | reference-loss 2 |
| HZ-002 linux v6 loss-jitter | 10 | no-difference 2, unresolved 8 | reference-loss 1 |
| HZ-002 null v4 loss-jitter | 10 | no-difference 6, unresolved 4 | reference-loss 1 |
| HZ-002 null v6 loss-jitter | 10 | no-difference 1, unresolved 9 | reference-loss 2 |

- **Gate 1, zero false positives: pass.** No inferred difference in any of the
  120 A/A or SACK-disabled runs. Of those, 77 were resolved (60 clean, 17
  under loss/jitter). Zero in 77 gives an exact one-sided 95% upper bound of
  3.82%; zero in the 60 resolved clean nulls gives 4.87%. Both bounds assume
  independent, stationary runs, which repeated runs on one kernel do not
  establish.
- **Gate 2, clean effect accuracy ≥90% over all planned runs: pass.** 20/20
  clean SACK-enabled HZ-001 runs show a treatment-only difference (12/12
  pairs, p = 0.00048828125).
- All 53 unresolved runs contain at least one timeout from the 5% netem loss.
  9 of them are also gated by `reference-loss`. No run triggered the
  throttling, carryover, clock or drift rules, and no run was invalid or
  missing.
- Paired RTT difference intervals (treatment − control) contained zero in 152
  of 160 runs. Median widths: 0.11–0.15 ms clean and 8.1–8.7 ms under
  loss/jitter. RTT remains descriptive.
- Runner transmissions per run: 48–54, depending on cleanup after
  unanswered probes. Wall time 11.0–11.2 s per run, 29.6 minutes in total.

## Failed attempts (retained in `failed-attempts/`)

1. **`aborted-binary-change`**: 9 complete runs and 1 empty report. I
   stopped this attempt deliberately when the stability rule was corrected to
   ignore NOP/EOL padding, so the saved assessments would not have matched
   the final code. Its complete reports replay with the final binary.
2. **`veth-checksum-offload`**: all 160 runs completed, and all 160 were
   **unresolved** with `reference-loss`, with zero false positives. The
   independent capture showed the endpoint answering every SYN within 25 µs,
   but its SYN/ACKs carried partial TCP checksums (veth TX checksum offload,
   `incorrect -> 0x2db3`). Since #68, HORIZON correlation rejects frames with
   invalid checksums. The control SYN/ACK was therefore never recorded and
   never cleaned up, and the paired treatment SYN on the same 4-tuple drew an
   RST from the half-open connection. The lab now disables TX checksum
   offload on its veths with `ethtool -K <dev> tx off` and records the setting
   in each truth snapshot. This affects any capture of locally generated,
   checksum-offloaded replies (for example containers over veth on the
   scanning host). Real NIC captures carry complete checksums. The Phase 0
   Linux corpus predates #68 and is unaffected.

## Files

[baseline-summary.json](baseline-summary.json) holds every run row and
stratum. [raw-corpus.tar.gz](raw-corpus.tar.gz) holds the campaign and the
failed attempts: reports, plans, experiments, independent PCAPs with drop
logs, truth snapshots before and after each run, resources, manifests and
the collector sources. [raw-artifact-hashes.json](raw-artifact-hashes.json)
hashes every archived file. [SHA256SUMS](SHA256SUMS) covers this directory.
Every complete report replays with the final binary (329 reports across the
campaign and attempts).
