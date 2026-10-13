# Native Windows IPv4 clean/block study

The separately registered `horizon-windows-native-clean-block/v1` study planned 12 clean
effect-hypothesis reports and three known firewall DROP reports for IPv4.
All planned outcomes are retained in their own denominator. The protocol was
committed before live traffic; the native helper never changed SACK.

| Stratum | Planned | Valid | Invalid | Missing | Expected outcome | Correct |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| Clean | 12 | 12 | 0 | 0 | SACK difference | 12 |
| Firewall blocked | 3 | 3 | 0 | 0 | Unresolved | 3 |

All 15 ordinary scanner checks matched native truth (12 open, three filtered).
The clean reports emitted 576 HORIZON runner packets and captured 924 packets /
53,544 bytes independently; their wall time was 27.220–27.229s per run and
reply RTT median 1.250–1.376ms. The blocked reports emitted and captured 72
packets / 4,320 bytes, with 72 expected arm timeouts and no replies. Across
the study, scanner captures retained 27 packets / 1,506 bytes. Independent
captures reported zero kernel drops, and HORIZON peak source-child RSS was
29,408–30,288 KiB. Timings and resources describe this source workload, not
calibrated wire latency or a speedup claim.

The clean numerical effect threshold is met
under the recorded finite workload. This is not a controlled native Windows
SACK-disabled null or an IID population accuracy result. The native `SackOpts`
registry value was `absent` at the start and checked around every run.
The blocked rule applied only to the measurement peer on TCP 443; a separate
fixed control connection recorded its presence. Blocked reports are not
reclassified as resolved nulls. Fixture cleanup was verified.

All 15 canonical reports replayed. The 238 raw files in
`raw-corpus.tar.gz` passed SHA-256 checks; extracted frozen-source re-analysis
reproduced the stored summary. Archive SHA-256: `e8e19ab299513d5b81c404d2e37fc663797093aaead596ec1cd286e8ff015e0d`.

The archive retains plans, native before/after truth, independent captures,
raw reports, scanner results, resource accounting, cleanup evidence, and
frozen source. No Windows loss/jitter, independently held-out validation,
SACK-disabled native null, or full issue #66 acceptance is claimed.
