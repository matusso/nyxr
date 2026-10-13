# Native Windows IPv6 clean/block study

The separately registered `horizon-windows-native-clean-block/v1` study planned 12 clean
effect-hypothesis reports and three known firewall DROP reports for IPv6.
All planned outcomes are retained in their own denominator. The protocol was
committed before live traffic; the native helper never changed SACK.

| Stratum | Planned | Valid | Invalid | Missing | Expected outcome | Correct |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| Clean | 12 | 12 | 0 | 0 | SACK difference | 12 |
| Firewall blocked | 3 | 3 | 0 | 0 | Unresolved | 3 |

All 15 ordinary scanner checks matched native truth (12 open, three filtered).
The clean reports emitted 576 HORIZON runner packets / 44,352 bytes and
captured 864 packets / 67,392 bytes independently; their wall time was
27.225–27.232s per run and reply RTT median 1.355–1.424ms. The blocked
reports emitted and captured 72 packets / 5,760 bytes, with 72 expected arm
timeouts and no replies. Across the study, IPv6 connect-scanner captures
retained 87 packets / 7,758 bytes, including kernel handshakes and teardown.
Independent captures reported zero kernel drops, and HORIZON peak source-child
RSS was 29,728–30,400 KiB. Timings and resources describe this source workload,
not calibrated wire latency or a speedup claim.

The clean numerical effect threshold is met
under the recorded finite workload. This is not a controlled native Windows
SACK-disabled null or an IID population accuracy result. The native `SackOpts`
registry value was `absent` at the start and checked around every run.
The blocked rule applied only to the measurement peer on TCP 443; a separate
fixed control connection recorded its presence. Blocked reports are not
reclassified as resolved nulls. Fixture firewall-rule cleanup was verified;
the source temporary IPv6 address was also removed. The operator's read-only
post-exit guest check found the temporary address absent, with IPv6 DHCP and
router discovery enabled, matching the recorded pre-setup interface state.
Its console output is retained in `guest-post-exit-cleanup.txt` and has separate
operator provenance from collector-originated records.

All 15 canonical reports replayed. The 238 raw files in
`raw-corpus.tar.gz` passed SHA-256 checks; extracted frozen-source re-analysis
reproduced the stored summary. Archive SHA-256: `635c1e955b483def8f667ae266e071e3637e73e22b79c817639fd4de835b5fea`.

The archive retains plans, native before/after truth, independent captures,
raw reports, scanner results, resource accounting, cleanup evidence, and
frozen source. No Windows loss/jitter, independently held-out validation,
SACK-disabled native null, or full issue #66 acceptance is claimed.
