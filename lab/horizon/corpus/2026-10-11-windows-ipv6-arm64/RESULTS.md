# Windows IPv6 exploratory live baseline, 2026-10-11

All three planned IPv6 baselines passed on the same operator-owned Windows VM
used for the IPv4 study. Each HORIZON run completed 12 pairs, found the expected
SACK negotiation difference, had no timeouts or capture/backend drops, and
retained every runner transmission in independent capture. The ordinary IPv6
TCP connect scanner reported the listener open in all three runs.

This is exploratory agreement with the registered native Windows SACK
hypothesis. SACK was not independently enabled/disabled, so these runs do not
supply controlled Windows null truth or satisfy issue #66's statistical gate.

## Fixture, registration and cleanup

Windows 11 Pro ARM64 build 26200 under Fusion 26.0.1 used its same native
adapter and TCP listener. Because the virtual segment originally had only
link-local IPv6, the operator started a bounded Mac setup script that assigned
`fd66:66:11::1/64` on `bridge101`. The guest helper assigned
`fd66:66:11::2/64` to the adapter selected by its existing private IPv4 address.
Both addresses were temporary; no default gateway was added. Windows used
ActiveStore and `SkipAsSource`, completed duplicate-address detection, and
restricted its uniquely named inbound allow rule to the exact IPv6 local/peer
addresses and TCP port 443. Native OS/adapter/TCP/firewall/address/route context
was recorded before/after each run and prior to temporary guest address setup.

Supplement `horizon-windows-ipv6-exploratory/v1` and all planned outcomes were
frozen before collector traffic: seeds 66200–66202, three repetitions, 12 pairs,
800ms observation, 300ms washout, 3pps, 48-packet/90s limit per run, alpha 0.05.
The IPv4 registration and archival outcomes remain unchanged. Families and
studies are not pooled to manufacture acceptance.

The helper removed its rule and temporary guest address, restored the recorded
IPv6 DHCP state, and confirmed router discovery remained unchanged. A fixed
cleanup callback over the existing private IPv4 segment supplied native
post-cleanup evidence. The temporary HTTP endpoint then closed. The Mac setup
script removed its alias after collection; an independent interface snapshot
confirmed its absence. The VM remains running for its operator.

## Outcomes and measured baseline

| Run | Complete pairs | Treatment-only SACK | Control-only SACK | p-value | Timeouts | Scanner | Valid baseline |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| 000 | 12 | 12 | 0 | 0.00048828125 | 0 | open | yes |
| 001 | 12 | 12 | 0 | 0.00048828125 | 0 | open | yes |
| 002 | 12 | 12 | 0 | 0.00048828125 | 0 | open | yes |

There were no missing, invalid, unresolved or reverse-direction outcomes and
no quality flags. Hypothesis agreement is 3/3 over all planned runs. Three
repeats on one fixture establish neither independent population accuracy nor
the registered 12-repeat clean-effect acceptance gate. No Windows false-positive
rate can be measured without known null controls.

- HORIZON: 144 runner TX packets / 11,088 bytes; 216 independently captured
  packets / 16,848 bytes across three runs.
- HORIZON wall time 27.231316–27.232681s/run; user CPU 0.240885–0.254965s;
  system CPU 0.463221–0.478500s; peak RSS 30,080–30,352 KiB.
- Reply RTT p50: 1.419, 1.439, 1.453ms; p95: 1.492, 1.527, 1.609ms.
  These are userspace timings over received replies, not calibrated wire latency.
- IPv6 connect scanner: 21 independent packets / 1,866 bytes; wall time
  0.046963–0.049182s/run; user CPU 0.007697–0.008096s; system CPU
  0.007690–0.008806s; peak RSS 28,576–28,864 KiB.

Each scanner capture included its actual outgoing IPv6 SYN, with matching
source/target/port and positive transmission denominator. Capture totals include
the kernel handshake and teardown. The scanner's reported single TX describes
its connect probe, not all kernel wire packets. Raw SYN scanner mode remains
IPv4-only. Resources measure source children, not Windows server CPU/RSS; Darwin
RSS bytes are normalized to KiB. The workloads do not support a speedup claim.

## Archive and verification

`raw-corpus.tar.gz` contains 363 files: the registered study, native telemetry,
cleanup evidence, independent PCAPs, canonical reports, plans, resource/log
records, frozen collector/helper/setup source and a Go source snapshot.
`raw-artifact-hashes.json` covers every raw file; `SHA256SUMS` covers all six
delivery files. Archive size is 536,114 bytes. SHA-256:

`2c77dfa50fa6af57303f0b91c14c41047aa4fa608d16ac478e77bc16ba40f2d5`

The same Darwin ARM64 Go 1.27.2 binary used in the IPv4 study has SHA-256
`951278fab4e04baf80d54cf74fab0cd96b6ae5a2e3b3898f02824f3137d22991`.
Its dirty VCS build metadata is retained. Source preservation is not a claim
of a reproducible clean-commit binary. The executable is not included.

All 363 extracted raw hashes and six delivery checksums passed. All three
canonical reports replayed identically, and frozen-source re-analysis of the
extracted study reproduced the saved summary. Current dual-family analysis
also reproduced both existing IPv4 summaries unchanged. The 17-test offline
suite passed on macOS with two Linux-only tests skipped (15 executed). IPv6
dry-run admission, missing-run denominator retention and denominator-shrink
rejection also passed.

After checksum verification and extraction into a fresh directory, a compatible
Nyxr binary can replay/re-analyze without network access:

```sh
nyxr horizon replay windows-v6-clean-000/horizon/report.json
python3 frozen-source/windows.py analyze --binary /path/to/nyxr --output .
```

Windows controlled SACK nulls, impairment coverage, BSD, independently held-out
fixtures, dependence/stationarity assessment and full confidence/effect samples
remain outstanding. These directly attached ULAs do not validate routed IPv6
or NAT traversal. Existing routes were recorded and temporary setup added its
connected prefix; macOS source kernel RSTs stayed enabled. This is Windows
endpoint coverage, not Windows Nyxr backend validation. Issue #66 remains open.
