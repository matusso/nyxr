# Windows IPv4 exploratory live baseline, 2026-10-11

Three repeated Windows IPv4 baselines passed independent capture and canonical
replay verification. Three earlier runs remain invalid as full baselines because
their short scanner captures were empty. All six HORIZON reports completed and
replayed identically. Neither study satisfies issue #66's full platform or
statistical acceptance gate.

## Fixture and registered scope

The operator-owned Fusion `win11` VM ran Windows 11 Pro ARM64 build 26200 under
Fusion 26.0.1. The macOS ARM64 source used `bridge101`, source 192.168.254.1,
target 192.168.254.130 and explicitly verified target MAC 00:0c:29:7d:91:cb.
The native PowerShell helper bound TCP 443 and created one temporary inbound
allow rule restricted to those local/peer addresses and that port. Native OS,
adapter, addresses, routes, TCP settings and firewall scope were recorded
before/after every run. The helper supports only fixed telemetry/stop messages.
Both helpers exited and both uniquely named rules were verified absent.

Each separate study froze `horizon-windows-ipv4-exploratory/v1` and its three
planned runs before measurement: seeds 66100–66102; 12 pairs; 800ms observation;
300ms washout; 3 packets/s; 48-packet and 90s limits per run. Native Windows SACK
support was a hypothesis, not independently toggled ground truth. There was no
known Windows null control. The failed initial study is not pooled with the
repeat to improve agreement or confidence.

## Outcomes and retained negative result

| Study | Planned/completed HZ | Valid full baselines | SACK differences | Unresolved HZ | Scanner open reports | Invalid captures |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `initial-buffered` | 3/3 | 0/3 | 3 | 0 | 3/3 | 3 |
| `repeat-immediate` | 3/3 | 3/3 | 3 | 0 | 3/3 | 0 |

Every HORIZON report had 12 complete pairs, 12 treatment-only replies and zero
control-only replies, timeouts, quality flags or backend drops; p=0.00048828125.
Every runner transmission was present in the independent HORIZON PCAPs.
Agreement describes this fixture's registered SACK hypothesis, not OS inference
accuracy or a population estimate.

The initial scanner logs reported zero kernel drops, yet all three PCAPs had
zero packets: short captures stopped before buffered packets reached the file.
The collector was corrected to request immediate capture and analysis now
requires captured SYN transmissions matching the scanner's positive TX
denominator. Zero drops alone cannot validate an empty capture. The corrected
analysis marks all three initial full baselines invalid and retains their
reports, logs, resource records and failed denominator. The repeat retained
two scanner packets (112 bytes) per run, including every scanner SYN.

Native Windows CIM telemetry also exposed scalar/array and numeric-enumeration
serialization differences. Fixture validation now accepts the actual narrow
representations while still rejecting broader address/port firewall scopes.
The listener preflight is retained as setup context, not an additional run.

## Repeat measurement baseline

- HORIZON: 144 runner TX packets / 8,208 bytes across three runs; 231 independently
  captured packets / 13,386 bytes, including endpoint and macOS kernel traffic.
- HORIZON wall time: 27.228882–27.231782s/run; user CPU 0.215694–0.239244s;
  system CPU 0.440968–0.471166s; peak RSS 30,000–30,464 KiB.
- Reply RTT p50 per run: 1.383, 1.400, 1.433ms; p95: 1.513, 1.636, 1.549ms.
  These are userspace timings over received replies, not calibrated wire latency.
- One-port SYN scanner: three open results; six captured packets / 336 bytes;
  wall time 0.357548–0.360855s/run; user CPU 0.012818–0.016442s;
  system CPU 0.021814–0.024710s; peak RSS 30,256–35,840 KiB.

RSS is normalized from Darwin bytes to KiB. Resources measure the macOS child
processes, not Windows server CPU/RSS. The scanner discovers one port while
HORIZON measures 12 paired comparisons; these timings establish no speedup.

## Archive and offline verification

`raw-corpus.tar.gz` contains 415 raw files: both separate studies, frozen
collector/helper/protocol files, telemetry, plans, independent PCAPs, canonical
reports, logs, resources, preflight, verification record and a Go source
snapshot. `raw-artifact-hashes.json` covers every raw file; `SHA256SUMS` covers
the delivery files. Archive size: 593,490 bytes. SHA-256:

`369bcf2aee4e5acaacd1ff4e322a2e9a78f9d0c0cfd9ee65a413e3e123b6e2d7`

The measured Darwin ARM64 binary used Go 1.27.2 and SHA-256
`951278fab4e04baf80d54cf74fab0cd96b6ae5a2e3b3898f02824f3137d22991`.
Its build info records a dirty VCS tree. `cmd/`, `internal/`, `go.mod` and
`go.sum` were copied at archival; this is source preservation, not a claim of a
reproducible clean-commit build. The binary itself is not included.

Verify delivery checksums, extract into a fresh directory, then verify each
raw-file hash. With a compatible Nyxr binary, replay any saved envelope:

```sh
nyxr horizon replay initial-buffered/windows-v4-clean-000/horizon/report.json
python3 repeat-immediate/frozen-source/windows.py analyze --binary /path/to/nyxr \
  --output initial-buffered
python3 repeat-immediate/frozen-source/windows.py analyze --binary /path/to/nyxr \
  --output repeat-immediate
```

Use the **corrected repeat collector** for both analyses. The initial frozen
collector documents what ran and predates the scanner-capture guard. All six
archived reports were replayed identically; corrected analysis of extracted
studies reproduced both stored summaries. All 415 raw hashes and six delivery
hashes passed. The 15-test offline suite passed on macOS with two Linux-only
tests skipped (13 executed); the earlier 10-test Linux run is recorded in the
Linux corpus. Docker was stopped during the additional suite rerun.

## Remaining gates

Windows IPv6, controlled Windows SACK nulls, impairments, BSD, independently
held-out fixtures and the full registered confidence/effect samples remain
outstanding. Three repeated observations on one Windows fixture establish no
independence/stationarity or population false-positive bound. Existing guest
routes were recorded without modification; direct virtual Ethernet probes on
the Fusion NAT segment do not measure NAT traversal or imply disconnection.
macOS kernel RSTs remained enabled, unlike the Linux source's suppressed RSTs.
This is a Windows endpoint fixture, not Windows Nyxr backend validation.
Issue #66 remains open.
