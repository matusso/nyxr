# Phase 2 correlation and packet evidence

Issue [#68](https://github.com/matusso/nyxr/issues/68) extends the existing
v1alpha1/v1alpha2 runner. New reports declare `correlationVersion:
tuple-token-v2`; offline replay retains the original rules for older reports.
These changes verify software behavior with fixtures. Live topology and
statistical calibration remain the separate #66/#69 gates.

## Correlation

TCP replies require the fresh ACK token and local destination address/port.
Exact matches also require the target address/port. Supported SYN/ACK and
RST/ACK replies use the shared research decoder, including bounded Ethernet
VLAN and IPv6 extension parsing. IP lengths, IPv4 header checksums, TCP/ICMP
checksums and option lengths are checked; fragments are rejected without
reassembly. Capture offload artifacts can therefore cause missing responses;
use an independent capture to diagnose them rather than treating them as evidence.

IPv4 destination-unreachable, time-exceeded and parameter-problem errors, and
IPv6 errors of types 1–4, require a quoted TCP tuple and sequence token.
Truncated quotes without the full sequence never match. A changed responder
address/port or quoted tuple with the correct token is an `ambiguous-path`
candidate, retained with `ambiguous-correlation`. Neither ICMP nor ambiguous
candidates authorize cleanup or feed SACK inference.

All matched replies are retained within the existing budgets. Exact duplicate
bytes carry `retransmission` and `duplicate-response`; changed TTL, options,
response class or responder carry `path-change`. These flags gate inference.
Late replies encountered during a later trial carry `late-rx` and
`relatedFlowId`, preserving their original flow attribution. Both trials carry
`delayed-response`; late packets never become a later trial's primary features.
Replay rechecks correlation, derived features and required quality flags.

## Clocks and cancellation

Each retained packet records timestamp provenance: clock source, encoding
resolution, precision, queue delay, operation duration and backend drop-counter
snapshot. Current ordinary PacketIO backends use a `userspace/time.Now` timestamp
and nanosecond encoding; precision and backend queue delay are **null** because
those backends do not expose calibrated values. Operation duration measures the
send/receive call, not backend queue delay. An optional `TimestampedReceiver`
interface accepts explicit backend provenance without changing PacketIO.
Clock regression and invalid backend metadata gate inference. The final
`backendDrops` is the per-run counter delta; a counter reset also gates inference.
RTT remains descriptive and includes software/backend delay.

Cancellation stops new transmissions, including cleanup. After an in-flight
receive stops, the runner drains queued replies for at most 20 ms, within the
same receive/frame/capture budgets, using a receive-only context. Drained
packets are late evidence. Transport failure ends reads immediately; any reply
returned with that error is retained first. `cleanup-skipped`, `cleanup-failed`
and `drain-failed` distinguish outcomes. The caller/controller still owns and
closes the transport. Remote SYN state may expire without cleanup.

## Bounded PCAPNG export

```sh
nyxr horizon resolve --experiment lab/horizon/hz-001.yaml \
  --allow-targets 192.0.2.0/24 --allow-ports 443 --simulate sack \
  --output run.json --pcapng run.pcapng --pcapng-max-bytes 1048576 \
  --pcapng-minimize
nyxr horizon replay run.json
nyxr horizon verify-capture run.json run.pcapng
nyxr horizon references run.json
```

The exporter reuses `internal/capture.PCAPNGWriter` and writes one bounded
artifact per run. Both outputs are new mode-0600 files and refuse overwrites.
The cap (256 bytes–8 MiB; default 8 MiB) includes section/interface headers,
packet blocks, padding and options. After the first packet that cannot fit,
remaining packets are omitted and counted. Retention omissions gate inference;
the raw JSON remains available within its independent DSL capture budget.
No background capture, rolling files or unbounded recorder queue is introduced.
Operators control file lifetime and deletion; automatic age-based retention is
outside this per-run export.

Payload minimization keeps Ethernet/IP/TCP headers and ICMP quoted headers and
tokens, removing application bytes and Ethernet padding from the PCAPNG copy.
It preserves original wire lengths and leaves bounded raw JSON evidence intact.
A minimized capture therefore cannot replace raw evidence for checksum replay.

The report includes the capture SHA-256 identity, encoded byte count, cap,
packet/drop counts and minimization policy. Retained evidence points to stable
PCAPNG packet IDs; packet comments carry the sealed report's evidence pointer.
`references` includes artifact/packet references alongside the existing exact
JSON source pointers. Replay reconstructs the expected capture identity and
references; `verify-capture` additionally verifies the actual file bytes.
Export/close failures preserve a partial JSON report without valid capture
references. Hashes detect corruption, not forged reports or signatures.

## Verification

`internal/horizon/testdata/correlation-ipv4.pcapng` and
`correlation-ipv6.pcapng` use documentation addresses and fixed timestamps.
They include malformed/truncated packets, bad checksums, IPv6 extensions and
fragments, ICMP errors and changed responders. `ReplayCaptureFixtures` is
bounded by encoded bytes, block sizes and 4096 records; it never opens a backend.
Regenerate fixtures explicitly with:

```sh
NYXR_UPDATE_FIXTURES=1 go test -run TestPhase2Fixtures ./internal/horizon
make check
go test -race ./internal/horizon/... ./internal/packet ./internal/capture ./cmd/nyxr
```

Regression coverage includes loss, cancellation draining, capture/backend
failures, duplicate caps, delayed attribution, optional timestamp metadata,
private CLI exports, payload minimization, file caps and resealed bad references.
