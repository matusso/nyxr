# Nyxr Protocol DSL

`nyxr/protocol/v1` and `nyxr/protocol/v2` definitions add stateful, read-only service identification without recompiling Nyxr. The scanner validates local YAML files before a scan. Definitions are considered alongside built-in probes by the adaptive planner; a port hint raises their priority, and each response updates the next choice. Every exchange, decision, extracted field, and protocol hypothesis is retained in the service observation. A matched result includes `protocol.schema` and `protocol.definition_sha256` in its attributes. A server registry match also includes `protocol.registry_version`.

```yaml
schema: nyxr/protocol/v1
protocol: postgresql
transport: tcp
ports: [5432]
timeout: 3s
steps:
  - send: {hex: "0000000804d2162f"} # PostgreSQL SSLRequest
  - receive: {max_bytes: 1}
  - expect: {hex: "53"}        # S = SSL accepted
  - start_tls: true             # records TLS parameters and certificates
```

Validate and run it:

```sh
nyxr probe validate postgres.yaml
nyxr scan --profile tcp-common --protocol-definitions postgres.yaml --ports 5432 --json 192.0.2.10
```

`--protocol-definitions` accepts comma-separated files. In a scan configuration file, `protocol_definitions` resolves relative paths from that file's directory. A definition is active only for its listed ports and transport. For UDP-only scans, pass `--service` and `--protocols udp` with at least one UDP definition. Local definitions are unavailable through remote API requests; the `ot-safe` profile rejects them.

## Steps

Each step has exactly one action. `send` accepts one of `text`, `hex`, or `base64` (up to 4096 bytes). `receive` requires `max_bytes` (1–4096); it reads until the limit, EOF, or a short quiet gap. A `length` field can read a framed message exactly, with `offset`, `bytes` (1, 2, or 4), and `order` (`big` or `little`). The field gives the number of bytes **after** the header.

`expect` tests the last received message using one of `hex`, `prefix`, or a Go RE2 `regex`, with an optional byte `offset`. A successful expectation is required before the engine claims an identity. An unmatched expectation stops the definition unless `on_miss` names a later label. `on_match` likewise jumps to a later label. All jumps must move forward, so a definition cannot loop indefinitely.

`extract` maps field names to RE2 expressions applied to the last response. The first capture group is used when present, otherwise the whole match. `start_tls: true` upgrades an existing TCP connection and records the peer certificate and negotiated TLS details. TLS identity is observed without asserting certificate trust.

`set` attaches literal fields after a successful exchange, for example `set: {postgresql.tls_supported: "true"}`. `repeat: {from: request, count: 2}` repeats an earlier labelled block up to four times. The engine also caps total executed steps at 128; a budget overrun fails the definition.

For example, this binary protocol uses a big-endian length and a branch:

```yaml
schema: nyxr/protocol/v1
protocol: example_rpc
transport: tcp
ports: [9001]
steps:
  - send: {hex: "00000001"}
  - receive:
      max_bytes: 512
      length: {offset: 0, bytes: 2, order: big}
  - expect: {hex: "4f4b", offset: 2}
    on_match: identity
  - send: {text: "unused"}
  - label: identity
    extract: {rpc.version: 'OK v([0-9]+)'}
```

Files are limited to 1 MiB, 32 ports, and 32 compiled steps. At most 32 files can be loaded together. Per-definition timeouts are capped at 30 seconds and the scan's `--service-timeout` remains the upper bound. Active connection pacing and worker limits are shared with built-in service probes. Version 1 supports TCP and UDP exchanges, STARTTLS over TCP, framing, matching, branching, bounded repetition, and extraction. Cross-target correlation belongs to the separate HORIZON Experiment DSL.

## Version 2: reuse and bounded arithmetic

Version 2 keeps the v1 steps and adds named parser modules, protocol inheritance, transport actions, and a signed `length.add` adjustment. A module and every protocol that uses it must be listed together. References are **names**, not filesystem paths. The compiler rejects missing references, cycles, duplicate labels, transport changes across inheritance, and expansions beyond 32 steps. A module can compose other modules with `modules`; `extends` names a v2 protocol and inherits its transport, ports, timeout, and steps. Child steps run after inherited steps. Each listed module runs before the document's own steps, in list order. A module must be used by a protocol.

For a frame whose two-byte length includes its own header, use `add: -2`:

```yaml
# frame.yaml
schema: nyxr/protocol/v2
module: frame-read
provenance: Operator-authored synthetic framing example.
steps:
  - receive:
      max_bytes: 64
      length: {offset: 0, bytes: 2, order: big, add: -2}
```

```yaml
# example.yaml
schema: nyxr/protocol/v2
protocol: example
provenance: Operator-authored example; not validated on a live endpoint.
transport: tcp
ports: [9001]
modules: [frame-read]
steps:
  - expect: {prefix: OK, offset: 2}
```

Run `nyxr probe validate frame.yaml example.yaml` before scanning, then pass both paths to `--protocol-definitions`. The signed adjustment must be within −4096..4096. At runtime, the adjusted payload length must fit within `max_bytes` after the header and cannot be negative. A short framed response is an error and cannot establish identity. Version 1 rejects `add`.

Use a `provenance` note (up to 256 bytes) on each v2 definition and module to record its source, owner, and validation status. The note is retained as `protocol.provenance` on a match. `protocol.definition_sha256` hashes the definition and its referenced sources so the exact loaded version can be distinguished across server restarts; it is not a claim of accuracy or trust.

The v2 `tls: true` action must be the first TCP step. It performs a TLS handshake on the connection before subsequent send/receive/expect steps. `start_tls: true` remains available for upgrading an existing plaintext TCP connection. For UDP, a one-step `dtls: true` or `quic: true` definition uses Nyxr's existing native handshake engine, including its structured TLS/certificate or QUIC evidence. These transport-only definitions must be named `dtls` or `quic`; a QUIC handshake that negotiates HTTP/3 keeps the native `http3` service result. The handshake does not establish an arbitrary application identity, and these actions do not expose DTLS application data or QUIC streams to the DSL. Each action uses the tighter of its definition timeout and the service timeout. Certificate identity is recorded without claiming trust.

## Offline fixture runner

`nyxr probe fixtures cases.yaml frame.yaml example.yaml` runs synthetic cases through the normal service planner and executor without opening a network socket. Add `--json` before the positional files for machine-readable results. Each fixture file must declare `schema: nyxr/protocol-fixtures/v1`, a `provenance` note identifying the origin of its bytes, and 1–64 named cases. Each case names its protocol and kind (`positive`, `negative`, `truncated`, or `noisy`), supplies up to 32 request/response hex exchanges, and declares the expected `service`, optional `fields`, `confidence_min`, `confidence_max`, and `error` state. Each exchange is capped at 4096 bytes. The runner reports a failed case with a nonzero exit status. The [sample corpus](../../tests/protocol/demo-fixtures.yaml) is synthetic and is not live protocol validation. Native DTLS/QUIC actions require separate transport integration tests.

## Server registry and reload

An operator can start `NYXR_API_TOKEN=<operator-token> nyxr serve --protocol-registry frame.yaml,example.yaml`. The registry requires a configured API token. The server validates all files before accepting scans. An authenticated `POST /api/v1/protocol-definitions/reload` with body `{}` rereads only those startup-selected paths, validates the complete set, and atomically publishes the next registry version. A failed reload leaves the prior version active. Each scan resolves one version before starting, so a running scan retains its original definitions. Remote scan requests cannot set `protocol_definitions` or a registry path, and a reload request cannot select files. The server applies registry definitions only to enabled service scans and enforces the same transport and `ot-safe` policy as local scans. Registry version numbers are process-local counters; the definition hash identifies source versions across restarts.
