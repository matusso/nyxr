# Nyxr Protocol DSL

`nyxr/protocol/v1` definitions add stateful, read-only service identification without recompiling Nyxr. The scanner validates each YAML file at the start of a local scan. Definitions are considered alongside built-in probes by the adaptive planner; a port hint raises their priority, and each response updates the next choice. Every exchange, decision, extracted field, and protocol hypothesis is retained in the service observation.

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

Files are limited to 1 MiB, 32 ports, and 32 steps. Per-definition timeouts are capped at 30 seconds and the scan's `--service-timeout` remains the upper bound. Active connection pacing and worker limits are shared with built-in service probes. Version 1 supports TCP and UDP exchanges, STARTTLS over TCP, framing, matching, branching, bounded repetition, and extraction. DTLS, QUIC, inheritance, arithmetic, and cross-target correlation require later schema versions.
