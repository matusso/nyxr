# Architecture overview

This page describes nyxr as it is built today. The long-term target
architecture and its rationale are in the [Design brief](design.md); delivery
status is in the [Roadmap](../roadmap.md).

## Principles

- **Scan fast first; interrogate intelligently second.** Fast discovery and
  deep service interrogation are separate stages connected by bounded queues.
  A slow service probe can never stall the packet receive path.
- **One request, one result format, every interface.** The CLI, the API and
  the web UI build the same request document, resolve it through the same code,
  and emit the same versioned records.
- **Evidence over inference.** A service or device is claimed only from
  matched responses. Unknown responses are kept, and every result states its
  confidence and reason.
- **Least privilege.** Everything except raw Ethernet I/O runs unprivileged.
- **Safe by default.** Disruptive behavior needs an explicit profile and target
  allowlist.

## Process model

```text
  ┌──────────────┐     ┌───────────────────────────────────────────────┐
  │  nyxr scan   │     │                 nyxr serve                    │
  │    (CLI)     │     │   REST API · SSE events · embedded web UI     │
  └──────┬───────┘     └──────────────────────┬────────────────────────┘
         │      config.Request (YAML / flags / JSON)
         └───────────────────┬────────────────┘
                             ▼
                 config.Resolve: profile defaults,
                 validation, safety policy, plan
                             │
                             ▼
  ┌──────────────────────── pipeline ─────────────────────────────────┐
  │                                                                   │
  │  discovery ──bounded queue──▶ service stage ──▶ device stage      │
  │  (scan)                       (service)          (device)         │
  │     │                                                │            │
  │     └──────────────▶ observe records (nyxr/v1) ◀─────┘            │
  │                           │            │                          │
  │                    printers / SSE   storage (SQLite)              │
  │                                                                   │
  │  capture (pcapng): reader ──bounded queue──▶ writer               │
  └───────────────────────────────────────────────────────────────────┘
                             │ raw Ethernet frames
                             ▼
            packetio: AF_PACKET │ BPF │ Npcap │ nyxr-packetd (Unix socket)
```

Raw Ethernet I/O can run in-process (CLI with privileges) or in
`nyxr-packetd`, a separate privileged relay. `nyxr serve` refuses to run with
raw privileges itself.

## Packages

| Package | Responsibility |
| --- | --- |
| `cmd/nyxr` | CLI entry point, subcommands and shell completion |
| `cmd/nyxr-packetd` | Privileged packet relay entry point |
| `internal/config` | `config.Request`, profile catalog, port sets, target parsing, resolution, validation and dry-run plans |
| `internal/pipeline` | Runs one scan: wires discovery, service, device, capture and sinks through bounded queues |
| `internal/scan` | Discovery engines: TCP connect, raw SYN, UDP, ICMP, ARP/NDP, research probes, rate limiting, route and neighbor resolution |
| `internal/probe` | UDP probe catalog, native YAML definitions, matchers and field extraction; Nmap UDP payload import |
| `internal/service` | Deep-probe stage: banner, SSH, TLS, HTTP, DNS, SOCKS, database, Modbus and EtherNet/IP, with evidence |
| `internal/nmapdb` | Runtime import of user-supplied `nmap-service-probes` files |
| `internal/device` | Device classification from independent signals |
| `internal/observe` | The versioned `nyxr/v1` record types |
| `internal/packet` | Reusable Ethernet/IP decoder, pcap reading, packet forge |
| `internal/packetio` | Live Ethernet backends behind one batch frame interface |
| `internal/packetd` | Privilege-separated relay protocol, server and client |
| `internal/capture` | Asynchronous pcapng evidence writer and pcapng reader |
| `internal/dissect` | Field-by-field packet breakdown with explanations |
| `internal/tui` | Interactive terminal packet browser |
| `internal/storage` | SQLite store: migrations, address inventory, identity graph, observations, evidence, packet index, retention |
| `internal/api` | REST API, SSE event fan-out, embedded web UI |
| `internal/netmon` | OS interface counters for on-the-wire statistics |
| `internal/ui` | Terminal rendering: color, progress bar, summaries |

## Request resolution

Every scan starts as a `config.Request`, whatever the interface:

1. The CLI reads `--config` YAML and overlays flags; the API decodes JSON.
   Unknown fields are rejected in both.
2. `Resolve` applies the profile defaults, then explicit fields.
3. It validates the result once: target and port syntax, profile safety rules
   (`ot-safe`, `research`), privilege needs, and remote restrictions for API
   requests.
4. The resolved configuration is either printed as a plan (`--dry-run`,
   `POST /api/v1/plan`) or handed to `pipeline.FromResolved`.

Because there is one path, a CLI scan and an API scan with the same document
produce the same observations. A test enforces this.

## Discovery engines

| Engine | Mechanism | Privilege |
| --- | --- | --- |
| TCP connect | OS sockets, bounded workers | None |
| UDP | Connected sockets, per-probe tokens, shared raw ICMP listener when permitted | None (raw ICMP optional) |
| ICMP echo | Raw IP sockets | Raw IP |
| Raw SYN | Checksummed templates, one batched TX owner, up to 16,384 outstanding probes, deadline queue, sharded decoder workers | Raw Ethernet |
| ARP / NDP | Raw Ethernet with a separate receive handle | Raw Ethernet |
| Research | Packet forge, one outstanding probe, five frames/s | Raw Ethernet |

## Receive hot path

The raw receive path follows strict rules so that throughput is limited by the
network, not by allocation or blocking:

- Each decoder worker owns a preallocated `gopacket.DecodingLayerParser`; the
  general-purpose `PacketSource` is not used.
- Receive buffers are pooled; no per-packet buffer allocation.
- Fixed worker counts and bounded queues; no per-target goroutines.
- No JSON encoding, disk or database writes on receive workers.
- Replies are correlated by a per-probe HMAC token, so unrelated and late
  packets are rejected cheaply.

Capture follows the same rule: a dedicated reader copies frames into a bounded
queue and a separate writer does the encoding and disk I/O. Overflow is counted
rather than allowed to block.

## Deep path

The service stage is fed by discovery results through a bounded queue served
by a fixed worker pool. When the queue is full, backpressure reaches the
discovery *consumer*, never packet receive. Each probe has a time budget capped
by `--service-timeout`, connections are paced by `--service-rate`, and every
exchange is recorded as evidence.

## Storage

The standalone store is SQLite through a cgo-free driver, so every release
binary can open the same file. The schema is versioned with forward-only
migrations, writes are batched per transaction on the pipeline's consumer, and
evidence bytes live in their own table. A PostgreSQL backend for a distributed
controller is planned.

## API and events

The API serves the same records the CLI prints. Live events use Server-Sent
Events with a 4096-event replay ring per scan and a 256-event queue per
subscriber; slow subscribers are disconnected, never waited on. The web UI is
an embedded, build-free single page that uses only the public API. gRPC is
deferred to the planned controller/agent protocol.
