# Roadmap

This page is the single status tracker: what the repository implements today, what is open, and the order to do it in. Acceptance criteria live in the linked GitHub issues, not here.

**Status date:** 2026-11-16. **Legend:** Done = implemented in the repository; Partial = useful code exists but the stated capability is incomplete; Planned = no end-to-end implementation yet. Done means the code or workflow exists, not that every target platform has been runtime tested.

| For | Read |
| --- | --- |
| Long-term product and architecture target | [Design brief](architecture/design.md) |
| NEXT GEN feature vision (numbered sections the issues cite) | [NEXT GEN roadmap](NEXT_GEN_ROADMAP.md) |
| HORIZON research plan | [HORIZON roadmap](HORIZON_ROADMAP.md), [implemented behavior](horizon/README.md) |
| Who owns what, adapter contracts and research gates | [NEXT GEN / HORIZON contracts](architecture/next-gen-horizon-contracts.md) |
| How the current code is structured | [Architecture overview](architecture/overview.md) |

## Current baseline

| Area | Status | Implemented now | Main gap |
| --- | --- | --- | --- |
| CLI and configuration | Done | `scan`, `profiles`, `decode`, `sniff`, `history`, `probe`, `evidence`, `serve`, `agent`, `central`, `horizon`, `calibration`, `completion`; one `config.Request` document for YAML, flags and API JSON; profile catalog with `planned` gating; named port sets; `--dry-run` plans; named scans and per-network databases | Policy enforcement beyond profiles (see [untracked items](#not-tracked-by-an-issue-yet)) |
| Portable scans | Partial | TCP connect and UDP socket scans on IPv4/IPv6; privileged ICMP echo, ARP/NDP discovery and raw IPv4/IPv6 SYN with automatic next hops; guarded raw research probes | Privileged live validation on macOS and Windows |
| Packet path | Partial | Shared decoder; bounded asynchronous raw SYN engine; AF_PACKET, BPF and Npcap backends; opt-in Linux AF_XDP copy mode; `nyxr-packetd` privilege split | Live runtime gates, multi-queue RX, measured throughput and drops ([#77](https://github.com/matusso/nyxr/issues/77)) |
| UDP intelligence | Partial | ICMPv4/v6 quote correlation, token matching, late replies, feedback retries; about 40 native probes; runtime-imported Nmap payloads; native QUIC/HTTP/3 and DTLS | Multi-datagram transactions ([#84](https://github.com/matusso/nyxr/issues/84)), multicast discovery ([#91](https://github.com/matusso/nyxr/issues/91)), VPN protocols ([#92](https://github.com/matusso/nyxr/issues/92)), 0-RTT and WebTransport ([#93](https://github.com/matusso/nyxr/issues/93)) |
| Service intelligence | Partial | Adaptive planner and deep-probe queue; Protocol DSL v1/v2; banner, SSH, TLS (SNI, ClientHello profiles, TLS/SSH fingerprints), HTTP, DNS, mail, FTP, Windows, directory, filesystem and database identities; Nmap banner matching and safe NSE bridge | Measured calibration ([#78](https://github.com/matusso/nyxr/issues/78)), efficiency metrics ([#90](https://github.com/matusso/nyxr/issues/90)), unknown-protocol families ([#88](https://github.com/matusso/nyxr/issues/88)) |
| Stack fingerprinting | Partial | Opt-in IPv4/IPv6 SYN option/ECN profiles, native signatures, family hypotheses with separate OS confidence | Kernel and embedded-stack signatures from a measured corpus ([#86](https://github.com/matusso/nyxr/issues/86)) |
| OT and IoT | Partial | `ot-safe` allowlists and caps; read-only Modbus, EtherNet/IP, BACnet, S7 and OPC UA identity probes; multi-signal device records | Live device validation ([#87](https://github.com/matusso/nyxr/issues/87)), further protocols ([#97](https://github.com/matusso/nyxr/issues/97)) |
| Evidence and storage | Partial | `nyxr/v1` records for every scan; pcapng capture and import; SQLite store; claim → exchange → packet traces and probe replay; coverage-aware scan diffs; central PostgreSQL and object storage | Live capture runtime gates |
| Asset identity | Partial | Persistent IDs, strong-key joins, review audit, temporal topology, Kubernetes and AWS/Azure/GCP inventory, cross-controller reconciliation, imported passive sightings | Live passive ingestion ([#98](https://github.com/matusso/nyxr/issues/98)), learned-target verification ([#100](https://github.com/matusso/nyxr/issues/100)) |
| API, web UI and fleet | Partial | REST API with bounded SSE; embedded UI served unprivileged; controller/agent fleet over mTLS gRPC with leases | Scheduling and alerts ([#94](https://github.com/matusso/nyxr/issues/94)), RBAC and audit |
| HORIZON | Partial | Paired experiments, policy DSL, correlation, calibrated hypotheses, adaptive profiles, API/UI ([#61–#73](https://github.com/matusso/nyxr/issues?q=is%3Aissue+HORIZON+is%3Aclosed) closed) | Prior-art decision gate ([#74](https://github.com/matusso/nyxr/issues/74)) |
| Build and release | Done | CI tests/vet, cgo-free builds for linux/windows/darwin on amd64/arm64, GHCR image, Homebrew formula | Runtime smoke tests on all six targets, signed provenance |

Cross-compilation confirms that a binary builds; it does **not** prove that live packet capture, raw sockets or every scan mode works on that operating system. A macOS BPF open/bind/timeout smoke test passed on `en0`; no received or transmitted frames were verified. A privileged Linux namespace run of the IPv6 SYN gate passed on 2026-10-30; macOS BPF and Windows Npcap SYN are unverified live. See [Runtime gates](development/runtime-gates.md). No packet-rate claim is established yet.

## Open work

Sixteen issues are open. They are ordered by what blocks them, not by their original priority label: most P1 issues list [#78](https://github.com/matusso/nyxr/issues/78) as a prerequisite, but #78 waits on a measured corpus, so it is treated as a soft dependency. Scores stay labeled `heuristic` until it lands.

### 1. Housekeeping (no code)

| Issue | State | Action |
| --- | --- | --- |
| [#87](https://github.com/matusso/nyxr/issues/87) S7 and OPC UA | Merged in PR #127; simulators and python-snap7/asyncua only | Stays open for live-device validation; no code work planned |
| [#78](https://github.com/matusso/nyxr/issues/78) Confidence calibration | Evaluator, provenance and `nyxr/calibration/v2` schema done; no measured corpus | Remaining scope is corpus collection and tuning |

### 2. Unblocked, self-contained

| Issue | Scope | Builds on |
| --- | --- | --- |
| [#90](https://github.com/matusso/nyxr/issues/90) Efficiency and intelligence metrics | One scan summary record aggregated from existing counters | Pipeline sinks, planner decisions |
| [#84](https://github.com/matusso/nyxr/issues/84) Multi-datagram UDP and adaptive timing | Bounded multi-reply collection and RTT-derived retry delay | `internal/scan/udp*.go`, `nyxr/udp/v1` |
| [#92](https://github.com/matusso/nyxr/issues/92) UDP protocol gaps | NAT-T and OpenVPN probes; WireGuard and Syslog explicitly inconclusive | `internal/probe/native` |
| [#93](https://github.com/matusso/nyxr/issues/93) QUIC/HTTP/3 capabilities | 0-RTT advertisement, optional WebTransport check, versioned fingerprint | `internal/service/quic.go`, the #85 fingerprint records |

### 3. Discovery and passive chain

| Issue | Scope | Builds on |
| --- | --- | --- |
| [#91](https://github.com/matusso/nyxr/issues/91) Broadcast and multicast UDP | Interface-scoped campaigns with multiple responders | #84 |
| [#98](https://github.com/matusso/nyxr/issues/98) Live passive ingestion | `nyxr listen` feeding the existing pcap importer | `storage.ImportPassiveCapture`, `internal/dissect` |
| [#100](https://github.com/matusso/nyxr/issues/100) Verify learned targets | `scan --learned` intersected with an explicit scope | Passive sightings; usable with imported captures before #98 |
| [#94](https://github.com/matusso/nyxr/issues/94) Scheduled scans and alerts | Persisted schedules in `serve`, diff-driven webhooks | `storage.DiffScans`, named networks, fleet `Submit` |

### 4. Gated on lab data or hardware

| Issue | Gate |
| --- | --- |
| [#78](https://github.com/matusso/nyxr/issues/78) Measured calibration | Registered, labeled, held-out corpus of real services and devices |
| [#86](https://github.com/matusso/nyxr/issues/86) Stack and device signatures | Same corpus, with OS versions and tuned stacks |
| [#77](https://github.com/matusso/nyxr/issues/77) AF_XDP validation | Privileged Linux run of the scripted gate; a multi-queue NIC for RSS |
| [#87](https://github.com/matusso/nyxr/issues/87) S7 and OPC UA live validation | Authorized Siemens CPU and production OPC UA server |

### 5. Breadth, then later

| Issue | Note |
| --- | --- |
| [#97](https://github.com/matusso/nyxr/issues/97) More OT protocols | One sub-issue per protocol, DSL definition plus fixture each |
| [#88](https://github.com/matusso/nyxr/issues/88) Unknown-protocol families | Start with exact-match normalized fingerprints |
| [#96](https://github.com/matusso/nyxr/issues/96) Finding pipeline export (P3) | Export contract first, adapters after |
| [#74](https://github.com/matusso/nyxr/issues/74) HORIZON prior-art gate | Waits on counsel; no repository work |

### Not tracked by an issue yet

- Privileged runtime gates for macOS BPF and Windows Npcap (SYN, capture, UDP ICMP), and capture drops under load.
- Hardware RX queue/socket fanout and end-to-end packet accounting with NIC counters, after measurement.
- UDP confidence and retry calibration under live loss, firewall and ICMP-limit cases (partly [#84](https://github.com/matusso/nyxr/issues/84)).
- Database wire protocols (Oracle TNS, DB2, RethinkDB, Kafka, native ClickHouse, vector stores) and TLS-wrapped database probing.
- Active imported Nmap probes under a rarity/intensity budget; today only the passive NULL-probe banner match runs on TCP.
- Resource-limited WASM plugins; Lua/NSE compatibility only for proven use cases.
- ICMP echo through the API (needs a raw IP socket in the scanning process) and the `research` profile outside the CLI.
- Enterprise hardening: authentication beyond one shared bearer token, RBAC, audit trail, scan approvals, secret handling, signed plugins, metrics/tracing, controller HA, threat models and upgrade/rollback procedures.
- Runtime smoke tests on all six binary targets and signed release provenance.

## Delivered

| Phase | Delivered | Detail |
| --- | --- | --- |
| 0 Test foundation | Unit, loopback and fuzz tests; PCAP fixtures; fake responders; Linux namespace lab; documented macOS/Windows gates | [Testing](development/testing.md) |
| 1 Discovery core | Connect, ICMP, ARP/NDP and raw IPv4/IPv6 SYN with HMAC tokens, sharded decoding and scoped rate limits | [Scanning](guide/scanning.md), [Raw packets](guide/raw-packets.md) |
| 2 UDP engine | Versioned native probes, campaigns, ICMP quote correlation, adaptive retry, explainable `open\|filtered` | [UDP](guide/udp.md) |
| 3 Evidence and services | `nyxr/v1` records on every scan, pcapng evidence, SQLite store, asset identity graph, deep-probe queue, database profile | [Storage and history](guide/storage-and-history.md), [Asset identity](guide/asset-identity.md), [Service identification](guide/service-identification.md) |
| 4 IoT and OT safety | `ot-safe` enforcement; Modbus, BACnet, EtherNet/IP, S7 and OPC UA read-only identity; multi-signal device records | [OT and IoT](guide/ot-and-iot.md) |
| 5 Packet forge | Validated builders, `research` profile, SCTP INIT and IP-protocol scans (fixture-gated; live transmit unverified) | [Research packets](guide/research-packets.md) |
| 6 API and web UI | REST and SSE on the shared request contract, embedded UI, live packet watch and resend, `nyxr-packetd` | [Web UI and API](guide/web-ui-and-api.md) |
| 7 Probe interoperability | Runtime-imported Nmap service probes and UDP payloads, local safe-NSE bridge | [Service identification](guide/service-identification.md) |
| 8 Distributed scanning | Controller/agent job sharding, mTLS identities, leases; central evidence store and reconciliation | [Fleet](guide/fleet.md), [Central](guide/central.md) |
| NEXT GEN | Contracts #75, records #76, DSL v2 #79, temporal topology #80, IPv6 SYN #81, evidence traces #82, cloud inventory #83, TLS/SSH fingerprints #85, S7/OPC UA #87, scan diffs #89, fleet #95, central storage #99 | [Closed issues](https://github.com/matusso/nyxr/issues?q=is%3Aissue+is%3Aclosed) |
| HORIZON | PoC #61–#65, corpus #66, DSL #67, correlation #68, calibrated trials #69–#71, adaptive profiles #72, API/UI #73 | [HORIZON guide](horizon/README.md) |

Phase 9 (enterprise hardening) has not started; its items are listed under [untracked items](#not-tracked-by-an-issue-yet).

## Delivery rules

- Keep fast packet discovery separate from deep service interrogation. Give each RX worker a preallocated `DecodingLayerParser`, fixed worker counts and bounded queues. Do not use `gopacket.PacketSource` there, or add JSON, synchronous disk/database writes or per-target goroutines.
- Give all packet backends the same raw-frame-to-decoder contract. Keep OS-specific code behind build tags and retain TCP connect as the unprivileged fallback.
- Treat no UDP response as `open|filtered`, never as proof of `open`. Keep unknown responses as evidence and show why a confidence value was assigned.
- Make potentially disruptive probes opt-in through explicit profiles and target policies. OT identification defaults to low-rate, read-only behavior.
- Gate each milestone on tests, documentation of privileges and limits, and six-target cross-builds. Raw features additionally need privileged runtime tests on the applicable OS. Record packet rate, drops and allocations before claiming performance improvements.
- Extend the existing scanner, service planner, DSL, evidence and asset store. HORIZON hypotheses never join inventory assets; see the [contracts](architecture/next-gen-horizon-contracts.md).

## Performance decisions

The decoder benchmark is a component measurement, not a scanner throughput result. Optimize in this order: parser reuse and buffer ownership; packet templates; AF_PACKET batching; sharded RX/TX; correlation and queue profiling. The AF_XDP backend exists in copy mode and is opt-in; add per-core ownership, NUMA affinity or zero copy only after an equal-workload benchmark shows the bottleneck ([#77](https://github.com/matusso/nyxr/issues/77)). Publish workload, hardware, packet loss and CPU alongside any packets-per-second number. Recorded results are in [Performance](development/performance.md).
