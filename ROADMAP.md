# nyxr implementation roadmap

This is the execution plan for the product described in [INSTRUCTIONS.md](INSTRUCTIONS.md). It records what the repository implements today and orders the remaining work into testable releases. `INSTRUCTIONS.md` remains the long-term product and architecture brief; this file is the implementation tracker.

**Status date:** 2026-09-30. **Legend:** Done = implemented in the repository; Partial = useful code exists but the stated capability is incomplete; Planned = no end-to-end implementation yet. A checked item means the code or workflow exists, not that every target platform has been runtime tested.

## Current baseline

| Area | Status | Implemented now | Main gap |
| --- | --- | --- | --- |
| CLI and configuration | Done | `scan`, `profiles`, `decode`, `sniff`; shared `internal/config` contract (flag/file/profile merge with one validation path); full profile catalog with honest `planned` gating; named port sets (`top100`, `all`); `--dry-run` plan (text/JSON); target/CIDR/range and port parsing; JSON observations; bounded workers | Rate-scheduling hierarchy and target/policy enforcement (tracked in the safety row and Phases 4/9); the API/web consuming the same contract (Phase 6) |
| Portable scans | Partial | TCP connect and UDP socket scans on IPv4/IPv6; privileged IPv4 ICMP echo; explicit raw IPv4 TCP SYN mode | Other TCP flag modes, IPv6 raw SYN/ICMP echo, ARP/NDP, SCTP and IP protocol scans |
| Packet path | Partial | Reused `gopacket.DecodingLayerParser` for Ethernet/VLAN IPv4/IPv6 TCP/UDP/ICMP and quoted IPv4 TCP; fixed-worker raw IPv4 TCP SYN scan with checksummed packet templates, token-validated SYN/ACK, RST/ACK and ICMP classification, bounded receive/decode/reply queues; AF_PACKET, BPF and Npcap live Ethernet backends | Privileged Linux and live macOS/Windows runtime gates, automatic neighbor/next-hop discovery, hardware multi-queue RX fanout and measured throughput/drops |
| UDP intelligence | Partial | Embedded native DNS A/NS, NTP and SNMPv2c GET probes; custom YAML/binary payloads; token checks, bounded late-reply matching, retries, confidence and response samples | Raw ICMP correlation, adaptive retries, broader protocol coverage and calibrated confidence |
| Safety and rate control | Partial | Global application-level probe rate, bounded concurrency, enforced read-only TCP-only `ot-safe` profile (rejects UDP/ICMP, custom payloads, unlimited or >5 rate, >4 workers, <3s timeout) | Per-host/subnet/interface limits, adaptive feedback, target allowlists/dry-run policy and research guardrails |
| Evidence and storage | Partial | Observation JSON, classic Ethernet pcap *reading*, limited UDP response hex | Asynchronous pcapng writing, packet-to-observation links, durable asset database |
| Build and release | Done | Tests/vet in CI, cgo-free builds and release archives/checksums for linux/windows/darwin on amd64/arm64, and a Linux amd64/arm64 GHCR image | Runtime smoke tests on all six binary targets and signed release provenance |
| Deep services, UI and agents | Planned | Architectural intent in `INSTRUCTIONS.md` | Protocol probes, API, web UI, scripting and distributed execution |

Cross-compilation confirms that a binary builds; it does **not** prove that live packet capture, raw sockets or every scan mode works on that operating system. A macOS BPF open/bind/timeout smoke test passed on `en0`; no received or transmitted frames were verified. Full BPF and Npcap live runtime gates remain open. Raw SYN currently requires an operator-supplied next-hop MAC and supports IPv4 TCP only. No packet-rate claim is established yet.

## Delivery rules

- Keep fast packet discovery separate from deep service interrogation. When the raw scan engine is connected, give each RX worker a preallocated `DecodingLayerParser`, fixed worker counts and bounded queues. Do not use `gopacket.PacketSource` there, or add JSON, synchronous disk/database writes or per-target goroutines.
- Give all packet backends the same raw-frame-to-decoder contract. Keep OS-specific code behind build tags and retain TCP connect as the unprivileged fallback.
- Treat no UDP response as `open|filtered`, never as proof of `open`. Keep unknown responses as evidence and show why a confidence value was assigned.
- Make potentially disruptive probes opt-in through explicit profiles and target policies. OT identification defaults to low-rate, read-only behavior.
- Gate each milestone on tests, documentation of privileges and limits, and six-target cross-builds. Raw features additionally need privileged runtime tests on the applicable OS. Record packet rate, drops and allocations before claiming performance improvements.

## Next delivery order

1. **Finish Phase 0 measurement and lab fixtures.** Establish reproducible packet and network behavior before tuning or adding more raw modes.
2. **Finish the Phase 1 packet discovery path.** Run privileged AF_PACKET, BPF and Npcap smoke tests; add automatic neighbor/route resolution and multi-queue RX sharding, then fill IPv6 ICMP and neighbor discovery gaps. Keep connect as the default until live raw backends pass runtime tests.
3. **Finish Phase 2 UDP classification.** Correlate raw ICMP errors with probes, expand safe native probes, and tune retry/confidence rules against controlled loss and firewall cases.
4. **Introduce the observation/evidence contract before broad fingerprinting.** This gives deep probes, storage, API and UI one stable result shape.

## Phase 0 — measurable test foundation · Partial

- [x] Unit tests for target/port parsing, packet decoding, pcap reading and native probe validation.
- [x] Loopback TCP/UDP tests, including UDP retry and late-response behavior; decoder allocation benchmark.
- [x] CI test/vet and six-OS/architecture build packaging.
- [ ] Add reusable PCAP fixtures for IPv4/IPv6, TCP/UDP/ICMP, VLANs, malformed/truncated frames and ICMP quotations.
- [ ] Add fake responders with configurable latency, loss, duplicate replies, ICMP rate limits and protocol mismatch.
- [ ] Add a privileged Linux network-namespace lab and repeatable macOS/Windows runtime smoke jobs or documented manual gates.
- [ ] Record baseline throughput, allocations, CPU, packet loss and NIC drops at fixed workloads; publish the benchmark command and environment with results.
- [ ] Fuzz packet decoders, probe definitions/matchers and pcap readers with hostile input.

**Exit:** CI reproduces classification and regression cases, and performance claims cite measured workloads rather than estimates.

## Phase 1 — high-speed discovery core · Partial

- [x] IPv4/IPv6 target parsing, CIDRs/ranges, TCP connect scanning, IPv4 ICMP echo, global rate limiting, JSON output and bounded workers.
- [x] Reusable Ethernet/IP/TCP/UDP/ICMP decoder and a Linux AF_PACKET packet I/O boundary.
- [x] Shared `internal/config` request contract (`Options` merged from flags/file/profile, resolved and validated once into `Config`) driving the CLI, a full profile catalog with `planned` profiles gated by clear errors, named port sets, and a `--dry-run` plan; the same contract is ready for the Phase 6 API/UI.
- [x] Connect raw RX/TX to the scan engine with fixed TX workers, sharded reusable decoder workers, pooled RX buffers and bounded task/decode/result/reply queues; classify SYN/ACK, RST/ACK, ICMP errors and timeouts with fixture-backed correlation tests.
- [x] Implement IPv4 TCP SYN over the shared packet I/O contract using checksummed packet templates, explicit next-hop MAC, source/interface selection and per-probe HMAC sequence tokens. Reject unrelated and late replies. Linux uses AF_PACKET; the same mode can use BPF/Npcap when available.
- [ ] Implement IPv6 ICMP echo, ARP and NDP discovery; add controlled fixtures for fragmented and extension-header traffic.
- [x] Add explicit `connect`/`syn` TCP mode selection and capability errors, keeping unprivileged connect as the default.
- [ ] Pass privileged runtime smoke tests for Linux AF_PACKET, macOS BPF and Windows Npcap live backends. BPF/Npcap code and six-target cross-builds exist, but live behavior is unverified.
- [ ] Resolve routes and ARP/NDP neighbors automatically; current SYN mode requires the correct next-hop MAC from the operator.
- [ ] Add hardware RX queue/socket fanout after measuring the current single reader and sharded decoder workers.
- [ ] Add per-host/subnet/interface rate limits, backpressure and cancellation; measure actual packets sent rather than counting only scheduled targets.
- [ ] Add TCP ACK/FIN/NULL/XMAS/custom flags only after the SYN path and safety controls are stable.

**Exit:** Controlled labs prove open/closed/filtered correlation for IPv4 and IPv6, under loss and background traffic; privileged features report clear prerequisites on every supported OS.

## Phase 2 — first-class UDP engine · Partial

- [x] Native YAML probe format with embedded DNS A/NS, NTP and read-only SNMPv2c probes, plus custom ASCII/hex/base64/file payloads.
- [x] Multi-probe campaigns, per-probe timeout/retries, global send pacing, HMAC-derived DNS/NTP/SNMP tokens, late-reply matching and bounded response samples.
- [x] Basic `open`, `closed` (when the OS reports port unreachable) and `open|filtered` observations with reason and confidence.
- [ ] Correlate raw ICMPv4/v6 quoted packets to the original UDP probe independent of socket-error behavior.
- [ ] Add bounded fallback correlation for protocols without a usable transaction field; test delayed, duplicate and cross-probe responses.
- [ ] Add safe probes and matchers in small tested groups: mDNS/LLMNR, TFTP, SSDP/STUN, SIP/IKE/IPMI, CoAP/BACnet and other entries prioritized by demand.
- [ ] Use packet-loss/ICMP-limit feedback for adaptive retries and calibrate confidence against known open/closed/filtered fixtures.
- [ ] Add extraction fields and a versioned native probe schema; make imported Nmap probes a separate optional database after license review.

**Exit:** UDP results remain explainable under silence, ICMP filtering, delayed replies and protocol mismatch; each new probe has a fixture and safety classification.

## Phase 3 — observations, evidence and service intelligence · Planned

- [ ] Define versioned scan/asset/port/service/fingerprint/probe/packet-evidence records, including confidence and unknown-response retention.
- [ ] Add asynchronous pcapng capture with result-to-packet references and bounded disk/queue behavior; keep file writes off RX workers.
- [ ] Add SQLite standalone storage with migrations, retention controls and query tests; keep PostgreSQL as the controller backend when needed.
- [ ] Build a deep-probe queue fed by discovery observations, with per-service timeouts and read-only handshakes.
- [ ] Start with generic banners, TLS, HTTP, SSH and DNS; then add SMTP/FTP/SNMP and database/infrastructure protocols in fixture-backed slices.
- [ ] Make TLS a shared subsystem for certificates, versions, ALPN and services behind TLS. Preserve unrecognized responses for future signatures.

**Exit:** One scan can discover, interrogate, store and explain a service without blocking the fast receive path. Each claimed service/version has supporting evidence.

## Phase 4 — IoT and OT safety · Planned

- [ ] Turn `ot-safe` into an enforced policy for packet rate, permitted probe list, timeouts and read-only operations; add target allowlists and dry-run plans.
- [ ] Add read-only Modbus, BACnet and EtherNet/IP identity probes first, then other OT protocols with simulator tests and explicit safety review.
- [ ] Combine OUI, mDNS/SSDP, banners, TLS, SNMP and port patterns into device fingerprints with explainable confidence.

**Exit:** OT scans can be audited for every transmitted probe, and device claims point to multiple independent observations.

## Phase 5 — packet forge and protocol breadth · Planned

- [ ] Add validated builders/templates for Ethernet, IP, TCP, UDP and ICMP with explicit checksum and fragmentation controls.
- [ ] Put malformed packets, arbitrary flags and fragmentation experiments behind a `research` profile and target policy.
- [ ] Add SCTP, IP-protocol scans and IPv6 extension handling only with parser, correlation and safety fixtures.

**Exit:** Generated packets round-trip through fixtures and the receive decoder; unsafe overrides cannot be sent by ordinary profiles.

## Phase 6 — API and web UI · Planned

- [ ] Expose the same validated scan configuration and observation schema through REST/gRPC; add live progress/events with bounded streams.
- [ ] Build scan creation/history, assets/services, packet evidence and profiles in the web UI from those APIs.
- [ ] Split privileged packet I/O into a narrow `packetd` process before running API/UI/storage alongside raw scanning.

**Exit:** A CLI and web scan with equivalent configuration produce equivalent observations; the web/API process has no raw-socket privilege.

## Phase 7 — scripting and probe interoperability · Planned

- [ ] Import user-supplied Nmap service probes into the native schema; preserve provenance and license boundaries.
- [ ] Add an Nmap/NSE bridge for selected scripts with structured output and category safety checks.
- [ ] Add resource-limited WASM plugins, then Lua/NSE compatibility only for proven use cases.

**Exit:** Scripts have bounded time/memory/network access, a versioned API and reproducible fixture tests.

## Phase 8 — distributed scanning · Planned

- [ ] Add controller/agent job sharding by target × port × protocol, mTLS identities, leases, retries and deduplicated observations.
- [ ] Add agent health, local rate policy enforcement and remote evidence transfer with backpressure.

**Exit:** A lost agent can resume/reassign a job without duplicate or missing final observations.

## Phase 9 — enterprise hardening · Planned

- [ ] Add authentication, RBAC, audit trail, scan approvals, allowlists and enforced rate policies.
- [ ] Add secret handling, signed plugins, observability metrics/tracing and controller HA where demand justifies it.
- [ ] Validate security and operational behavior with threat models, failure tests and upgrade/rollback procedures.

**Exit:** Privilege boundaries, policy enforcement and audit records are independently testable; operations can recover from agent and controller failure.

## Performance decisions

The decoder benchmark is a component measurement, not a scanner throughput result. Optimize in this order: parser reuse and buffer ownership; packet templates; AF_PACKET batching; sharded RX/TX; correlation and queue profiling. Evaluate AF_XDP/PF_RING only if measured AF_PACKET results show a bottleneck that these steps cannot remove. Publish workload, hardware, packet loss and CPU alongside any packets-per-second number.
