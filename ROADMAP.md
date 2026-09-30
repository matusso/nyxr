# nyxr implementation roadmap

This is the execution plan for the product described in [INSTRUCTIONS.md](INSTRUCTIONS.md). It records what the repository implements today and orders the remaining work into testable releases. `INSTRUCTIONS.md` remains the long-term product and architecture brief; this file is the implementation tracker.

**Status date:** 2026-09-30. **Legend:** Done = implemented in the repository; Partial = useful code exists but the stated capability is incomplete; Planned = no end-to-end implementation yet. A checked item means the code or workflow exists, not that every target platform has been runtime tested.

## Current baseline

| Area | Status | Implemented now | Main gap |
| --- | --- | --- | --- |
| CLI and configuration | Done | `scan`, `profiles`, `decode`, `sniff`, `history`; shared `internal/config` contract (flag/file/profile merge with one validation path); full profile catalog with honest `planned` gating; named port sets (`top100`, `all`); `--dry-run` plan (text/JSON); target/CIDR/range and port parsing; JSON observations; bounded workers | Rate-scheduling hierarchy and target/policy enforcement (tracked in the safety row and Phases 4/9); the API/web consuming the same contract (Phase 6) |
| Portable scans | Partial | TCP connect and UDP socket scans on IPv4/IPv6; privileged IPv4/IPv6 ICMP echo, explicit ARP/NDP discovery and raw IPv4 TCP SYN mode | Other TCP flag modes, IPv6 raw SYN, SCTP and IP protocol scans; privileged live validation |
| Packet path | Partial | Reused `gopacket.DecodingLayerParser` for Ethernet/VLAN IPv4/IPv6 TCP/UDP/ICMP and quoted IPv4 TCP; fixed-worker raw IPv4 TCP SYN scan with checksummed packet templates, token-validated SYN/ACK, RST/ACK and ICMP classification, bounded receive/decode/reply queues; AF_PACKET, BPF and Npcap live Ethernet backends | Privileged Linux and live macOS/Windows runtime gates, automatic neighbor/next-hop discovery, hardware multi-queue RX fanout and measured throughput/drops |
| UDP intelligence | Partial | Raw ICMPv4/v6 quote correlation with socket fallback; DNS A/NS, NTP, SNMP, mDNS, LLMNR, TFTP, SSDP, STUN, SIP OPTIONS and CoAP GET probes; versioned YAML with extraction fields; bounded late-reply matching and feedback-based retries | Privileged live ICMP gates, IKE/IPMI/BACnet safety fixtures and wider calibration |
| Safety and rate control | Partial | Global application-level probe rate, bounded concurrency, enforced read-only TCP-only `ot-safe` profile (rejects UDP/ICMP, custom payloads, unlimited or >5 rate, >4 workers, <3s timeout) | Per-host/subnet/interface limits, adaptive feedback, target allowlists/dry-run policy and research guardrails |
| Evidence and storage | Partial | Versioned `nyxr/v1` record stream (host/port/service/packet-evidence/scan); asynchronous bounded pcapng capture with per-flow packet IDs; pcap and pcapng reading; SQLite store with migrations, assets, evidence bytes, packet index, queries and retention | Live capture runtime gates, plain discovery scans still on the legacy observation stream, PostgreSQL controller backend, object storage for large artifacts |
| Build and release | Done | Tests/vet in CI, cgo-free builds and release archives/checksums for linux/windows/darwin on amd64/arm64, and a Linux amd64/arm64 GHCR image | Runtime smoke tests on all six binary targets and signed release provenance |
| Deep services, UI and agents | Partial | Bounded deep-probe queue fed by discovery: passive banner, SSH, TLS (chain, version, cipher, ALPN, service inside TLS), HTTP and DNS `version.bind`; every exchange kept as evidence; `service`, `deep`, `web` and `full` profiles | SMTP/FTP/SNMP/database/infrastructure probes, API, web UI, scripting and distributed execution |

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
3. **Finish Phase 2 UDP validation.** Run privileged ICMPv4/v6 gates on each platform, then expand the remaining safe protocol slices and tune retry/confidence rules against controlled loss and firewall cases.
4. **Build on the Phase 3 observation/evidence contract.** Route every scan through the record pipeline, run the capture runtime gates, then add service probes in fixture-backed slices.

## Phase 0 — measurable test foundation · Partial

- [x] Unit tests for target/port parsing, packet decoding, pcap reading and native probe validation.
- [x] Loopback TCP/UDP tests, including UDP retry and late-response behavior; decoder allocation benchmark.
- [x] CI test/vet and six-OS/architecture build packaging.
- [x] Add deterministic reusable PCAP fixtures for IPv4/IPv6, TCP/UDP/ICMP, VLANs, malformed/truncated frames and ICMP quotations.
- [x] Add fake UDP and SYN responders with configurable latency, loss, duplicate replies, ICMP rate limits and protocol mismatch.
- [x] Add a privileged Linux network-namespace lab and documented macOS/Windows live RX/TX gates. The Linux lab and Windows gate have not yet run on their target hosts.
- [ ] Record baseline throughput, allocations, CPU, packet loss and NIC drops at fixed workloads; publish the benchmark command and environment with results. Decoder and synthetic scan results are recorded in `tests/performance/README.md`; real NIC drop counters await the privileged Linux lab.
- [x] Fuzz packet decoders, probe definitions/matchers and pcap readers with hostile input; short campaigns run in CI.

**Exit:** CI reproduces classification and regression cases, and performance claims cite measured workloads rather than estimates.

## Phase 1 — high-speed discovery core · Partial

- [x] IPv4/IPv6 target parsing, CIDRs/ranges, TCP connect scanning, IPv4 ICMP echo, global rate limiting, JSON output and bounded workers.
- [x] Reusable Ethernet/IP/TCP/UDP/ICMP decoder and a Linux AF_PACKET packet I/O boundary.
- [x] Shared `internal/config` request contract (`Options` merged from flags/file/profile, resolved and validated once into `Config`) driving the CLI, a full profile catalog with `planned` profiles gated by clear errors, named port sets, and a `--dry-run` plan; the same contract is ready for the Phase 6 API/UI.
- [x] Connect raw RX/TX to the scan engine with fixed TX workers, sharded reusable decoder workers, pooled RX buffers and bounded task/decode/result/reply queues; classify SYN/ACK, RST/ACK, ICMP errors and timeouts with fixture-backed correlation tests.
- [x] Implement IPv4 TCP SYN over the shared packet I/O contract using checksummed packet templates, explicit next-hop MAC, source/interface selection and per-probe HMAC sequence tokens. Reject unrelated and late replies. Linux uses AF_PACKET; the same mode can use BPF/Npcap when available.
- [x] Implement IPv6 ICMP echo, ARP and NDP discovery; add controlled fixtures for fragmented and extension-header traffic. The protocol paths have unit and synthetic frame tests; privileged live gates remain open.
- [x] Add explicit `connect`/`syn` TCP mode selection and capability errors, keeping unprivileged connect as the default.
- [ ] Pass privileged runtime smoke tests for Linux AF_PACKET, macOS BPF and Windows Npcap live backends. BPF/Npcap code and six-target cross-builds exist, but live behavior is unverified.
- [ ] Resolve routes and ARP/NDP neighbors automatically. IPv4 SYN now looks up routes and resolves ARP next hops unless a MAC is supplied; NDP discovery is explicit, while IPv6 raw SYN and automatic NDP next-hop use remain open.
- [ ] Add hardware RX queue/socket fanout after measuring the current single reader and sharded decoder workers.
- [ ] Add per-host/subnet/interface rate limits, backpressure and cancellation; measure actual packets sent rather than counting only scheduled targets. Scoped limits and cancellable waits are implemented; raw-send counts are reported per observation, while end-to-end packet accounting and NIC counters await live lab runs.
- [ ] Add TCP ACK/FIN/NULL/XMAS/custom flags only after the SYN path and safety controls are stable.

**Exit:** Controlled labs prove open/closed/filtered correlation for IPv4 and IPv6, under loss and background traffic; privileged features report clear prerequisites on every supported OS.

## Phase 2 — first-class UDP engine · Partial

- [x] Native YAML probe format with embedded DNS A/NS, NTP and read-only SNMPv2c probes, plus custom ASCII/hex/base64/file payloads.
- [x] Multi-probe campaigns, per-probe timeout/retries, global send pacing, HMAC-derived DNS/NTP/SNMP tokens, late-reply matching and bounded response samples.
- [x] Basic `open`, `closed` (when the OS reports port unreachable) and `open|filtered` observations with reason and confidence.
- [x] Correlate raw ICMPv4/v6 quoted packets to the original UDP probe independent of socket-error behavior, with socket fallback when raw sockets are unavailable. Synthetic quote tests exist; live privileged gates remain.
- [x] Add bounded socket-scoped fallback correlation for protocols without a transaction field; retain unmatched response evidence and test delayed, duplicate and mismatched replies.
- [x] Add a safe fixture-backed group: mDNS/LLMNR, TFTP, SSDP/STUN, SIP OPTIONS and CoAP GET.
- [ ] Add IKE/IPMI/BACnet only after read-only safety review and protocol fixtures; prioritize further probes by demand.
- [x] Use packet-loss/ICMP-limit feedback for one adaptive retry and distinguish token-validated, protocol-shaped, unknown, ICMP and silent results by reason and confidence.
- [ ] Calibrate confidence and retry behavior with privileged live loss, firewall and ICMP-limit cases on Linux, macOS and Windows.
- [x] Add matcher-specific extraction fields and a versioned native probe schema (`nyxr/udp/v1`), accepting schema-less legacy definitions.
- [ ] Consider an imported Nmap probe database only after license review; keep it optional and separate.

**Exit:** UDP results remain explainable under silence, ICMP filtering, delayed replies and protocol mismatch; each new probe has a fixture and safety classification.

## Phase 3 — observations, evidence and service intelligence · Partial

- [x] Define versioned scan/asset/port/service/fingerprint/probe/packet-evidence records, including confidence and unknown-response retention. `internal/observe` defines the `nyxr/v1` records. Service observations carry `fingerprint: matched|unknown` and per-probe evidence (request/response bytes, layer, matcher, error).
- [x] Add asynchronous pcapng capture with result-to-packet references and bounded disk/queue behavior; keep file writes off RX workers. A separate capture handle feeds a bounded reader→writer queue, the file has a size budget, drops are counted, and `packet-evidence` records link target/transport/port to pcapng packet IDs. Live capture on AF_PACKET/BPF/Npcap still needs the privileged runtime gates.
- [x] Add SQLite standalone storage with migrations, retention controls and query tests (cgo-free `modernc.org/sqlite`, `nyxr history`). PostgreSQL stays planned as the controller backend.
- [x] Build a deep-probe queue fed by discovery observations, with per-service timeouts and read-only handshakes. Fixed workers, a bounded queue whose backpressure reaches the discovery consumer rather than packet RX, connection pacing, and per-probe budgets capped by `--service-timeout`.
- [x] Start with generic banners, TLS, HTTP, SSH and DNS. Each has loopback fixtures, and the parsers are fuzzed.
- [ ] Add SMTP/FTP/SNMP and database/infrastructure protocols in fixture-backed slices (the `database` profile stays planned until then).
- [x] Make TLS a shared subsystem for certificates, versions, ALPN and services behind TLS. Preserve unrecognized responses for future signatures. Alternative ClientHello profiles and SNI for hostname targets are not implemented yet.
- [ ] Route plain discovery scans through the record pipeline too, so every scan emits `nyxr/v1` records. Today the pipeline runs only when a service stage, `--pcapng` or `--db` is active.
- [ ] Pass live capture runtime gates on Linux AF_PACKET, macOS BPF and Windows Npcap, and measure capture drops under load.

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
