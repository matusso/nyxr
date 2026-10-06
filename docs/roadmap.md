# Roadmap

This is the execution plan for the product described in the [Design brief](architecture/design.md). It records what the repository implements today and orders the remaining work into testable releases. The design brief remains the long-term product and architecture target; this page is the implementation tracker. For how the current code is structured, see the [Architecture overview](architecture/overview.md).

**Status date:** 2026-10-06. **Legend:** Done = implemented in the repository; Partial = useful code exists but the stated capability is incomplete; Planned = no end-to-end implementation yet. A checked item means the code or workflow exists, not that every target platform has been runtime tested.

## Current baseline

| Area | Status | Implemented now | Main gap |
| --- | --- | --- | --- |
| CLI and configuration | Done | `scan`, `profiles`, `decode` (with an interactive `--tui` packet browser), `sniff`, `history`, `probe import`, `serve`, `completion` for bash/zsh/fish/PowerShell; one `config.Request` document (YAML file plus flags, or API JSON) resolved and validated by one `Resolve` path; full profile catalog with honest `planned` gating; named port sets (`top100`, nmap-ranked `top1000`/`top2000`/`top5000`/`top8387`, `database`, `all`); `--dry-run` plan (text/JSON); target/CIDR/range and port parsing; JSON observations; bounded workers | Rate-scheduling hierarchy and target/policy enforcement (tracked in the safety row and Phases 4/9) |
| Portable scans | Partial | TCP connect and UDP socket scans on IPv4/IPv6; privileged IPv4/IPv6 ICMP echo, explicit ARP/NDP discovery and raw IPv4 TCP SYN mode; guarded raw research TCP/UDP/ICMP/SCTP/IP protocol probes | IPv6 production raw SYN, wider protocol-specific interpretation and privileged live validation |
| Packet path | Partial | Reused `gopacket.DecodingLayerParser` for Ethernet/VLAN IPv4/IPv6 TCP/UDP/ICMP and quoted IPv4 TCP; bounded asynchronous raw IPv4 TCP SYN scan with checksummed packet templates, token-validated SYN/ACK, RST/ACK and ICMP classification, batched sends and deadline expiry; AF_PACKET, BPF and Npcap live Ethernet backends | Privileged Linux and live macOS/Windows runtime gates, hardware multi-queue RX fanout and measured throughput/drops |
| UDP intelligence | Partial | Raw ICMPv4/v6 quote correlation with socket fallback; `udp-basic`/`udp-common`/`udp-full` strategies; DNS, DHCP, NTP, NBNS, mDNS, LLMNR, Kerberos, CLDAP, RADIUS, IKE, L2TP, SNMPv1/v2c/v3, SSDP, SLP, BACnet (with Device property and FDT reads), CoAP, RPC, IPMI, TFTP, SIP, STUN, memcached and game-server probes; runtime-imported Nmap UDP payloads; versioned YAML with extraction fields; bounded late-reply matching and feedback-based retries; native QUIC/HTTP/3 and DTLS handshakes with QUIC transport parameters and connection IDs | Privileged live ICMP gates, 0-RTT capability, verified WebTransport endpoint support, and wider calibration |
| Safety and rate control | Partial | Global and scoped application-level probe rates, bounded concurrency, allowlisted `ot-safe` TCP policy with approved ports and read-only identity probes; allowlisted research profile capped at five frames/s | Live OT device validation and packet-level audit capture privileges |
| Evidence and storage | Partial | Versioned `nyxr/v1` record stream (host/port/service/device/packet-evidence/scan); bounded pcapng capture and pcap/pcapng import; SQLite store with address inventory, local and namespaced asset IDs, validated MAC/SNMP/SMB/SSH/scoped-inventory links, direct Kubernetes API node collection, heuristic identity candidates, membership and review audits, safe hostname/certificate/UPnP clues, passive LLDP/interface/VLAN sightings, device profile claims, evidence bytes, packet index, queries and retention | History before the migration baseline, calibrated confidence, full interface/topology ownership, live passive graph ingestion, direct cloud controller collection, cross-controller reconciliation, live capture runtime gates, plain discovery scans still on the legacy observation stream, PostgreSQL controller backend, object storage for large artifacts |
| Build and release | Done | Tests/vet in CI, cgo-free builds and release archives/checksums for linux/windows/darwin on amd64/arm64, and a Linux amd64/arm64 GHCR image | Runtime smoke tests on all six binary targets and signed release provenance |
| Deep services, UI and agents | Partial | Bounded deep-probe queue fed by discovery: passive banner, SSH, TLS (chain, version, cipher, ALPN, service inside TLS), HTTP, DNS `version.bind`, Modbus and EtherNet/IP identity; SMB (SMB2 negotiate plus anonymous NTLM host/OS/domain identity), RDP (X.224 security negotiation and certificate) and MSRPC endpoint-mapper identification; LDAP rootDSE and Active Directory identification, Kerberos AS-REQ realm discovery, NFS and ONC RPC portmapper enumeration, the Ceph messenger banner and S3-compatible object-storage recognition over HTTP; database profile with common SQL/NoSQL/graph/cache handshakes; runtime-imported `nmap-service-probes` banner matching and a local Nmap bridge for selected safe NSE scripts; every exchange kept as evidence; `tcp-common`, `tcp-full`, `web`, `database`, `deep-scan`, `windows`, `filesystem`, `iot` and `ot-safe` profiles; REST API with bounded SSE events and an embedded web UI served unprivileged (including live packet watching and single-frame resend), with raw I/O in `nyxr-packetd` | SMTP/FTP/SNMP and additional database wire protocols, active imported probes, native scripting and distributed execution |

Cross-compilation confirms that a binary builds; it does **not** prove that live packet capture, raw sockets or every scan mode works on that operating system. A macOS BPF open/bind/timeout smoke test passed on `en0`; no received or transmitted frames were verified. Full BPF and Npcap live runtime gates remain open. Raw SYN supports IPv4 TCP only and resolves next hops with route lookup and ARP; macOS can reuse a valid cached gateway MAC. No packet-rate claim is established yet.

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
- [ ] Record baseline throughput, allocations, CPU, packet loss and NIC drops at fixed workloads; publish the benchmark command and environment with results. Decoder and synthetic scan results are recorded in [Performance](development/performance.md); real NIC drop counters await the privileged Linux lab.
- [x] Fuzz packet decoders, probe definitions/matchers and pcap readers with hostile input; short campaigns run in CI.

**Exit:** CI reproduces classification and regression cases, and performance claims cite measured workloads rather than estimates.

## Phase 1 — high-speed discovery core · Partial

- [x] IPv4/IPv6 target parsing, CIDRs/ranges, TCP connect scanning, IPv4 ICMP echo, global rate limiting, JSON output and bounded workers.
- [x] Reusable Ethernet/IP/TCP/UDP/ICMP decoder and a Linux AF_PACKET packet I/O boundary.
- [x] Shared `internal/config` request contract (`Options` merged from flags/file/profile, resolved and validated once into `Config`) driving the CLI, a full profile catalog with `planned` profiles gated by clear errors, named port sets, and a `--dry-run` plan; the Phase 6 API consumes the same contract as `config.Request`.
- [x] Connect raw RX/TX to the scan engine with one batched TX owner, up to 16,384 outstanding SYN probes, sharded reusable decoder workers, pooled RX buffers and bounded task/decode/reply queues; classify SYN/ACK, RST/ACK, ICMP errors and timeouts with fixture-backed correlation tests.
- [x] Implement IPv4 TCP SYN over the shared packet I/O contract using checksummed packet templates, explicit next-hop MAC, source/interface selection and per-probe HMAC sequence tokens. Reject unrelated and late replies. Linux uses AF_PACKET; the same mode can use BPF/Npcap when available.
- [x] Implement IPv6 ICMP echo, ARP and NDP discovery; add controlled fixtures for fragmented and extension-header traffic. The protocol paths have unit and synthetic frame tests; privileged live gates remain open.
- [x] Add explicit `connect`/`syn` TCP mode selection and capability errors, keeping unprivileged connect as the default.
- [ ] Pass privileged runtime smoke tests for Linux AF_PACKET, macOS BPF and Windows Npcap live backends. BPF/Npcap code and six-target cross-builds exist, but live behavior is unverified.
- [ ] Resolve routes and ARP/NDP neighbors automatically. IPv4 SYN now looks up routes and resolves ARP next hops unless a MAC is supplied; NDP discovery is explicit, while IPv6 raw SYN and automatic NDP next-hop use remain open.
- [ ] Add hardware RX queue/socket fanout after measuring the current single reader and sharded decoder workers.
- [ ] Add per-host/subnet/interface rate limits, backpressure and cancellation; measure actual packets sent rather than counting only scheduled targets. Scoped limits and cancellable waits are implemented; raw-send counts are reported per observation, while end-to-end packet accounting and NIC counters await live lab runs.
- [x] Add TCP ACK/FIN/NULL/XMAS/custom flags only after the SYN path and safety controls are stable. Available in the allowlisted `research` profile only (Phase 5); ordinary profiles reject them.

**Exit:** Controlled labs prove open/closed/filtered correlation for IPv4 and IPv6, under loss and background traffic; privileged features report clear prerequisites on every supported OS.

## Phase 2 — first-class UDP engine · Partial

- [x] Native YAML probe format with embedded DNS A/NS, NTP and read-only SNMPv2c probes, plus custom ASCII/hex/base64/file payloads.
- [x] Multi-probe campaigns, per-probe timeout/retries, global send pacing, HMAC-derived DNS/NTP/SNMP tokens, late-reply matching and bounded response samples.
- [x] Basic `open`, `closed` (when the OS reports port unreachable) and `open|filtered` observations with reason and confidence.
- [x] Correlate raw ICMPv4/v6 quoted packets to the original UDP probe independent of socket-error behavior, with socket fallback when raw sockets are unavailable. Synthetic quote tests exist; live privileged gates remain.
- [x] Add bounded socket-scoped fallback correlation for protocols without a transaction field; retain unmatched response evidence and test delayed, duplicate and mismatched replies.
- [x] Add a safe fixture-backed group: mDNS/LLMNR, TFTP, SSDP/STUN, SIP OPTIONS and CoAP GET.
- [x] Add IKE/IPMI only after read-only safety review and protocol fixtures. Both are classified `safe` and have request/response fixtures. BACnet Who-Is, Device property and FDT reads have simulator fixtures and one live building-controller result; IKE and IPMI still lack live device gates.
- [x] Use packet-loss/ICMP-limit feedback for one adaptive retry and distinguish token-validated, protocol-shaped, unknown, ICMP and silent results by reason and confidence.
- [ ] Calibrate confidence and retry behavior with privileged live loss, firewall and ICMP-limit cases on Linux, macOS and Windows.
- [x] Add matcher-specific extraction fields and a versioned native probe schema (`nyxr/udp/v1`), accepting schema-less legacy definitions.
- [x] Consider an imported Nmap probe database only after license review; keep it optional and separate. `--nmap-udp-probes` loads UDP payloads from an operator-supplied file at runtime; nothing is bundled (see Phase 7).

**Exit:** UDP results remain explainable under silence, ICMP filtering, delayed replies and protocol mismatch; each new probe has a fixture and safety classification.

## Phase 3 — observations, evidence and service intelligence · Partial

- [x] Define versioned scan/asset/port/service/fingerprint/probe/packet-evidence records, including confidence and unknown-response retention. `internal/observe` defines the `nyxr/v1` records. Service observations carry `fingerprint: matched|unknown` and per-probe evidence (request/response bytes, layer, matcher, error).
- [x] Add asynchronous pcapng capture with result-to-packet references and bounded disk/queue behavior; keep file writes off RX workers. A separate capture handle feeds a bounded reader→writer queue, the file has a size budget, drops are counted, and `packet-evidence` records link target/transport/port to pcapng packet IDs. Live capture on AF_PACKET/BPF/Npcap still needs the privileged runtime gates.
- [x] Add SQLite standalone storage with migrations, retention controls and query tests (cgo-free `modernc.org/sqlite`, `nyxr history`). PostgreSQL stays planned as the controller backend.
- [x] Add the first asset identity graph layer: persistent database-local IDs, validated MAC/SNMP engine ID/SMB GUID correlation, source-signal provenance, historical database backfill, CLI/API/UI reads and retention cleanup.
- [x] Add heuristic identity confidence and competing candidates, a durable membership event log from migration onward, and a manual review/override audit.
- [x] Add verified SSH host keys, scoped inventory identifiers, safe hostname/certificate/UPnP relationships, and imported passive LLDP/interface/VLAN observations.
- [x] Collect Kubernetes node UIDs and internal/external IP addresses from a verified HTTPS API with an explicit cluster scope.
- [ ] Complete pre-migration ownership history where source data permits, calibrated confidence, direct cloud collection and cross-controller reconciliation, live passive ingestion, and full interface/topology ownership. See the [next-generation asset roadmap](NYXR_NEXT_GEN_ROADMAP.md#3-asset-identity-graph).
- [x] Build a deep-probe queue fed by discovery observations, with per-service timeouts and read-only handshakes. Fixed workers, a bounded queue whose backpressure reaches the discovery consumer rather than packet RX, connection pacing, and per-probe budgets capped by `--service-timeout`.
- [x] Start with generic banners, TLS, HTTP, SSH and DNS. Each has loopback fixtures, and the parsers are fuzzed.
- [x] Add the `database` profile with a broad TCP port set and response-validated Redis, Memcached, PostgreSQL, MongoDB, Bolt, CQL, TDS, MySQL and selected HTTP database identities.
- [ ] Expand database wire protocol coverage (Oracle TNS, DB2, RethinkDB, Kafka, native ClickHouse, vector protocols), TLS-wrapped database probing, and fixture-backed live compatibility; add SMTP/FTP/SNMP.
- [x] Make TLS a shared subsystem for certificates, versions, ALPN and services behind TLS. Preserve unrecognized responses for future signatures. Alternative ClientHello profiles and SNI for hostname targets are not implemented yet.
- [x] Explain captures offline: `nyxr decode` summarizes pcap/pcapng files into hosts and open/closed/filtered ports, and `--tui` browses every packet with field-level notes and a linked hex dump (`internal/dissect`, `internal/tui`).
- [ ] Route plain discovery scans through the record pipeline too, so every scan emits `nyxr/v1` records. Today the pipeline runs only when a service stage, `--pcapng` or `--db` is active.
- [ ] Pass live capture runtime gates on Linux AF_PACKET, macOS BPF and Windows Npcap, and measure capture drops under load.

**Exit:** One scan can discover, interrogate, store and explain a service without blocking the fast receive path. Each claimed service/version has supporting evidence.

## Phase 4 — IoT and OT safety · Partial

- [x] Enforce `ot-safe` target allowlists, approved TCP ports and identity probes, rate/concurrency/timeout caps, and a dry-run plan. Run discovery and service stages sequentially to preserve the rate cap.
- [x] Add read-only Modbus function 43/14, BACnet unicast Who-Is and EtherNet/IP ListIdentity probes with simulator tests and recorded exchanges. BACnet is available through an explicit UDP scan; `ot-safe` remains TCP-only.
- [x] Emit device records from at least two independent service, UDP, MAC OUI or port signals with explainable confidence. OUI prefixes are evidence rather than vendor names.

Live tests on representative OT equipment, a vendor OUI database, and a fuller set of industrial protocols from the [Design brief](architecture/design.md#11-otics-safety-profile) remain open. Packet-level auditing still requires `--pcapng` and capture privileges.

**Exit:** OT scans can be audited for every transmitted probe, and device claims point to multiple independent observations.

## Phase 5 — packet forge and protocol breadth · Done (fixture-gated)

- [x] Add validated builders/templates for Ethernet/VLAN, IPv4/IPv6, TCP, UDP, ICMP and SCTP with explicit checksum and fragmentation controls.
- [x] Put malformed packets, arbitrary TCP flags and fragmentation experiments behind a `research` profile and explicit target allowlist, with one outstanding probe and a five-frame/s cap.
- [x] Add SCTP INIT and raw IP-protocol scans, bounded IPv6 extension parsing, and fixture-backed correlation for direct replies and ICMP quotes.

The raw research path is fixture-tested and cross-buildable; privileged live
transmit/receive behavior remains unverified on Linux, macOS and Windows.
IPv6 research requires an operator-supplied next-hop MAC until automatic NDP
routing is implemented. The CLI exposes a conservative subset of the builder's
header controls; advanced VLAN, options and extension layouts remain internal.

**Exit:** Generated packets round-trip through fixtures and the receive decoder; unsafe overrides cannot be sent by ordinary profiles.

## Phase 6 — API and web UI · Partial

- [x] Expose the same validated scan configuration and observation schema through REST; add live progress/events with bounded streams. `config.Request` is the one document for YAML, flags and API JSON; `pipeline.FromResolved` maps it to stages for both. Events are Server-Sent Events with a 4096-event replay ring, 256-event subscriber queues and `Last-Event-ID` resume; slow clients are disconnected, never waited on. gRPC is deferred to the Phase 8 controller/agent protocol, which needs it; SSE covers one-way browser streaming without a WebSocket dependency.
- [x] Build scan creation/history, assets/services, packet evidence and profiles in the web UI from those APIs. It is an embedded, build-free UI (`nyxr serve`) with dry-run plans, live results, cancel and pcapng download.
- [x] Add live packet watching and single-frame clone/edit/resend to the web UI through packetd, with bounded browser buffers and an explicit `--allow-packet-send` opt-in.
- [x] Split privileged packet I/O into a narrow `nyxr-packetd` process before running API/UI/storage alongside raw scanning. It is a separate binary that relays Ethernet frames over a Unix socket for allowlisted interfaces, with a source-MAC check, frame, client and rate limits. `nyxr serve` refuses root or `CAP_NET_RAW`/`CAP_NET_ADMIN` by default, and `nyxr scan --packetd` uses the same relay.

A test runs one loopback TCP and service scan through the CLI and the API and requires identical observations apart from IDs and timings. The UI was checked in headless Chromium against a live server. Open items: ICMP echo still needs a raw IP socket in the scanning process, so the API refuses ICMP. The `research` profile stays CLI-only until Phase 9 approvals. packetd has been exercised on macOS, matching the local BPF backend whose live RX/TX gate is open, but not yet on privileged Linux or Windows. Authentication is a single shared bearer token; RBAC and audit are Phase 9.

**Exit:** A CLI and web scan with equivalent configuration produce equivalent observations; the web/API process has no raw-socket privilege.

## Phase 7 — scripting and probe interoperability · Partial

- [x] Import user-supplied Nmap service probes into the match model; preserve provenance and license boundaries. `internal/nmapdb` parses an operator-supplied `nmap-service-probes` file at runtime (never bundled), records its path and SHA-256, and compiles match/softmatch patterns with Go's RE2. Patterns RE2 cannot express (backreferences, lookaround) are skipped and counted rather than failing the import. `nyxr probe import` summarizes a database and prints the Nmap Project license notice. The service engine's `nmap` probe matches a connect banner against the NULL-probe rules and emits service/product/version with provenance, sending no extra traffic. Fixtures, a fuzz target and CLI/config/pipeline tests cover the path.
- [ ] Send the imported active probes (GetRequest and friends) under a rarity/intensity budget and per-port cap; today only the passive NULL-probe banner match is wired into TCP scanning. Imported UDP payloads are sent through `--nmap-udp-probes`.
- [x] Add a local Nmap/NSE bridge for selected installed scripts with structured XML output and category safety checks. It runs named scripts on discovered open TCP/UDP ports, requires `safe`, excludes high-risk categories, and bounds each host execution. Lua/NSE execution inside nyxr remains future work.
- [ ] Add resource-limited WASM plugins, then Lua/NSE compatibility only for proven use cases.

**Exit:** Scripts have bounded time/memory/network access, a versioned API and reproducible fixture tests. Imported Nmap data stays runtime-loaded with recorded provenance and never ships inside a nyxr binary.

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
