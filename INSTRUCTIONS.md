# Network / Port Security Scanner Roadmap

## 1. Product architecture

The goal is not to build “Nmap rewritten in Go.” The scanner should be a modern scanning platform with Masscan/ZMap-class discovery speed, Nmap-class protocol intelligence, much stronger UDP scanning, OT-aware safety, raw-packet experimentation, packet evidence, distributed execution, and one consistent CLI/API/Web UI.

The architecture should separate **high-speed packet scanning** from **deep interrogation**.

```text
                         ┌──────────────────────────┐
                         │         Web UI           │
                         │  React/Svelte + WebSocket│
                         └────────────┬─────────────┘
                                      │
                         ┌────────────▼─────────────┐
                         │       REST/gRPC API      │
                         └────────────┬─────────────┘
                                      │
                    ┌─────────────────▼──────────────────┐
                    │             Scan Planner           │
                    │ targets / profiles / policies      │
                    │ rate / sharding / retries          │
                    └─────────────────┬──────────────────┘
                                      │
                 ┌────────────────────┴────────────────────┐
                 │                                         │
      ┌──────────▼──────────┐                  ┌───────────▼───────────┐
      │ FAST PACKET ENGINE  │                  │ DEEP PROBE ENGINE     │
      │                     │                  │                       │
      │ TCP SYN             │                  │ Service detection     │
      │ UDP                 │                  │ TLS                   │
      │ ICMP                │                  │ HTTP/H2/WebSocket     │
      │ SCTP                │                  │ Redis/Mongo/SQL       │
      │ ARP/NDP             │                  │ SSH/SMB/LDAP/etc.     │
      │ IP protocols        │                  │ IoT/OT protocols      │
      └──────────┬──────────┘                  └───────────┬───────────┘
                 │                                         │
                 └────────────────────┬────────────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │   Fingerprint Engine    │
                         │ confidence + evidence   │
                         └────────────┬────────────┘
                                      │
                ┌─────────────────────┼──────────────────────┐
                │                     │                      │
        ┌───────▼──────┐      ┌──────▼───────┐      ┌──────▼───────┐
        │ Asset DB     │      │ PCAP Evidence│      │ Script Engine│
        │ observations │      │ PCAPNG       │      │ Lua/WASM/NSE │
        └──────────────┘      └──────────────┘      └──────────────┘
```

The fast engine discovers things. The probe engine determines **what those things actually are**.

---

## 2. Go + gopacket performance model

The scanner should stay in Go and use `gopacket`, but the high-speed engine must avoid the general-purpose `gopacket.PacketSource` path.

> **The default hot-path decoder is `gopacket.DecodingLayerParser` with pre-allocated layer structures.**

This is a deliberate architectural choice, not merely a micro-optimization.

`gopacket.PacketSource` is convenient for generic packet inspection, but it constructs a general packet/layer representation and may allocate substantially more memory while decoding. That is useful for tools such as packet analyzers, but unnecessary for a scanner where the protocol stack is normally predictable.

For scanner traffic such as:

```text
Ethernet -> IPv4 -> TCP
Ethernet -> IPv4 -> UDP
Ethernet -> IPv6 -> TCP
Ethernet -> IPv6 -> UDP
Ethernet -> IPv4 -> ICMP
```

we can pre-allocate the layer objects once per worker and reuse them for every received packet.

Example worker layout:

```go
type Decoder struct {
    eth     layers.Ethernet
    ipv4    layers.IPv4
    ipv6    layers.IPv6
    tcp     layers.TCP
    udp     layers.UDP
    icmp4   layers.ICMPv4
    icmp6   layers.ICMPv6
    payload gopacket.Payload

    parser  *gopacket.DecodingLayerParser
    decoded []gopacket.LayerType
}
```

Conceptually:

```go
parser := gopacket.NewDecodingLayerParser(
    layers.LayerTypeEthernet,
    &eth,
    &ipv4,
    &ipv6,
    &tcp,
    &udp,
    &icmp4,
    &icmp6,
    &payload,
)

decoded := make([]gopacket.LayerType, 0, 8)

for {
    raw := receivePacket()

    decoded = decoded[:0]

    if err := parser.DecodeLayers(raw, &decoded); err != nil {
        continue
    }

    // Inspect only the decoded structures required by the scan engine.
}
```

The important property is that the scanner reuses the same layer structures instead of creating a generic packet object for every received frame.

### Packet I/O remains pluggable

Packet decoding and packet acquisition should remain separate concerns.

```go
type PacketIO interface {
    Open(...) error
    SendBatch([]RawPacket) error
    ReceiveBatch([]RawPacket) (int, error)
    Stats() IOStats
    Close() error
}
```

Backends:

```text
packetio/
    pcap/
    afpacket/
    rawsocket/
    bpf/
    pfring/
    afxdp/
```

Every backend feeds raw frame bytes into the same `DecodingLayerParser` based decoding pipeline.

This gives us:

```text
AF_PACKET / AF_XDP / BPF / PCAP
              ↓
         raw []byte
              ↓
 DecodingLayerParser worker
              ↓
  preallocated layer structs
              ↓
       correlation engine
```

### Rules for the receive hot path

The packet engine should have:

- **no `gopacket.PacketSource` in the performance-critical scanner path;**
- `DecodingLayerParser` as the primary decoder;
- one pre-allocated decoder stack per RX worker;
- fixed worker count;
- CPU-sharded RX/TX processing;
- batched packet reads and writes;
- preallocated packet buffers;
- reuse of decoded-layer slices;
- zero goroutines per target;
- no JSON encoding;
- no string formatting;
- no synchronous logging;
- no synchronous database writes;
- no generic `gopacket.Packet` creation unless a slow/deep path explicitly requires it;
- prebuilt packet templates for transmission;
- incremental checksum updates where possible;
- asynchronous observation/result handling.

### Fast path vs deep path

Use two decoding modes:

```text
FAST RX PATH
------------
raw packet
    ↓
DecodingLayerParser
    ↓
Ethernet/IP/TCP/UDP/ICMP fields
    ↓
correlation/state
    ↓
observation

DEEP ANALYSIS PATH
------------------
interesting response
    ↓
copy/reference payload
    ↓
protocol-specific parser
    ↓
TLS / HTTP / DNS / SNMP / OT / etc.
```

The fast scanner should decode only the fields needed to correlate responses.

For example, a TCP SYN scan normally needs only:

```text
source IP
destination IP
source port
destination port
TCP flags
sequence/acknowledgement
```

There is no reason to construct a complete generic packet hierarchy just to learn that a target returned `SYN/ACK`.

### Parser specialization

For maximum throughput, we may maintain specialized decoder workers:

```text
decoder-tcp4
decoder-tcp6
decoder-udp4
decoder-udp6
decoder-icmp4
decoder-icmp6
decoder-arp
```

or use one parser per interface/RX queue that understands all common layers.

Benchmark both approaches.

The rule is:

> **Prefer predictable, preallocated decoding over convenient general-purpose packet abstraction.**

### Packet generation

The same philosophy applies on TX.

Do not serialize a full set of layer objects from scratch for every probe if most packet fields remain constant.

Use packet templates:

```text
Ethernet header template
IPv4/IPv6 header template
TCP/UDP header template
payload template
```

Then modify only:

```text
target IP
target port
source port
sequence/token
IP ID
protocol-specific transaction ID
checksums
```

before transmission.

### Performance target

Before considering a language rewrite, squeeze the Go/gopacket implementation first:

```text
1. DecodingLayerParser
2. preallocated decoder workers
3. AF_PACKET batch RX/TX
4. packet templates
5. stateless correlation
6. CPU/RX queue sharding
7. memory allocation profiling
8. AF_XDP if AF_PACKET becomes the bottleneck
```

This keeps the implementation maintainable while giving us a credible path toward very high packet rates.

---

## 3. Stateless scanning where possible

Instead of storing one state object per outstanding probe, encode validation data into packet fields where possible.

Example:

```text
token = HMAC(scanSecret, targetIP || targetPort || scanID)
```

Use this approach for:

- TCP sequence numbers;
- ICMP identifiers;
- UDP transaction IDs where supported;
- DNS IDs;
- SNMP request IDs;
- protocol-specific identifiers.

UDP protocols without suitable identifiers fall back to a bounded correlation table.

---

## 4. Scanning engines

Each transport should be a plugin behind a common interface.

```text
scanner/
    tcp/
    udp/
    icmp/
    icmp6/
    arp/
    ndp/
    sctp/
    ipproto/
```

### TCP

Initial modes:

```text
SYN scan
TCP connect scan
ACK scan
FIN
NULL
XMAS
custom TCP flags
```

Allow custom:

```text
sequence
ack
window
TTL
MSS
options
flags
payload
checksum
source port
IP flags
```

Connect scanning is useful when raw packet privileges aren't available.

SYN should be the high-performance default.

---

## 5. UDP as a first-class engine

UDP should be one of the scanner's biggest differentiators.

The wrong model is:

```text
send empty UDP
wait
nothing returned
=> open|filtered
```

Instead use **protocol-aware probe campaigns**.

### UDP strategy

For each UDP target:

```text
1. Known service-specific probe
2. Secondary protocol probe
3. Generic probe
4. Alternative probe when ambiguity remains
5. Adaptive retry
6. Correlate UDP + ICMP responses
7. Assign state + confidence
```

Examples:

```text
UDP/53
 ├─ DNS A query
 ├─ DNS CHAOS query if explicitly enabled
 └─ generic DNS probe

UDP/161
 ├─ SNMP request
 └─ alternate SNMP version probe

UDP/123
 └─ NTP request

UDP/500
 └─ IKE negotiation probe

UDP/5683
 └─ CoAP

UDP/47808
 └─ BACnet/IP

UDP/1900
 └─ SSDP

UDP/5060
 └─ SIP

UDP/623
 └─ IPMI/RMCP
```

Useful UDP probes:

```text
DNS
mDNS
LLMNR
NetBIOS
DHCP
TFTP
NTP
SNMP
SIP
IKE
IPMI
RADIUS
Syslog
QUIC
WireGuard detection
STUN
CoAP
DTLS
VXLAN
BACnet
RIP
ISAKMP
```

Return evidence and confidence, not just a boolean state.

Example:

```text
State: open
Confidence: 100
Reason: valid SNMP response
Probe: snmp-v2-get
RTT: 2.7 ms
Packets TX: 1
Packets RX: 1
```

or:

```text
State: open|filtered
Confidence: 32
Reason: no application response and no ICMP unreachable
Probes attempted: 4
```

---

## 6. Native payload database

Create a native probe format from the beginning.

Example:

```yaml
name: dns-version
transport: udp

ports:
  - 53

tags:
  - dns
  - discovery

safety: safe

payload:
  encoding: hex
  data: "..."

timeout: 750ms
retries: 1

match:
  - type: dns

extract:
  - dns.rcode
  - dns.answers
```

Payload sources:

```text
ASCII
escaped strings
HEX
Base64
raw file
generated packet
Go protocol generator
```

CLI examples:

```bash
scan --payload foo.yaml
scan --send-hex "00ff..."
scan --send-base64 "..."
scan --payload-file request.bin
```

Probe definitions should be composable:

```text
payload
matcher
extractor
correlator
```

---

## 7. Nmap probe compatibility

Build an importer for `nmap-service-probes`, but do not assume Nmap probe data can simply be bundled into a proprietary binary.

Support:

```text
probe import nmap-service-probes
```

Maintain:

```text
probes/native/
```

with native definitions.

Resulting model:

```text
Native database
+
user database
+
runtime-imported Nmap database
```

---

## 8. Service fingerprinting engine

A discovered port should enter a structured pipeline.

```text
port
 ↓
passive banner
 ↓
probable protocol
 ↓
targeted probe
 ↓
response matcher
 ↓
additional probe if needed
 ↓
service identity
 ↓
version/product/device metadata
```

Results should include confidence and supporting evidence.

Example:

```text
443/tcp
state       open
service     https
confidence  100%

TLS 1.3
ALPN        h2,http/1.1
Certificate *.example.com
HTTP        nginx
HTTP/2      yes
WebSocket   possible
Product     nginx 1.xx
```

---

## 9. Deep protocol modules

Common interface:

```go
type ServiceProbe interface {
    Name() string
    Match(ctx ProbeContext) bool
    Probe(ctx ProbeContext) (*Observation, error)
}
```

### Web

```text
HTTP/1.0
HTTP/1.1
HTTP/2
HTTP/3
HTTPS
TLS
WebSocket
GraphQL
REST hints
gRPC
FastCGI
```

GraphQL detection can inspect:

```text
/graphql
/graphql/
api/graphql
content type
GraphQL response structure
```

and optionally perform introspection when explicitly requested.

### Infrastructure

```text
SSH
FTP
SMTP
IMAP
POP3
DNS
DHCP
LDAP
Kerberos
SMB
RDP
NFS
RPC
VNC
Telnet
```

### Databases

```text
Redis
MongoDB
PostgreSQL
MySQL/MariaDB
MSSQL
Oracle TNS
Cassandra
Elasticsearch
Memcached
InfluxDB
Couchbase
```

Prefer unauthenticated, read-only handshake/fingerprint operations.

---

## 10. TLS subsystem

TLS should be its own subsystem, not just certificate CN extraction.

Capture:

```text
TLS versions
cipher suites
ALPN
certificate chain
SAN
issuer
subject
validity
public key algorithm
key size
signature algorithm
OCSP stapling
SNI behavior
session tickets
TLS extensions
supported groups
HTTP/2
HTTP/3 hints
```

Optionally test different ClientHello profiles.

The TLS layer should also identify services running behind TLS.

---

## 11. OT/ICS safety profile

Do not treat OT like ordinary IT.

Create:

```text
--profile ot-safe
```

with:

- low packet rate;
- conservative timeout;
- no malformed packets;
- no fuzzing;
- read-only identification only.

Protocols:

```text
Modbus/TCP
S7comm
BACnet/IP
EtherNet/IP
DNP3
IEC 60870-5-104
OPC UA
PROFINET discovery
MQTT
AMQP
CoAP
KNX/IP
Fox
Omron FINS
Melsec
```

Prefer read-only identification operations such as:

```text
EtherNet/IP -> ListIdentity
BACnet      -> Who-Is / I-Am
Modbus      -> Device Identification
```

---

## 12. IoT detection

Build a device fingerprint layer above service detection.

Inputs:

```text
MAC OUI
mDNS
SSDP
UPnP
HTTP headers
TLS certificate
SSH banner
SNMP sysDescr
DHCP fingerprints
open-port combination
service versions
hostnames
```

Output example:

```text
Device family: Hikvision camera
Confidence: 91%

Evidence:
  OUI
  HTTP server
  RTSP
  ONVIF
  UPnP device descriptor
```

---

## 13. IP protocol scanning

Support extensible scanning for:

```text
IPv4 protocol numbers 0–255
ICMP
IGMP
GRE
ESP
AH
SCTP
IPv6 extension protocols
```

Classifications:

```text
responsive
protocol-unreachable
administratively-prohibited
no-response
```

---

## 14. Packet Forge

Dedicated subsystem:

```text
forge/
    ethernet
    arp
    ipv4
    ipv6
    tcp
    udp
    icmp
    sctp
```

Allow custom definitions for:

```text
Ethernet headers
VLAN tags
IP options
IPv6 extension headers
fragmentation
TTL
DSCP
TCP options
TCP flags
window
sequence
checksums
UDP length
payload
```

Optional intentional overrides:

```text
invalid checksum
strange IP length
unusual flag combinations
fragment layouts
```

Potentially disruptive malformed/fuzzing features should sit behind:

```text
--profile research
```

---

## 15. Packet capture integration

Each scan should optionally produce:

```text
scan.pcapng
```

Packets should also be linked to scan results.

```text
Host
 └── 443/tcp
      ├── SYN
      ├── SYN/ACK
      ├── TLS ClientHello
      ├── TLS ServerHello
      ├── certificate
      └── HTTP response
```

UI example:

```text
TX 21:44:01.121 SYN
RX 21:44:01.123 SYN/ACK
TX 21:44:01.124 ACK
TX 21:44:01.128 ClientHello
RX 21:44:01.130 ServerHello
```

PCAP writing must be asynchronous so disk I/O cannot stall scanning.

---

## 16. NSE compatibility

Use three stages.

### Stage A — Nmap bridge

Discover ports with our scanner, then invoke locally installed Nmap for selected NSE scripts and import the structured output.

### Stage B — Lua engine

Embed Lua 5.4 and gradually implement compatibility APIs such as:

```text
nmap.new_socket()
nmap.registry
nmap.get_port_state()
nmap.set_port_state()
nmap.clock_ms()
stdnse
shortport
comm
sslcert
http
```

### Stage C — native NSE compatibility

Support enough `nselib` behavior to execute common NSE scripts directly.

Also preserve NSE safety categories such as:

```text
safe
discovery
intrusive
exploit
dos
```

---

## 17. Native scripting API

Do not make NSE the future of the scanner.

Support:

```text
Lua
WASM
native Go modules
```

WASM is attractive for enterprise plugins because it is:

```text
sandboxed
cross-platform
resource-limited
language-independent
```

Plugin API:

```text
target()
ports()
send()
recv()
connect_tcp()
connect_udp()
tls_connect()
http_request()
report_service()
report_attribute()
emit_finding()
```

---

## 18. Scan profiles

Provide opinionated profiles:

```text
discovery
fast
tcp
udp
udp-deep
service
deep
iot
ot-safe
web
database
full
research
custom
```

Examples:

```bash
scanner scan 10.10.0.0/16 --profile fast
```

```bash
scanner scan 10.10.0.0/16 \
  --profile udp-deep \
  --ports 53,123,161,500,623,1900,47808
```

```bash
scanner scan host.example.com \
  --profile deep
```

---

## 19. Rate management

Support more than a flat `--rate`.

Rate controls:

```text
PPS
Mbps/Gbps
per-host PPS
per-subnet PPS
burst
adaptive mode
packet loss feedback
NIC drop feedback
ICMP rate limiting detection
```

Scheduler hierarchy:

```text
Global limit
    ↓
Interface limit
    ↓
Target-network limit
    ↓
Host limit
```

Randomize or permute target × port space so one host is not hammered sequentially.

---

## 20. Result data model

Everything becomes an observation.

```text
Scan
Asset
Interface
Address
Port
Protocol
Service
Fingerprint
Certificate
Banner
PacketEvidence
ProbeExecution
ScriptResult
Finding
```

Possible observation model:

```text
Observation {
    scan_id
    timestamp

    target
    transport
    port

    state
    confidence
    reason

    probe

    service
    product
    version

    attributes

    packet_refs
}
```

Never discard raw evidence just because fingerprinting failed.

Unknown responses become:

```text
unknown fingerprint
```

which can later feed signature development.

---

## 21. Storage

Standalone:

```text
SQLite
```

Enterprise/controller:

```text
PostgreSQL
```

Large artifacts:

```text
PCAPNG
screenshots
raw response data
```

Store in filesystem or S3-compatible object storage.

Single-host deployment should still be easy:

```bash
scanner web
```

---

## 22. Distributed scanning

Design early even if implemented later.

```text
                 Controller
                     │
          ┌──────────┼──────────┐
          │          │          │
       Agent A    Agent B    Agent C
```

Communication:

```text
gRPC / ConnectRPC
mTLS
```

Controller shards:

```text
targets × ports × protocol
```

Useful for:

```text
different VLANs
different datacenters
cloud accounts
remote offices
very large address spaces
```

---

## 23. Privilege separation

Do not run the web/API/database components as root just because raw sockets require privileges.

Use:

```text
scanner-controller
scanner-packetd
```

Only `packetd` gets the minimum required capabilities.

Typical Linux capabilities:

```text
CAP_NET_RAW
CAP_NET_ADMIN
```

The web/API/database layers remain unprivileged.

---

## 24. Web UI

Dark, simple, dense, terminal-inspired.

Main pages:

```text
Dashboard

Scans
 ├─ new scan
 ├─ templates
 ├─ running
 └─ history

Assets
 ├─ hosts
 ├─ services
 ├─ operating systems
 └─ devices

Network
 └─ topology

Protocols

Payloads

Scripts

Packet Lab

PCAP

Agents

Settings
```

### New scan

```text
TARGETS
10.10.0.0/16

PROFILE
[ Deep Scan ]

PORTS
● Default
○ Top 100
○ Top 1000
○ All
○ Custom

PROTOCOLS
☑ TCP
☑ UDP
☑ ICMP
☐ SCTP
☐ IP protocols

RATE
500,000 pps

CAPTURE
☑ Store packet evidence
```

Show results live using WebSockets.

---

## 25. UI host view

Example:

```text
10.10.5.27
────────────────────────────────

Linux
Dell server

Latency  0.83 ms

PORT      SERVICE
22/tcp    SSH
80/tcp    HTTP
443/tcp   HTTPS
161/udp   SNMP

TLS
────
TLS 1.2 / 1.3
h2
CN server01.example.net

FINGERPRINTS
────────────
OpenSSH 9.x
nginx
Linux

PACKETS
───────
34 captured

[ View packets ]
[ Download PCAP ]
```

---

## 26. Suggested repository layout

```text
cmd/
    scanner/
    scannerd/
    scanner-agent/

internal/
    api/
    config/

    engine/
        scheduler/
        targets/
        rate/
        correlation/

    packetio/
        pcap/
        afpacket/
        raw/
        afxdp/

    scan/
        tcp/
        udp/
        icmp/
        icmp6/
        arp/
        ndp/
        sctp/
        ipproto/

    probe/
        engine/
        database/
        matchers/

    protocols/
        dns/
        http/
        tls/
        ssh/
        snmp/
        redis/
        mongodb/
        postgres/
        mysql/
        smb/
        ldap/
        modbus/
        bacnet/
        ethernetip/
        ...

    fingerprint/

    forge/

    capture/

    scripting/
        lua/
        wasm/
        nse/

    storage/
        sqlite/
        postgres/

    distributed/

    security/

    telemetry/

web/

probes/
    tcp/
    udp/
    ot/
    iot/

tests/
    pcaps/
    fingerprints/
    integration/
    performance/
```

---

## 27. Development phases

### Phase 0 — benchmark framework

Before features:

```text
packet generator
fake responders
packet-loss simulation
latency simulation
benchmark scripts
PCAP fixtures
```

Hard performance numbers from day one.

### Phase 1 — high-speed core

Deliver:

```text
IPv4
IPv6
target parsing
CIDR/ranges
TCP SYN
ICMP
ARP/NDP
stateless correlation
rate limiting
AF_PACKET
PCAP
JSON output
CLI
```

### Phase 2 — UDP engine

Build:

```text
UDP state detection
ICMP correlation
probe database
protocol-specific payloads
multi-probe campaigns
adaptive retries
confidence scoring
```

### Phase 3 — service detection

Implement:

```text
generic banners
TLS
HTTP
SSH
DNS
SMTP
FTP
SNMP
Redis
Mongo
Postgres
MySQL
SMB
RDP
LDAP
```

### Phase 4 — IoT + OT

Add:

```text
BACnet
Modbus
S7
EtherNet/IP
OPC UA
DNP3
MQTT
CoAP
UPnP
ONVIF
device fingerprinting
```

### Phase 5 — Packet Forge

Custom packets:

```text
binary payloads
custom headers
custom TCP flags
IP options
fragmentation
checksum override
packet templates
```

### Phase 6 — Web UI/API

Same configuration objects must power:

```text
CLI
REST
Web
```

No feature should exist only in CLI.

### Phase 7 — scripting

Implement:

```text
WASM plugins
Lua
Nmap bridge
NSE compatibility
```

### Phase 8 — distributed scanning

Add:

```text
controller
agents
mTLS
job sharding
remote capture
agent health
```

### Phase 9 — enterprise hardening

```text
OIDC/SAML
RBAC
audit trail
scan approvals
target allowlists
rate policies
encrypted credentials
signed plugin packages
HA controller
metrics
OpenTelemetry
Prometheus
```

---

## 28. Testing strategy

Build an automated network lab containing:

```text
Linux network namespaces
Docker containers
VMs
tc/netem
virtual routers
IPv6
firewalls
NAT
packet loss
latency
reordering
ICMP limiting
```

Service fixtures:

```text
nginx
Apache
OpenSSH
Redis
MongoDB
PostgreSQL
MariaDB
DNS
SNMP
LDAP
SMB
MQTT
OT simulators
```

Continuously compare behavior against:

```text
Nmap
Masscan
ZMap
```

not because their output is always correct, but to identify behavioral differences.

---

## 29. Fuzz the scanner itself

Use Go fuzzing for:

```text
packet parsers
fingerprint matchers
payload parsers
service decoders
PCAP parsers
script API
```

Assume every returned packet is hostile.

---

## 30. Performance objectives

Avoid promising a specific packet rate before benchmarking.

### Generation 1

```text
AF_PACKET
hundreds of thousands → 1M+ pps
minimal packet loss
single machine
```

### Generation 2

```text
multi-queue NIC
CPU affinity
batching
zero-copy optimizations
several Mpps
```

### Generation 3

```text
AF_XDP backend
10/25/40/100 GbE optimization
distributed scanning
```

Long-term target: compete with Masscan/ZMap for shallow discovery while transitioning immediately into intelligent service probing.

---

## 31. Metrics

Expose:

```text
scanner_packets_tx_total
scanner_packets_rx_total
scanner_rx_dropped_total
scanner_targets_total
scanner_targets_completed
scanner_probes_total
scanner_probe_timeout_total
scanner_services_detected_total
scanner_pps
scanner_bps
scanner_queue_depth
scanner_packet_latency
```

Internal profiling:

```text
pprof
OpenTelemetry
Prometheus
```

---

## 32. Defining product features

The scanner should not market itself merely as “faster Nmap.”

Its defining combination should be:

```text
             FAST
              │
              │
 MASSIVE ─────┼───── DEEP
              │
              │
          EVIDENCE
```

Core differentiators:

1. Masscan/ZMap-style asynchronous scanning
2. Multiple ports and protocols simultaneously
3. Best-in-class UDP interrogation
4. Native TCP/UDP/ICMP/SCTP/IP protocol scanning
5. Extensible binary probe database
6. Deep service fingerprinting
7. TLS/Web/DB protocol intelligence
8. IoT fingerprinting
9. OT-safe discovery
10. Integrated packet forge
11. Every scan optionally backed by PCAP evidence
12. NSE interoperability
13. Lua/WASM plugin ecosystem
14. CLI + API + Web as equal interfaces
15. Distributed agents
16. Enterprise-grade auditability and safety

> **Scan fast first; interrogate intelligently second.**

That architecture gives the project a realistic path to competing with **ZMap/Masscan on discovery** and **Nmap on depth**, rather than creating another scanner that is mediocre at both.
