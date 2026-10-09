# Nyxr Next-Generation Network Scanner Roadmap

## Delivery ownership and baseline

The [NEXT GEN / HORIZON ownership contract](architecture/next-gen-horizon-contracts.md)
maps every section to local implementation, remaining owner, canonical issue and
validation gate. It governs shared-interface extensions; sketches, phases, commands
and example scores below remain vision. Reuse the existing scanner, service planner,
DSL, evidence and asset store. HORIZON owns controlled experiments and transport-state
inference. Local implementation does not imply publication or live validation.

Delivery: [NYXR NEXT GEN](https://github.com/users/matusso/projects/3),
foundation [#75](https://github.com/matusso/nyxr/issues/75).

## Vision

Nyxr should evolve beyond being a fast port scanner.

The target should be:

> **Nyxr = high-speed network discovery + protocol intelligence + asset identity + evidence engine.**

The goal is not simply to become a faster version of Nmap, Masscan, Naabu, or ZGrab. Nyxr should combine speed, deep protocol understanding, reliable identification, explainable evidence, modern protocol support, and continuous asset intelligence into one platform.

---

## Strategic Positioning

Current tools tend to specialize:

- **Nmap** — excellent fingerprinting and service detection depth
- **Masscan** — extremely high-speed stateless discovery
- **ZGrab2** — strong application-layer handshakes and structured transcripts
- **Naabu** — fast modern port scanning with integration into ProjectDiscovery tooling

Nyxr should combine the strongest parts of those categories and add capabilities they do not provide well:

- adaptive protocol probing
- stateful UDP discovery
- asset correlation
- evidence-based identification
- passive + active discovery
- OT/ICS awareness
- unknown-protocol clustering
- continuous change detection
- distributed enterprise scanning
- modern QUIC / HTTP/3 support

---

# Priority Overview

| Priority | Feature | Strategic Value |
|---|---|---|
| **P0** | Adaptive Probe Engine | Core architectural differentiator |
| **P0** | Stateful Protocol Detection | Can exceed traditional `-sV` style detection |
| **P0** | Asset Identity Graph | Converts ports into meaningful assets |
| **P0** | Evidence / Transcript Engine | Makes every detection explainable |
| **P1** | Native Deep UDP Engine | Major weakness in most scanners |
| **P1** | QUIC / HTTP/3 Intelligence | Modern protocol coverage |
| **P1** | TLS / SSH / TCP Fingerprinting | Better device and software identification |
| **P1** | AF_XDP Fast Path | Masscan-class Linux performance potential |
| **P1** | OT / ICS Protocol Suite | Strong commercial differentiator |
| **P2** | Passive + Active Discovery | Finds assets active scanning misses |
| **P2** | Distributed Scanning | Enterprise-scale operation |
| **P2** | Differential Monitoring | Continuous exposure monitoring |
| **P2** | Unknown Protocol Classifier | Finds repeated proprietary services |
| **P3** | Vulnerability Verification Pipeline | Adds scanner-to-assessment workflows |

---

# 1. Adaptive Probe Engine

## Implementation status (October 2026)

**Implemented:** Discovery feeds the bounded service queue. The classifier
combines port priors, server-first banners, protocol grammar and transport
signals; the planner selects each eligible probe by expected entropy reduction
per execution cost. Native and declarative protocol machines share an executor
and evidence update loop for TCP and UDP. Database exchanges are planned
individually; ALPN chooses HTTP/1 or native HTTP/2 on the negotiated TLS
connection. An observed Envoy header makes a read-only `/server_info` product
validator eligible. Parser results update hypotheses, while silence and I/O
failures remain inconclusive. Probe budgets, deadlines, cancellation, bounded
responses, attempt tracking and a minimum information gain bound the work.
JSON, stored history, API results and the web UI carry the decisions,
before/after hypotheses, evidence references and termination reason. Unknown
services retain observations for future native parsers or protocol definitions.
See the [service identification guide](guide/service-identification.md).

**Limits:** Likelihoods and costs are engineering estimates, not calibrated
probabilities. A product validator only strengthens a matching structured
response; a denied or absent admin endpoint leaves the header claim unchanged.
The example's SYN/ACK-based Linux identification is available through section 7
as a separate heuristic stack claim; the adaptive engine does not infer an OS
from TLS or HTTP headers. The existing
native protocol and DSL bounds still apply within each state machine.

This should become the core of Nyxr.

Traditional service detection often follows:

```text
port
  ↓
predefined probes
  ↓
responses
  ↓
regex / signature
```

Nyxr should instead use:

```text
observation
  ↓
hypothesis
  ↓
best next probe
  ↓
new observation
  ↓
confidence update
  ↺
```

Example:

```text
TCP/8443 OPEN
     │
     ├── SYN/ACK fingerprint
     │      Linux-like stack, confidence 61%
     │
     ├── TLS ClientHello
     │      TLS 1.3
     │      ALPN: h2,http/1.1
     │      SAN: api.example.com
     │
     ├── HTTP/2 probe
     │      Server: envoy
     │
     ├── Envoy-specific validation
     │
     └── RESULT
            HTTPS
            Envoy Proxy
            Linux
            confidence: 98%
```

The key difference is that Nyxr should not blindly fire every possible probe.

It should select the probe with the highest expected information gain.

## Proposed Internal Flow

```text
Observation
   ↓
Classifier
   ↓
Candidate Protocols
   ↓
Probe Planner
   ↓
Probe
   ↓
Response Parser
   ↓
Evidence Update
   ↺
```

## Benefits

- fewer probes
- less network noise
- faster deep detection
- higher confidence
- easier support for unknown services
- easier extension to new protocols

---

# 2. Nyxr Protocol DSL

Protocol detection should not be hardcoded entirely in Go.

Create a declarative protocol definition language.

Example:

```yaml
protocol: postgresql

transports:
  - tcp

ports:
  - 5432

steps:
  - send:
      hex: "0000000804d2162f"

  - expect:
      bytes: "53"

    then:
      protocol: postgresql
      capability:
        tls: true

  - start_tls: true

  - extract:
      certificate: true
```

The DSL should support:

```text
send
receive
expect
regex
binary match
length fields
branch
repeat
starttls
tls
dtls
quic
udp
tcp
extract
calculate
timeout
correlate
```

## Design Goals

- hot-loadable definitions
- no scanner recompilation required
- reusable parsers
- protocol inheritance
- test fixtures
- fuzzable protocol modules
- per-protocol confidence scoring
- structured extracted fields
- evidence generation
- safe timeouts and limits

---

# 3. Asset Identity Graph

## Implementation status (October 2026)

**Implemented:** Nyxr assigns persistent local IDs and database-namespaced global IDs. Validated MAC, SNMP engine ID, SMB GUID, signature-verified SSH host key, and scoped Kubernetes/cloud IDs can join addresses. Kubernetes node UIDs and addresses can be collected directly from the HTTPS API; scoped Kubernetes/cloud IDs can also be imported from inventory JSON. The graph shows current membership, source observations, conservative link confidence, competing weak-clue hypotheses, and device class/model/OS claims. Membership events preserve joins, splits, and removal from the migration baseline onward. The CLI, API, and web UI support manual join/separate/clear reviews with an audit log. SSDP supplies UPnP UUID clues; hostname and leaf certificate clues remain relationships, never automatic merge keys. Pcap/pcapng import supplies passive IP sightings and LLDP chassis/port, capture-interface, and VLAN topology observations; matched LLDP links appear on graph assets. See the [asset identity guide](guide/asset-identity.md) for commands and API paths.

**Remaining:** Earlier ownership history cannot be reconstructed when an existing database receives its migration baseline. Namespaced global IDs distinguish database lineages, and scoped inventory signals yield matching portable IDs across databases, but other devices still need controller reconciliation. LLDP and passive evidence enter through capture import, not a live graph pipeline; LLDP without a management address has no asset link. Cloud IDs enter through scoped operator inventory import, not direct cloud API collection. Interface ownership, VLAN membership over time, and topology beyond imported LLDP sightings still need a full graph model. Model/OS synthesis covers validated Modbus/EtherNet/IP, SMB, Nmap, and device-class observations, not every device family. Confidence scores are heuristics rather than calibrated probabilities. Shared certificates, hostnames, MAC OUIs, HTTP headers, and software banners remain deliberately excluded from automatic merge keys.

Nyxr should stop treating IP addresses as independent scan results.

Instead of:

```text
10.10.1.43

22 SSH
80 HTTP
443 HTTPS
161 SNMP
```

Nyxr should build:

```text
Asset NYXR-A83F92

Device:
  Cisco Catalyst 9300

OS:
  Cisco IOS XE 17.x

Identity evidence:
  MAC OUI
  SNMP engine ID
  SSH host key
  HTTPS certificate
  HTTP fingerprint
  TCP stack fingerprint
  LLDP chassis ID

IPs:
  10.10.1.43
  fe80::a21b:...
  10.10.20.1

Interfaces:
  Gi1/0/1
  Gi1/0/2
  ...

Confidence:
  99.4%
```

## Possible Identity Signals

```text
MAC address
IPv4
IPv6
hostname
reverse DNS
mDNS
LLMNR
NetBIOS
certificate fingerprint
certificate SAN
SSH host key
SMB GUID
SNMP engine ID
SNMP sysObjectID
HTTP favicon
HTTP headers
TLS fingerprint
TCP fingerprint
UPnP UUID
LLDP chassis ID
Kubernetes metadata
cloud metadata
```

## Outcome

Nyxr should be able to determine that several IP addresses, names, and interfaces belong to the same physical or virtual asset.

This makes results much more valuable for:

- asset inventory
- security monitoring
- exposure management
- incident response
- network mapping
- attack surface management

---

# 4. Evidence and Transcript Engine

**Implemented foundation (#76):** All discovery and service scans share the
`nyxr/v1` record pipeline, including CLI `--no-db`. Observation/exchange source
references map to exact retained JSON with parser/claim/completeness metadata;
unknown UDP responses are bounded and retained. History/API preserve the same
source mapping, migration preserves existing asset lineage, and retention returns
explicit unavailable sources. HORIZON's offline report adapter reuses replay and
references the original envelope without a second capture store or graph. These
unit, loopback and replay checks do not establish privileged/live HORIZON gates.
See [output records](reference/output-records.md#source-references).

Every service identification should carry evidence.

Instead of:

```json
{
  "service": "postgresql"
}
```

Nyxr should return:

```json
{
  "service": "postgresql",
  "confidence": 0.997,
  "evidence": [
    {
      "probe": "postgres_ssl_request",
      "response": "53",
      "meaning": "PostgreSQL SSL supported"
    }
  ]
}
```

Nyxr should optionally retain:

```text
raw request
raw response
packet timestamps
PCAP fragments
TLS handshake
HTTP transaction
probe path
classifier decisions
response parsing
confidence changes
```

## Web UI Workflow

```text
Scan Result
   ↓
View Evidence
   ↓
View Packets
   ↓
Clone Probe
   ↓
Modify
   ↓
Resend
```

This complements Nyxr's planned packet viewer/editor functionality and makes the scanner useful for research and protocol analysis.

---

# 5. Native Deep UDP Engine

UDP must become a first-class capability.

Avoid the simplistic model:

```text
send payload
wait
open|filtered
```

Create a real transaction engine.

## Required Capabilities

```text
ICMP unreachable correlation
ICMP rate-limit handling
adaptive retries
adaptive retry delay
source-port preservation
transaction IDs
response correlation
fragmentation
large responses
multi-packet responses
protocol state
DTLS
QUIC
broadcast discovery
multicast discovery
```

## Priority UDP Protocols

```text
DNS
NTP
SNMP v1/v2/v3
BACnet
CoAP
QUIC
DTLS
IKE
IPsec NAT-T
TFTP
SIP
RADIUS
DHCP
NetBIOS
mDNS
SSDP
Syslog
Memcached
CLDAP
WireGuard
OpenVPN
```

The goal should be **stateful UDP**, not just a larger static payload database.

---

# 6. Native QUIC / HTTP/3 Support

Modern service detection needs first-class QUIC support.

Nyxr should extract:

```text
QUIC versions
version negotiation
ALPN
TLS certificate
transport parameters
connection IDs
HTTP/3 SETTINGS
Alt-Svc
0-RTT capability
datagram capability
WebTransport capability
HTTP response
server fingerprint
```

Example:

```bash
nyxr scan 10.0.0.1 -p udp/443
```

Possible result:

```text
443/udp open

QUIC v1
HTTP/3

TLS:
  TLS 1.3
  ALPN h3

HTTP:
  server: cloudflare

QUIC:
  active_connection_id_limit: 2
  max_udp_payload_size: 65527
  datagram: supported
```

---

# 7. TCP/IP Stack Fingerprinting

## Implementation status (October 2026)

**Implemented:** `--fingerprint` with raw IPv4 SYN mode uses a fixed native
option/ECN probe and retains bounded, token-correlated SYN/ACK and RST/ACK
samples within the existing timeout. Evidence covers window, MSS, scale,
TTL/initial-TTL estimate, DF, option bytes/order, SACK, timestamps, ECN,
sampled IP ID behavior, repeat timing and reset behavior. Native rules emit
cautious Linux, Windows and BSD/macOS hypotheses; unknown, conflicting and
truncated collections retain evidence. Stable signatures normalize counters.
JSON, history, API, text and web UI expose the results. Device synthesis
combines network/application evidence with separate OS confidence and conflict
reporting; asset profiles retain family claims without merging on signatures.
See the [TCP/IP stack fingerprinting guide](guide/tcp-stack-fingerprinting.md).

**Remaining:** Live calibration, IPv6 raw SYN collection, kernel/version and
specific embedded-stack rules, verified intermediary/device roles, cross-flow
IP ID analysis and longer controlled retransmission experiments. Connect scans
do not expose headers. Receive times are batch estimates; duplicates cannot
prove retransmission. Confidence is heuristic and describes the responder.

Do not rely only on service banners.

Collect characteristics from SYN/ACK, RST, and related traffic.

## Features

```text
window size
MSS
window scale
TTL
DF flag
TCP options
TCP option ordering
SACK
timestamps
ECN
IP ID behavior
retransmission behavior
RST behavior
```

Combine network-stack evidence with application-layer fingerprints.

## Possible Identifications

```text
OS family
kernel family
embedded TCP/IP stack
load balancer
firewall
reverse proxy
NAT
VPN gateway
printer
IoT device
network appliance
```

## Recommendation

Use Nyxr-native fingerprints and classifiers where possible to avoid commercial licensing dependencies on third-party fingerprint systems.

---

# 8. AF_XDP High-Performance Backend

`gopacket.DecodingLayerParser` is a good optimization, but Nyxr will eventually hit limits in high-rate scanning.

Recommended architecture:

```text
Nyxr Packet Engine

             ┌── AF_XDP
Linux ───────┤
             └── libpcap fallback

macOS ────────── BPF

Windows ──────── Npcap
```

## Linux Fast Path

```text
NIC queue 0 → CPU 0 → worker 0
NIC queue 1 → CPU 1 → worker 1
NIC queue 2 → CPU 2 → worker 2
...
```

## Performance Techniques

```text
preallocated packet buffers
zero allocation hot path
per-core state
batch RX
batch TX
lock-free queues
target sharding
port sharding
NIC RSS awareness
NUMA awareness
adaptive packet rate
backpressure
```

Do not replace the portable engine.

Maintain:

```text
portable engine
    +
high-performance Linux engine
```

This provides both portability and top-tier performance.

---

# 9. OT / ICS Protocol Suite

OT support could become a major commercial differentiator.

## Recommended Protocols

```text
BACnet
Modbus/TCP
Siemens S7
DNP3
IEC 60870-5-104
EtherNet/IP / CIP
OPC UA
PROFINET discovery
KNXnet/IP
Moxa discovery
Fox
Omron FINS
Mitsubishi MELSEC
Schneider protocols
```

## Extracted Information

```text
vendor
device family
model
firmware
serial number
station ID
PLC mode
module list
rack/slot
BACnet objects
CIP identity
S7 module information
device capabilities
```

Nyxr should aim to identify actual industrial devices, not merely detect open ports.

---

# 10. Unknown Protocol Discovery

Unknown services should not simply return:

```text
unknown
```

Nyxr should analyze behavior.

## Features

```text
server-speaks-first
ASCII vs binary
entropy
message length
magic bytes
length prefix
endianness
response timing
response similarity
TLS acceptance
HTTP-like grammar
line-oriented framing
null termination
ASN.1-like structures
protobuf-like structures
CBOR-like structures
```

Possible output:

```text
UNKNOWN SERVICE

Probability:
  proprietary binary RPC   71%
  industrial protocol      16%
  database protocol         8%

Characteristics:
  server-speaks-first
  binary
  big-endian 32-bit length prefix
  deterministic 24-byte banner

Fingerprint:
  nxp_9e83a124
```

## Cluster Unknown Services

Nyxr should group matching unknown services across a network.

Example:

> 137 hosts appear to run the same unknown binary service.

This is extremely valuable for internal asset discovery and proprietary systems.

---

# 11. Passive + Active Discovery

Add passive discovery mode:

```bash
nyxr listen
```

Passive mode should learn:

```text
hosts
MACs
VLANs
DNS names
TLS certificates
HTTP hosts
DHCP fingerprints
mDNS
SSDP
LLMNR
NetBIOS
ARP
IPv6 NDP
services
```

Then allow active verification:

```bash
nyxr scan --learned
```

Architecture:

```text
Passive Observation
        +
Active Verification
        ↓
      Asset
```

This can find systems that ordinary CIDR scanning misses.

---

# 12. Differential and Continuous Scanning

Nyxr should understand changes over time.

Example:

```text
10.0.10.22

Yesterday:
  22/tcp
  443/tcp

Today:
  22/tcp
  443/tcp
  6379/tcp NEW
```

Track:

```text
new service
removed service
certificate changed
SSH host key changed
OS changed
firmware changed
HTTP title changed
TLS configuration changed
SNMP identity changed
MAC vendor changed
new IPv6 address
new asset
asset disappeared
```

This evolves Nyxr into a platform for:

```text
attack surface management
SOC monitoring
exposure monitoring
shadow IT detection
change detection
incident response
continuous inventory
```

---

# 13. Distributed Nyxr Architecture

Long-term enterprise architecture:

```text
                 Nyxr Controller
                       │
            ┌──────────┼──────────┐
            │          │          │
          agent       agent      agent
          EU-1        US-1       LAN-1
```

## Controller Responsibilities

```text
target partitioning
rate limits
checkpointing
retry scheduling
deduplication
result streaming
scan leases
agent health
capability scheduling
central evidence storage
```

## Agent Capabilities

Agents should advertise:

```text
raw socket
AF_XDP
IPv6
local subnet access
OT protocol support
packet capture
privilege level
supported interfaces
throughput limits
```

Possible usage:

```bash
nyxr scan 10.0.0.0/8 \
  --distributed \
  --rate 20mpps
```

---

# 14. Vulnerability Verification Pipeline

Nyxr should not become a monolithic Nessus replacement inside the scanner core.

Keep responsibilities separated.

Recommended architecture:

```text
Nyxr
 │
 ├── discover
 ├── fingerprint
 ├── classify
 │
 ▼
Finding Pipeline
 │
 ├── Nuclei
 ├── Nyxr checks
 ├── CVE matcher
 └── plugins
```

Nyxr's main responsibility should be to provide high-quality, high-confidence service and asset intelligence to downstream vulnerability logic.

---

# 15. Confidence Scoring

Every important result should have a confidence score.

Example:

```text
Service: PostgreSQL
Confidence: 99.7%

Evidence:
  port heuristic             +4%
  PostgreSQL SSL response   +58%
  protocol grammar match    +28%
  TLS behavior               +9.7%
```

Possible confidence categories:

```text
0-30%    weak hypothesis
30-60%   probable
60-85%   likely
85-97%   strong
97-100%  confirmed
```

Confidence should be derived from evidence, not assigned manually.

---

# 16. Scan Intelligence Metrics

Nyxr should report its own scanning efficiency.

Example:

```text
Scan intelligence:

Hosts scanned:              65,536
Hosts alive:                   318
Open services:               1,937
Protocol probes sent:       14,291
Probes avoided:            183,922
Services confirmed:          1,711
Unknown services:               23
Average confidence:           96.7%
```

This would visibly demonstrate the benefit of adaptive probing.

---

# 17. Suggested Result Model

Each result should be centered around an asset.

Example:

```yaml
asset:
  id: NYXR-A83F92

identity:
  vendor: Cisco
  model: Catalyst 9300
  os: Cisco IOS XE
  version: "17.x"
  confidence: 0.994

addresses:
  - 10.10.1.43
  - fe80::a21b:...

services:
  - port: 22
    transport: tcp
    service: ssh
    product: Cisco SSH
    confidence: 0.99

  - port: 443
    transport: tcp
    service: https
    product: Cisco WebUI
    confidence: 0.98

evidence:
  ssh_host_key: ...
  tls_certificate: ...
  snmp_engine_id: ...
  tcp_fingerprint: ...

relationships:
  vlan: 10
  gateway: 10.10.1.1
```

---

# 18. Suggested Internal Architecture

```text
                         NYXR

                     Target Engine
                          │
              ┌───────────┴────────────┐
              │                        │
       Packet Fast Path          Socket Engine
       AF_XDP/gopacket         TCP/UDP/QUIC/TLS
              │                        │
              └───────────┬────────────┘
                          │
                    Observation Bus
                          │
                 Adaptive Probe Planner
                          │
              ┌───────────┼────────────┐
              │           │            │
          Protocol     Fingerprint     OS
           Engine        Engine       Engine
              │           │            │
              └───────────┼────────────┘
                          │
                     Evidence Store
                          │
                     Asset Resolver
                          │
                      Asset Graph
                          │
                ┌─────────┴─────────┐
                │                   │
               CLI                 API
                                    │
                                  Web UI
```

---

# 19. Recommended Implementation Order

If only five major workstreams are selected, implement them in this order:

## Phase 1 — Adaptive Detection Core

Build:

- observation bus
- adaptive probe planner
- confidence engine
- protocol state machine interface
- reusable probe executor

This is the foundation for everything else.

---

## Phase 2 — Nyxr Protocol DSL

Build:

- YAML or custom DSL
- protocol compiler / validator
- TCP support
- UDP support
- STARTTLS
- TLS
- binary parsers
- extraction rules
- branching
- protocol test framework

Move service detection definitions outside the scanner binary.

---

## Phase 3 — Evidence and Asset Identity

Build:

- evidence store
- scan transcripts
- response capture
- confidence explanation
- asset resolver
- identity correlation
- persistent asset IDs

This converts Nyxr from a port scanner into an asset-intelligence engine.

---

## Phase 4 — Deep UDP + QUIC

Implement:

- transaction correlation
- ICMP handling
- adaptive retries
- stateful protocol flows
- DTLS
- QUIC
- HTTP/3

This creates a strong advantage over traditional scanners.

---

## Phase 5 — Linux Performance Backend

Implement:

- AF_XDP
- per-core workers
- RX/TX batching
- preallocated buffers
- RSS queue mapping
- lock-free data structures
- performance benchmarks

Keep gopacket / pcap as the portable fallback.

---

# 20. Secondary Roadmap

After the first five workstreams:

## Phase 6

- passive discovery
- IPv6 discovery
- asset graph enrichment
- TCP stack fingerprinting
- SSH / TLS fingerprinting

## Phase 7

- OT / ICS protocol suite
- BACnet
- Modbus
- S7
- DNP3
- CIP
- OPC UA

## Phase 8

- unknown-protocol classification
- fingerprint clustering
- proprietary-service detection

## Phase 9

- continuous differential scanning
- historical assets
- exposure changes
- alerting

## Phase 10

- distributed Nyxr controller
- remote agents
- scan scheduling
- enterprise scale

---

# 21. CLI Direction

Possible future commands:

```bash
nyxr scan 10.0.0.0/24

nyxr scan 10.0.0.0/24 --deep

nyxr scan 10.0.0.0/24 --udp-deep

nyxr scan 10.0.0.0/24 --identify-assets

nyxr scan 10.0.0.0/24 --evidence

nyxr listen

nyxr scan --learned

nyxr diff scan-old.json scan-new.json

nyxr asset show NYXR-A83F92

nyxr evidence show <service-id>

nyxr probe replay <evidence-id>

nyxr scan 10.0.0.0/8 --distributed
```

---

# 22. Example Future Nyxr Output

Instead of:

```text
318 hosts
1,937 open ports
```

Nyxr should produce:

```text
318 assets discovered
1,937 services discovered

294 products identified
271 versions identified
303 operating systems classified

17 network devices
23 OT devices
14 Kubernetes components
8 databases

3 unknown service families
6 newly exposed services
2 changed SSH identities
1 unexpected BACnet device

Average identification confidence: 96.7%

Packets transmitted:          8,721,441
Application probes:              14,291
Unnecessary probes avoided:     183,922
```

---

# 23. Definition of Success

Nyxr reaches the "top of the mountain" when it can answer more than:

> Which ports are open?

It should answer:

> What assets exist?

> What are they?

> What software and protocols are they running?

> How confident are we?

> What evidence proves it?

> What changed?

> Which systems appear related?

> Which services are unknown but structurally similar?

> Which assets are new, unexpected, exposed, or behaving differently?

That moves Nyxr from a scanner into a full network intelligence platform.

---

# Recommended Top Five

The five highest-value investments are:

1. **Adaptive stateful probe engine + Nyxr Protocol DSL**
2. **Asset Identity Graph**
3. **Native deep UDP + QUIC / HTTP/3**
4. **Evidence / transcript / PCAP architecture**
5. **AF_XDP Linux fast path**

These five features together would create a significantly more differentiated product than simply adding more scan types, ports, payloads, or flags.
