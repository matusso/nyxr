# UDP scanning

UDP is a first-class engine in nyxr. Instead of guessing from silence, it sends
protocol payloads, validates replies against what was sent, correlates ICMP
errors to individual probes, and states how confident each result is.

- [How results are classified](#how-results-are-classified)
- [Probe strategies](#probe-strategies)
- [Built-in probe catalog](#built-in-probe-catalog)
- [QUIC and HTTP/3](#quic-and-http3)
- [DTLS](#dtls)
- [IKE and IPsec VPNs](#ike-and-ipsec-vpns)
- [Custom payloads](#custom-payloads)
- [Native probe definitions](#native-probe-definitions)
- [Using Nmap UDP probes](#using-nmap-udp-probes)
- [Platform behavior and limits](#platform-behavior-and-limits)

## How results are classified

| Result | Meaning | Confidence |
| --- | --- | --- |
| `open`, validated service | A reply matched the probe's protocol and, where the protocol has one, its transaction token | 100% |
| `open`, protocol-shaped | A reply has the protocol's shape, but no transaction token to correlate it | 85% |
| `open`, socket-scoped | A reply arrived on the probe's socket, but the probe identity is unconfirmed | 80% |
| `open`, `unknown` fingerprint | A datagram came back that no matcher recognized; a hex sample is kept as evidence | 75% |
| `closed` | ICMP port unreachable for this probe | 95% |
| `filtered` | ICMP network or host unreachable | 85% |
| `open\|filtered` | No UDP or ICMP reply. The port may be open and silent, or filtered | 30% |

A silent port is never reported as definitely open. An empty datagram is a
valid probe under [RFC 768](https://www.rfc-editor.org/rfc/rfc768), and
[RFC 1122](https://www.rfc-editor.org/rfc/rfc1122) only says a closed port
*should* answer with ICMP port unreachable, so silence is inconclusive.

**Transaction tokens.** Where a protocol carries a request identifier, nyxr
derives it from a per-scan secret and requires the reply to echo it: the DNS
transaction ID, NTP originate timestamp, SNMP request or message ID, STUN
transaction ID, SIP Call-ID and CoAP token. Replies without a token (for
example BACnet I-Am) are accepted with lower confidence.

**ICMP correlation.** With raw-socket permission, one shared ICMPv4/ICMPv6
listener matches each error to the probe it quotes, using addresses, ports,
length and checksum. Without that permission the result notes that raw ICMP is
unavailable, and connected UDP sockets still classify port-unreachable errors
when the OS delivers them.

**Adaptive retries.** `--udp-retries` sets extra attempts per probe. When
feedback on a host suggests loss or ICMP rate limiting, later ports on that host
get one additional adaptive retry. `--rate` counts retries too.

## Probe strategies

| Profile | What is sent |
| --- | --- |
| `udp-basic` | An empty datagram per port |
| `udp-common` | The payloads listed for each requested port; an empty datagram when none apply; QUIC service probing on hinted ports |
| `udp-full` | Every available payload on every requested port, until a reply validates a service or the catalog is exhausted; QUIC service probing on hinted ports |

All three select the 32 UDP ports of the `udp` port set by default. `--ports`
replaces that list. `udp-full` retries each probe once.

```sh
nyxr scan --profile udp-basic --ports 53,123 192.0.2.1
nyxr scan --profile udp-common 192.0.2.1
nyxr scan --profile udp-full --udp-retries 1 --json 192.0.2.1
nyxr scan --profile udp-full --dry-run 192.0.2.0/28
```

## Built-in probe catalog

All built-in probes are read-only requests.

| Area | Protocols |
| --- | --- |
| Name services | DNS status, A/NS lookup and CHAOS TXT `version.bind`; mDNS; LLMNR; NBNS |
| Network infrastructure | DHCP, NTPv2/v3/v4, SNMPv1/v2c/v3 (engine discovery), TFTP, RPC, SLP, IKE, L2TP, RADIUS authentication and accounting |
| Directory and auth | Kerberos, CLDAP root DSE search |
| Discovery and IoT | SSDP, CoAP GET, STUN |
| Building automation | BACnet Who-Is, Device property reads, BBMD Foreign Device Table |
| Management | IPMI, Citrix, DB2 |
| Voice and media | SIP OPTIONS |
| Games | Source, Quake, GameSpy, TeamSpeak |
| Other | memcached, empty datagram |

A few protocol notes:

- **DHCP.** DHCPDISCOVER goes to server port 67; port 68 is the client reply
  port. nyxr listens on 68 for offers when it can bind it and falls back to an
  ephemeral port otherwise.
- **LDAP.** LDAP bind is a TCP operation, so the UDP catalog uses a
  connectionless LDAP (CLDAP) search instead. `cldap.attributes` records the
  root DSE attributes returned, including naming contexts and capabilities.
- **RADIUS accounting (1813).** The probe is a deliberately unauthenticated
  accounting-shaped request. A reply identifies RADIUS; silence remains
  `open|filtered`, because compliant servers may discard it without a shared
  secret.
- **TFTP.** Replies from the server's new transfer port are accepted.
- **SOCKS** is a TCP protocol and is identified by the
  [service stage](service-identification.md#socks), not here.
- **Games.** GameSpy and Quake port lists are hints; `udp-full` tries those
  payloads on every selected port.

BACnet behavior is described in [OT and IoT](ot-and-iot.md#bacnet).

## QUIC and HTTP/3

`udp-common`, `udp-full`, and `deep-scan` run a native QUIC handshake on
UDP/443, 4433, and 8443 after discovery, including ports classified
`open|filtered` because ordinary UDP payloads received no reply. A completed
handshake upgrades the service observation to `open`. The probe negotiates
HTTP/3, records the negotiated QUIC version, version negotiation when it
occurs, connection IDs, peer transport parameters, TLS 1.3 details and
certificate chain, ALPN, peer datagram support, and HTTP/3 SETTINGS. It then
sends a read-only `HEAD /` and records the status, `Server`, and `Alt-Svc`
headers when returned.

```sh
nyxr scan --profile udp-common --ports 443 --json 192.0.2.10
```

To try QUIC on other UDP ports, enable the service stage and select `quic` as
the fallback probe:

```sh
nyxr scan --protocols udp --ports 7443 --service \
  --service-probes quic --service-fallback quic --json 192.0.2.10
```

The probe accepts self-signed or name-mismatched certificates so it can report
their identity. Its certificate fields describe what the peer presented; they
do not assert certificate trust. The HTTP/3 `extended_connect` and datagram
settings identify prerequisites for WebTransport, not a verified WebTransport
endpoint. 0-RTT eligibility is not yet reported.

## DTLS

The same UDP profiles perform a DTLS handshake on UDP/5684 and 5349. A valid
handshake identifies the service as `dtls`, upgrades the port to `open`, and
records its cipher suite, ALPN and presented certificates without sending
application data. To try another port, use `--service-probes dtls
--service-fallback dtls` with `--protocols udp` and `--service`. The current
DTLS library does not expose the negotiated DTLS version, so nyxr reports
`DTLS` without a version number.

## IKE and IPsec VPNs

Discovery sends an IKEv1 Main Mode offer and an IKEv2 IKE_SA_INIT to UDP/500
and, behind the RFC 3948 four-byte non-ESP marker, to UDP/4500. `udp-full`
tries all four on every port. A reply counts only when it echoes the probe's
random initiator SPI with the same IKE major version.

The requests follow the NAT traversal RFCs (RFC 3715 states the problem):

- IKEv1 Main Mode carries the RFC 3947 and draft NAT-T vendor IDs, which
  RFC 3947 3.1 requires in the first two Phase 1 messages.
- IKEv2 IKE_SA_INIT carries `NAT_DETECTION_SOURCE_IP` and
  `NAT_DETECTION_DESTINATION_IP`, SHA-1 of SPIi, SPIr, IP and port
  (RFC 7296 2.23).
- RFC 3947 3 and RFC 7296 2.23 require responders to accept any source port
  and reply to it, so probing through NAT works. Responders that support NAT
  traversal must also accept negotiations that begin on 4500 (RFC 3947 4).

The probes still send from UDP/500 (plain) and UDP/4500 (NAT-T) for gateways
that ignore that rule. Binding them needs root; without it, or when a local
IPsec daemon owns the port, nyxr falls back to an ephemeral port.

With `--fingerprint` (or `--service`), the `ike` service probe tries IKEv1 then
IKEv2, plain then NAT-T framed (NAT-T first on 4500). When IKEv1 answers it
also asks IKEv2 on the same framing, so `ike.versions` says which versions the
gateway speaks. Both offers are broad (ike-scan style for IKEv1; AES-CBC,
3DES, SHA1/SHA2 and MODP/ECP/Curve25519 groups for IKEv2), so a gateway
either accepts one or says why not.

When the gateway accepts an offer, the probe continues as far as it can
without a credential:

- **IKEv1** sends Main Mode message 3 (key exchange, nonce and, if the gateway
  announced NAT-T, the RFC 3947 NAT-D payloads) and decodes message 4: the
  gateway's NAT-D pair, a certificate request and the vendor IDs many
  gateways only send there. Message 5 needs the pre-shared key or
  certificate, so the probe stops.
- **IKEv1 Aggressive Mode** is then requested as a separate negotiation, in
  the group Main Mode settled on (MODP-1024 otherwise), offering AES/3DES
  with SHA2-256/SHA1/MD5 for pre-shared key and XAUTH, with the identity
  `KEY_ID vpn`. A gateway that accepts returns its identity and, with a
  pre-shared key, `HASH_R`. That hash is computed from the key and values
  visible on the wire, so anyone who can send this request can test key
  guesses offline: report it as a finding. nyxr records the hash and does
  not attempt to recover the key.
- **IKEv2** completes the Diffie-Hellman exchange (MODP-1024/2048/3072,
  ECP-256/384 or Curve25519), returning a `COOKIE` or switching to the group
  named by `INVALID_KE_PAYLOAD` when asked. It then sends one encrypted
  `IKE_AUTH` without an AUTH payload, which requests EAP (RFC 7296 2.16). No
  credential is offered. The gateway answers with its identity, certificate
  and EAP method, or with an encrypted error such as `AUTHENTICATION_FAILED`.
  The probe announces `IKEV2_FRAGMENTATION_SUPPORTED` and reassembles a
  reply sent as RFC 7383 encrypted fragments. When the reply carries a
  certificate and an AUTH payload, the signature is checked against that
  certificate (RSA, or ECDSA P-256/384/521). `verified` means the gateway
  holds the certificate's private key; the chain is not validated. The probe
  then sends a Delete so the gateway does not keep a half-open SA.

Following RFC 7296 2.23, a gateway probed on UDP/500 that supports NAT
detection is sent `IKE_AUTH` on UDP/4500 behind the non-ESP marker, and on 500
again if 4500 stays silent.

| Attribute | Example |
| --- | --- |
| `banner` | `VPN (IKE NAT-T)` |
| `ike.versions` | `1,2` |
| `ike.initiator_spi`, `ike.responder_spi` | `46fba3402687e27c`, `b969545c24a005ca` |
| `ike.next_payload` | `Notification (N)` |
| `ike.version` | `1.0` |
| `ike.exchange_type` | `Informational`, `Identity Protection (Main Mode)`, `IKE_SA_INIT` |
| `ike.flags.*` | IKEv1 `encryption`, `commit`, `authentication`; IKEv2 `initiator`, `version`, `response` |
| `ike.message_id`, `ike.length` | `76b5df1e`, `40` |
| `ike.transform` | the proposal the gateway accepted, e.g. `3DES/SHA1/PSK/MODP-1024` or `AES-CBC-256/HMAC-SHA2-256/HMAC-SHA2-256-128/MODP-2048` |
| `ike.lifetime`, `ike.ke_group` | `28800s`, `MODP-2048` |
| `ike.notify` | `NO-PROPOSAL-CHOSEN`, `INVALID_KE_PAYLOAD (wants ECP-256)`, `IKEV2_FRAGMENTATION_SUPPORTED` |
| `ike.vendor_ids`, `ike.vendors` | raw Vendor ID payloads and their names |
| `ike.product` | implementation named by a Vendor ID, with version when encoded |
| `ike.nat_t_support` | `RFC 3947 NAT-T` or a draft (IKEv1 vendor ID), or `RFC 7296 NAT detection` |
| `ike.nat.scanner` | `direct` or `behind NAT`: whether the gateway saw nyxr's own address and port |
| `ike.nat.gateway` | `direct` or `behind NAT`: whether the gateway's own address is the scanned one (a port-forwarded gateway reports `behind NAT`) |
| `ike.nat.gateway_internal` | `10.20.0.5:500`: the address a NATed gateway hashed into its NAT detection payload |
| `ike.main_mode_message` | `4` when the IKEv1 gateway answered message 3 |
| `ike.ke.notify` | the IKEv1 gateway's error to message 3, e.g. `INVALID-KEY-INFORMATION` |
| `ike.aggressive` | `accepted` or `refused`, when the gateway answered the Aggressive Mode request |
| `ike.aggressive.transform`, `.id`, `.hash`, `.notify` | the accepted transform, the gateway's identity, `HASH_R` in hex, or its refusal |
| `ike.key_exchange` | `completed` when the IKEv2 `IKE_AUTH` reply decrypted and verified |
| `ike.fragments` | number of RFC 7383 fragments the `IKE_AUTH` reply arrived in |
| `ike.auth.signature` | `verified`, `invalid` or `not checked` (RFC 7427 digital signatures) |
| `ike.auth.port`, `ike.auth.notify` | port that answered `IKE_AUTH`, and its notifies, e.g. `AUTHENTICATION_FAILED` |
| `ike.id` | the gateway's identity, e.g. `FQDN vpn.example.com` |
| `ike.auth_method`, `ike.eap` | `RSA signature`; `Request Identity`, `Request MSCHAPv2` |
| `ike.cert.subject`, `.issuer`, `.names`, `.not_after`, `.sha256` | the gateway's end-entity certificate |
| `ike.certreq`, `ike.certreq.ca_key_hashes` | `X.509, 1 CA` and the SHA-1 of each CA key the gateway trusts (IKEv2), or the CA name (IKEv1) |
| `ike.additional_addresses` | other addresses a MOBIKE gateway lists |
| `ike.v2.*` | the IKEv2 answer when IKEv1 answered first |

Vendor IDs are matched against MD5 digests of their defining strings (NAT-T
RFC and drafts, strongSwan, Microsoft, Cisco Unity, XAUTH, fragmentation),
a few fixed vendor prefixes (Dead Peer Detection, Check Point, FortiGate), and
about 115 further IDs taken from Nmap's `ike-fingerprints.lua` (Juniper and
NetScreen, SonicWall, ZyXEL, Cisco VPN Concentrator, SSH Sentinel/QuickSec,
FreeS/WAN, Openswan, StoneGate, SafeNet, Nortel, KAME/racoon and more).
Versions come from the ID itself: strongSwan `MD5("strongSwan X.Y.Z")`, the
Windows release number after `MS NT5 ISAKMPOAKLEY`, Check Point's version
code, and versioned IDs in the table. Plain-text IDs such as Cisco's
`FLEXVPN-SUPPORTED` are shown as text. The product and version also fill the
service's `product` and `version`.

The probe runs on UDP/500 and 4500, and on any other port where discovery
already validated an IKE reply. Use `--service-fallback ike` to try it on every
open UDP port.

**Internal address recovery.** A NAT detection hash covers only the SPIs, an
address and a port (SHA-1 in IKEv2, the negotiated hash in IKEv1), and the
SPIs are on the wire. When a gateway turns out to be behind NAT, nyxr hashes
every address in 192.168.0.0/16, 172.16.0.0/12, 100.64.0.0/10 and 10.0.0.0/8
with the scanned port, 500 and 4500 until one matches, which costs a second
or two of CPU per NATed gateway when nothing matches.

For a gateway scanned over IPv6 it first tries IPv6 candidates, then the IPv4
ranges above (the gateway may be an IPv4 host behind NAT64 or a dual-stack
load balancer). IPv6 space cannot be searched: a proper unique local prefix
has 40 random bits. So only hand-typed prefixes are tried, `fd00:0:0:S::/64`
for S up to `ff`, `fc00::/64` and `fec0::/64`, each with the scanned
address's interface ID (NPTv6 preserves it) and the interface IDs `::1` to
`::ffff`. Expect IPv6 recovery to miss on well-run networks.

Limits: nyxr does not try to recover a pre-shared key from an Aggressive Mode
hash, does not parse RFC 7427 digital signatures (it does not request them),
and does not validate certificate chains. IKEv1 leaves half-open SAs on the
gateway until its timeout (one for Main Mode, one for Aggressive Mode), so
scanning one gateway repeatedly in a short time can trip its per-peer limit
(strongSwan blocks a peer at five).

## Custom payloads

Choose exactly one of the following. A custom payload replaces the built-in
probes for that scan.

| Flag | Payload source |
| --- | --- |
| `--payload file.yaml` | A [native probe definition](#native-probe-definitions) |
| `--send-hex 010203` | Hex bytes |
| `--send-base64 AQID` | Base64 bytes |
| `--payload-file probe.bin` | Raw bytes from a file |

```sh
nyxr scan --protocols udp --ports 9999 --send-hex "010203" 192.0.2.1
nyxr scan --protocols udp --ports 9999 --payload my-probe.yaml 192.0.2.1
```

## Native probe definitions

A native definition can target particular ports and set its own timeout,
retries, matchers and extracted fields:

```yaml
schema: nyxr/udp/v1
name: sample-discovery
transport: udp
ports: [9999]
tags: [discovery]
safety: safe
payload:
  encoding: hex
  data: "01020304"
timeout: 750ms
retries: 1
match:
  - type: any
```

| Field | Notes |
| --- | --- |
| `schema` | Optional; defaults to `nyxr/udp/v1`. Unknown versions are rejected |
| `ports` | Ports the probe applies to. A probe with no applicable port falls back to the empty datagram |
| `safety` | Only `safe` is accepted |
| `payload.encoding` | `ascii`, `hex`, `base64`, or `raw_file` (path relative to the YAML file) |
| `source_port` | Local port to send from, for services that only answer peers on a fixed port. Ports below 1024 need root; when the port cannot be bound nyxr sends from an ephemeral port |
| `match[].type` | `any`, `dns`, `dns-status`, `dhcp`, `nbns`, `kerberos`, `cldap`, `radius`, `ike`, `ike-nat-t`, `l2tp`, `snmpv1`, `ntp`, `snmp`, `snmpv3`, `stun`, `tftp`, `ssdp`, `sip`, `coap`, `bacnet`, `bacnet-read`, `bacnet-fdt`, `rpc`, `slp`, `ipmi`, `citrix`, `db2`, `source`, `quake`, `gamespy`, `teamspeak`, `memcached` |
| `extract` | Fields to copy into the observation's `fields` map (below) |

Extractable fields:

| Field | Source |
| --- | --- |
| `dns.rcode`, `dns.txt` | DNS reply code and TXT data |
| `cldap.attributes` | Root DSE attributes |
| `ntp.stratum` | NTP stratum |
| `stun.message_type` | STUN message type |
| `snmp.engine_id` | SNMP engine ID |
| `tftp.error_code` | TFTP error code |
| `ssdp.server` | SSDP `SERVER` header |
| `sip.status` | SIP status line |
| `coap.code` | CoAP response code |
| `bacnet.device_id`, `bacnet.vendor_id`, `bacnet.fdt_entries` | BACnet identity and FDT |

Some matchers add fields automatically. A valid SNMPv3 Report adds
`snmp.version`, `snmp.enterprise`, `snmp.engine_id_format`,
`snmp.engine_id_data`, `snmp.engine_boots`, `snmp.engine_time_seconds` and
`snmp.engine_time`. BACnet enrichment adds `bacnet.object_name`,
`bacnet.vendor_name`, `bacnet.application_software`, `bacnet.firmware`,
`bacnet.model_name`, `bacnet.description` and `bacnet.location`, and FDT
entries appear as `bacnet.fdt.0`, `bacnet.fdt.1` and so on.

A scan configuration file can name a definition with `udp_probe_file`.

## Using Nmap UDP probes

`--nmap-udp-probes FILE` adds the UDP payloads from a local
`nmap-service-probes` file to the built-in catalog:

```sh
nyxr scan --profile udp-full --nmap-udp-probes /usr/share/nmap/nmap-service-probes \
  --ports 111,2049,47808 192.0.2.10
```

- `udp-common` uses the file's `ports` directives to select probes; probes
  without ports apply to any port.
- `udp-full` tries every imported probe on each requested port and uses the
  port directives only to order them.
- Empty requests and requests larger than the maximum UDP payload are skipped.
- Any datagram returned to an imported request confirms the port is open, but
  without a protocol-specific matcher the service identity stays unconfirmed.
- The option needs a local file, cannot be combined with a custom payload, is
  never allowed by `ot-safe`, and cannot be used through the remote API.

The license boundary is described in
[Nmap interoperability](service-identification.md#nmap-service-probe-interoperability).

## Platform behavior and limits

- Port-unreachable reporting depends on the operating system and firewall. A
  silent or rate-limited ICMP path leaves results `open|filtered`.
- Raw ICMP correlation has fixture tests but still needs privileged live gates
  on Linux, macOS and Windows.
- The protocol matchers have packet fixtures; most have no live device gate
  yet. BACnet has simulator fixtures and one live controller check.

Current validation status is tracked in the [Roadmap](../roadmap.md).
