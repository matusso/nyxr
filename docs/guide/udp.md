# UDP scanning

UDP is a first-class engine in nyxr. Instead of guessing from silence, it sends
protocol payloads, validates replies against what was sent, correlates ICMP
errors to individual probes, and states how confident each result is.

- [How results are classified](#how-results-are-classified)
- [Probe strategies](#probe-strategies)
- [Built-in probe catalog](#built-in-probe-catalog)
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
| `udp-common` (and `udp`) | The payloads listed for each requested port; an empty datagram when none apply |
| `udp-deep` | Every available payload on every requested port, until a reply validates a service or the catalog is exhausted |

`udp-common` and `udp-deep` select 32 common UDP ports by default. `--ports`
replaces that list. `udp-deep` retries each probe once.

```sh
nyxr scan --profile udp-basic --ports 53,123 192.0.2.1
nyxr scan --profile udp-common 192.0.2.1
nyxr scan --profile udp-deep --udp-retries 1 --json 192.0.2.1
nyxr scan --profile udp-deep --dry-run 192.0.2.0/28
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
- **Games.** GameSpy and Quake port lists are hints; `udp-deep` tries those
  payloads on every selected port.

BACnet behavior is described in [OT and IoT](ot-and-iot.md#bacnet).

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
| `match[].type` | `any`, `dns`, `dns-status`, `dhcp`, `nbns`, `kerberos`, `cldap`, `radius`, `ike`, `l2tp`, `snmpv1`, `ntp`, `snmp`, `snmpv3`, `stun`, `tftp`, `ssdp`, `sip`, `coap`, `bacnet`, `bacnet-read`, `bacnet-fdt`, `rpc`, `slp`, `ipmi`, `citrix`, `db2`, `source`, `quake`, `gamespy`, `teamspeak`, `memcached` |
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
nyxr scan --profile udp-deep --nmap-udp-probes /usr/share/nmap/nmap-service-probes \
  --ports 111,2049,47808 192.0.2.10
```

- `udp-common` uses the file's `ports` directives to select probes; probes
  without ports apply to any port.
- `udp-deep` tries every imported probe on each requested port and uses the
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
