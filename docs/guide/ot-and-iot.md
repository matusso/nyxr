# OT and IoT

Industrial and embedded devices often react badly to aggressive scanning. nyxr
treats them as a separate case: the `ot-safe` profile enforces an allowlist,
low rates and read-only identity requests, and the device fingerprint stage
only classifies a device when independent signals agree.

- [The `ot-safe` profile](#the-ot-safe-profile)
- [Industrial identity probes](#industrial-identity-probes)
- [Siemens S7](#siemens-s7)
- [OPC UA](#opc-ua)
- [BACnet](#bacnet)
- [Device fingerprinting](#device-fingerprinting)
- [Validation status](#validation-status)

## The `ot-safe` profile

```sh
nyxr scan --profile ot-safe --allow-targets 192.0.2.0/24 --dry-run 192.0.2.10
nyxr scan --profile ot-safe --allow-targets 192.0.2.0/24 --json 192.0.2.10
```

`ot-safe` refuses to run unless every rule below holds:

| Rule | Value |
| --- | --- |
| Target allowlist | `--allow-targets` (IPs or CIDRs) is required, and every resolved target must be inside it |
| Protocol | TCP connect only. UDP, ICMP, raw SYN and custom payloads are rejected |
| Ports | 80, 102, 443, 502, 4840 and 44818 only |
| Rate | 1 to 5 connection attempts per second |
| Concurrency | At most four workers |
| Timeout | Discovery timeout of at least three seconds |
| Service probes | Only the Modbus, EtherNet/IP, S7 and OPC UA identity reads |

The service stage runs *after* discovery, so its separately paced identity
reads never overlap discovery traffic. `--dry-run --json` shows the allowlist
and the service plan.

For packet-level audit evidence, add `--pcapng` and `--interface` with capture
privileges. Without capture, the record stream still reports every discovery
attempt and keeps the request and response bytes of each identity read.

## Industrial identity probes

| Protocol | Request | Port |
| --- | --- | --- |
| Modbus | Function 43 / MEI 14, Read Device Identification (basic) | TCP/502 |
| EtherNet/IP | ListIdentity | TCP/44818 |
| Siemens S7 | COTP connect, Setup Communication, read SZL 0x0011 and 0x001C | TCP/102 |
| OPC UA | Hello, OpenSecureChannel (None), GetEndpoints, CloseSecureChannel | TCP/4840 |
| BACnet | Who-Is, then read-only Device property reads | UDP/47808 |

Modbus and EtherNet/IP return product and version fields with the raw exchange
as evidence. The requests follow the
[Modbus application and TCP/IP guides](https://www.modbus.org/modbus-specifications)
and [ODVA's ListIdentity format](https://jp.odva.org/wp-content/uploads/2020/05/PUB00081R1_Performance_Methodology_v1.0.pdf).

### Policy review for S7 and OPC UA

Both probes were added to the `ot-safe` allowlist after checking scope, rate
and read-only behavior:

- **Scope.** They run only on ports the operator lists, against addresses
  inside `--allow-targets`, after discovery has finished.
- **Rate.** S7 opens at most two connections per port (one per rack/slot
  attempt) and OPC UA one. Both count against the 1–5 connections per second
  and four-worker caps; S7 has a 4-second and OPC UA a 5-second budget per
  connection.
- **Read-only.** S7 sends only a connection request, Setup Communication and
  two SZL reads. It never reads or writes process memory, never changes the
  CPU mode and never supplies a password. OPC UA calls only the GetEndpoints
  discovery service. It never creates or activates a session, presents
  credentials, or reads or writes the address space.
- **No experiments.** The probes are fixed exchanges. HORIZON experiment
  policies stay separate, and `ot-safe` enables none of them.

Every byte sent is kept in the observation's evidence (`request`), so the
transmitted probes can be audited against this list.

## Siemens S7

The S7 probe speaks S7comm over ISO-on-TCP
([RFC 1006](https://www.rfc-editor.org/rfc/rfc1006)):

1. COTP connection request to rack 0, slot 2 (S7-300/400). If the CPU answers
   at the COTP layer but refuses that TSAP, one more connection tries slot 1
   (S7-1200/1500). A peer that does not speak COTP gets no second attempt.
2. Setup Communication, which negotiates the PDU size.
3. Read SZL 0x0011 (module identification) and 0x001C (component
   identification), index 0.

| Attribute | Source |
| --- | --- |
| `s7.module`, `s7.hardware` | SZL 0x0011 order numbers (MLFB) of the module and hardware |
| `s7.firmware` | SZL 0x0011 firmware version, for example `V2.9.4` |
| `s7.system_name`, `s7.module_name`, `s7.plant_id`, `s7.serial`, `s7.module_type`, `s7.memory_serial`, `s7.location` | SZL 0x001C component identification |
| `s7.rack`, `s7.slot`, `s7.pdu_size` | The TSAP that accepted the connection and the negotiated PDU size |
| `s7.partial` | Why a list was refused, malformed or fragmented |

`product` is the module type name, or the order number when there is none.
`version` is the firmware version. A field the CPU does not send is left
out, never filled with a default. Further SZL fragments are not requested;
`s7.partial` says when the CPU had more.

## OPC UA

The OPC UA probe is a discovery client for the binary `opc.tcp` protocol. It
uses the operator's hostname in the endpoint URL when there is one. It reads
the server's endpoint descriptions and stops:

| Attribute | Meaning |
| --- | --- |
| `opcua.access` | Always `discovery`: no session was created and no credentials were used |
| `opcua.application_uri`, `opcua.product_uri`, `opcua.application_name`, `opcua.application_type` | Server application description |
| `opcua.endpoint_url`, `opcua.endpoint_count` | First endpoint URL and the number of endpoints |
| `opcua.security_modes`, `opcua.security_policies` | Offered message security modes and policies |
| `opcua.user_token_types` | Advertised login methods (`anonymous`, `username`, `certificate`, `issued-token`) |
| `opcua.anonymous_offered` | Whether an endpoint advertises anonymous access. This is policy text, not a login test |
| `opcua.certificate_sha256`, `opcua.certificate_subject`, `opcua.certificate_not_after` | First application instance certificate |

`product` is the application name. Product versions come from the server's
BuildInfo, which can only be read inside a session, so `version` stays empty.
Authenticated access is outside the probe's scope. An OPC UA server is not
treated as proof of a controller: device fingerprinting counts S7, Modbus and
EtherNet/IP as industrial-device evidence, but not OPC UA alone.

## BACnet

BACnet is a UDP protocol, so it runs through the UDP profiles rather than
`ot-safe`, which is TCP-only:

```sh
nyxr scan --profile udp-common --ports 47808 --fingerprint --json 192.0.2.10
```

`udp-common` sends a BACnet Who-Is on UDP/47808; `udp-full` tries it on every
requested UDP port. The sequence is:

1. **Who-Is.** Unicast or broadcast I-Am replies are parsed for the device and
   vendor IDs.
2. If Who-Is is silent, a read-only Device object-identifier query and a BBMD
   Foreign Device Table (FDT) read.
3. Once a reply confirms the port is open, read the Device name, vendor,
   application software, firmware, model, description and location
   properties, plus the FDT when available.

Missing optional replies leave the validated open result intact. nyxr prefers
local UDP/47808 as the source port for these IPv4 probes and uses an ephemeral
port if 47808 is busy. I-Am and FDT responses carry no transaction token, so
their confidence is lower than token-validated replies. The FDT timeout shown is
the time remaining at the moment of the scan and changes between runs.

The requests follow the
[BACnet Who-Is/I-Am encoding examples](https://bacnet.org/wp-content/uploads/sites/4/2022/08/Encoding.pdf).
The extracted fields are listed in [UDP scanning](udp.md#native-probe-definitions).

## Device fingerprinting

`--fingerprint` combines independent observations into a `device` record. The
`iot` profile enables it by default.

```sh
nyxr scan --profile iot --fingerprint --json 192.0.2.10
```

Signals it can combine:

- Matched service identities (TCP service stage)
- UDP identities: BACnet, SNMP, mDNS, SSDP and CoAP
- MAC OUI prefixes from ARP or NDP discovery
- Open port patterns
- Native TCP/IP stack hypotheses from [raw SYN fingerprinting](tcp-stack-fingerprinting.md)

A device record is emitted only when **at least two independent signals**
support the claim. The record carries the class, the confidence and the
contributing signals. A port alone never claims a device type. An OUI prefix
is kept as evidence and is not expanded into a vendor name, because nyxr does
not ship a vendor database.

Run `--fingerprint` with a UDP profile to include BACnet, SNMP, mDNS, SSDP and
CoAP observations from the same scan.

## Validation status

The Modbus, EtherNet/IP, BACnet, S7 and OPC UA probes have local simulator
tests, including refused, truncated, malformed and canceled exchanges. S7 and
OPC UA were also checked against independent implementations: the
python-snap7 3.3.0 server and an asyncua 2.1.0 server (scripts in
`tests/lab/ot/`). The snap7 server's non-standard SZL 0x001C reply is reported
as partial rather than guessed. S7 and OPC UA have not yet been validated
against live Siemens CPUs or production OPC UA servers. A live
scan of a Siemens PXC22.1-E.D building controller returned its Device
identifier, name, vendor, application software, firmware, model, description
and one FDT entry. Broader live testing on representative OT equipment, a
vendor OUI database and more industrial protocols are on the
[Roadmap](../roadmap.md#phase-4--iot-and-ot-safety--partial).
