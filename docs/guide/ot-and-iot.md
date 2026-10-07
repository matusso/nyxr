# OT and IoT

Industrial and embedded devices often react badly to aggressive scanning. nyxr
treats them as a separate case: the `ot-safe` profile enforces an allowlist,
low rates and read-only identity requests, and the device fingerprint stage
only classifies a device when independent signals agree.

- [The `ot-safe` profile](#the-ot-safe-profile)
- [Industrial identity probes](#industrial-identity-probes)
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
| Ports | 80, 443, 502 and 44818 only |
| Rate | 1 to 5 connection attempts per second |
| Concurrency | At most four workers |
| Timeout | Discovery timeout of at least three seconds |
| Service probes | Only the Modbus and EtherNet/IP identity reads |

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
| BACnet | Who-Is, then read-only Device property reads | UDP/47808 |

Modbus and EtherNet/IP return product and version fields with the raw exchange
as evidence. The requests follow the
[Modbus application and TCP/IP guides](https://www.modbus.org/modbus-specifications)
and [ODVA's ListIdentity format](https://jp.odva.org/wp-content/uploads/2020/05/PUB00081R1_Performance_Methodology_v1.0.pdf).

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

The Modbus, EtherNet/IP and BACnet probes have local simulator fixtures. A live
scan of a Siemens PXC22.1-E.D building controller returned its Device
identifier, name, vendor, application software, firmware, model, description
and one FDT entry. Broader live testing on representative OT equipment, a
vendor OUI database and more industrial protocols are on the
[Roadmap](../roadmap.md#phase-4--iot-and-ot-safety--partial).
