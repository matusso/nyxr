# Raw packet scanning

TCP connect scanning works everywhere without privileges and is the default.
With raw Ethernet access, nyxr can also send its own packets: raw IPv4 TCP SYN,
ARP and NDP neighbor discovery, and ICMP echo.

- [Raw TCP SYN](#raw-tcp-syn)
- [ARP and NDP discovery](#arp-and-ndp-discovery)
- [ICMP echo](#icmp-echo)
- [Platform requirements](#platform-requirements)
- [Packet I/O design](#packet-io-design)
- [Validation status](#validation-status)

## Raw TCP SYN

```sh
sudo nyxr scan --tcp-mode syn --interface eth0 \
  --protocols tcp --ports 80,443 192.0.2.10
```

| Reply | State |
| --- | --- |
| SYN/ACK | `open` |
| Matching RST/ACK | `closed` |
| Matching ICMP destination unreachable | `filtered` |
| No reply before the deadline | `filtered` (timeout) |

Replies must match the target, both ports and a per-probe sequence token
derived with HMAC, so unrelated and late packets are rejected.

**Route and neighbor resolution.** nyxr loads the routing table once, then
resolves each distinct next-hop MAC with ARP before sending. On macOS, a valid
entry for the interface in the ARP cache is reused; otherwise nyxr sends a
padded ARP request and retries silent neighbors. An unresolved next hop
produces a `no-response` observation and no SYN is sent.

| Flag | When to use it |
| --- | --- |
| `--interface` | Always; must be an Ethernet interface |
| `--source-ip` | The interface has several IPv4 addresses. It must belong to the interface |
| `--source-mac` | Windows Npcap adapters whose MAC cannot be read from the OS |
| `--next-hop-mac` | Override automatic resolution. A wrong MAC makes every probe time out |
| `--interface-rate` | Cap raw sends on the interface |

To find the gateway MAC by hand on macOS, run `netstat -rn -f inet` for the
route and `arp -n GATEWAY_IP` for its cached MAC.

**Limits.** Raw SYN supports IPv4 TCP targets only. `ot-safe` always uses
connect mode. `--dry-run` shows the chosen mode and link details; route and
neighbor discovery only happen when the scan runs.

**Performance.** Up to 16,384 probes can be outstanding. Silent probes expire
from a bounded deadline queue, and transmit calls are batched when the rate
allows. A single packet reader feeds bounded queues and reusable decoder
workers, and receive buffers are pooled so receive work does not allocate per
packet.

## ARP and NDP discovery

Find on-link IPv4 neighbors with ARP, or IPv6 neighbors with NDP. Results
include the verified MAC address:

```sh
sudo nyxr scan --profile custom --protocols arp --interface eth0 --timeout 1s 192.0.2.10
sudo nyxr scan --profile custom --protocols ndp --interface eth0 --timeout 1s 2001:db8:1::10
```

ARP uses a separate receive handle from SYN capture. MAC addresses feed the
[device fingerprint](ot-and-iot.md#device-fingerprinting) stage as OUI evidence.

## ICMP echo

`--protocols icmp` sends IPv4 or IPv6 echo requests over raw sockets, which
usually need elevated privileges on every platform. A missing permission is
reported as an observation; nyxr does not silently switch scan methods.

## Platform requirements

| Platform | Backend | Requirement |
| --- | --- | --- |
| Linux | AF_PACKET | Root or `CAP_NET_RAW`, and an Ethernet interface |
| macOS | `/dev/bpf` | Access to a free BPF device, and an Ethernet interface |
| Windows | Npcap (`wpcap.dll`, loaded at runtime) | Npcap installed; the adapter must expose Ethernet frames |

**Windows adapter names.** Npcap adapter IDs (`\Device\NPF_{GUID}`) can differ
from OS interface names. Pass the Npcap adapter ID to `--interface`, and set
both `--source-ip` and `--source-mac`. If the adapter cannot be mapped to an OS
route, also set `--next-hop-mac`.

To run raw scans without giving privileges to the scanner itself, use
[`nyxr-packetd`](deployment.md#privilege-separation-with-nyxr-packetd):

```sh
nyxr scan --packetd /run/nyxr/packetd.sock --tcp-mode syn --interface eth0 192.0.2.10
```

## Packet I/O design

The receive path uses `gopacket.DecodingLayerParser` with preallocated
Ethernet, VLAN, IPv4/IPv6, TCP, UDP and ICMP layers, not the general-purpose
`PacketSource`. The packet I/O interface moves batches of raw Ethernet frames
and keeps acquisition separate from decoding, so every backend (AF_PACKET, BPF,
Npcap, packetd) shares one frame-to-decoder contract. The decoder expects
Ethernet frames, optionally VLAN-tagged; other link types are not supported.

The design rationale is in [Architecture](../architecture/overview.md).

## Validation status

The raw path has deterministic PCAP fixtures, fake-responder fault tests, fuzz
targets and cross-builds for all six release targets. A macOS BPF
open-and-timeout smoke test has passed. Live receive and transmit on BPF and
Npcap, privileged Linux scanning and real NIC drop measurements are still
pending; see [Runtime gates](../development/runtime-gates.md) and
[Performance](../development/performance.md).
