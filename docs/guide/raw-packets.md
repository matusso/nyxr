# Raw packet scanning

TCP connect scanning works everywhere without privileges and is the default.
With raw Ethernet access, nyxr can also send its own packets: raw IPv4 and
IPv6 TCP SYN, ARP and NDP neighbor discovery, and ICMP echo.

- [Raw TCP SYN](#raw-tcp-syn)
- [IPv6 raw SYN](#ipv6-raw-syn)
- [ARP and NDP discovery](#arp-and-ndp-discovery)
- [ICMP echo](#icmp-echo)
- [Platform requirements](#platform-requirements)
- [Linux AF_XDP](#linux-af_xdp)
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
| Matching ICMP or ICMPv6 destination unreachable | `filtered` |
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
| `--source-ip` | The interface has several IPv4 addresses, or you want one fixed IPv6 source. It must belong to the interface |
| `--source-mac` | Windows Npcap adapters whose MAC cannot be read from the OS |
| `--next-hop-mac` | Override automatic resolution. A wrong MAC makes every probe time out |
| `--interface-rate` | Cap raw sends on the interface |

To find the gateway MAC by hand on macOS, run `netstat -rn -f inet` for the
route and `arp -n GATEWAY_IP` for its cached MAC.

**Limits.** Raw SYN scans TCP only. `ot-safe` always uses connect mode. `--dry-run` shows the chosen mode and link details; route and
neighbor discovery only happen when the scan runs.

Add `--fingerprint` to offer TCP options and retain SYN/ACK and RST/ACK
header evidence with native OS-family hypotheses. Results wait until the
original probe deadline. See [TCP/IP stack fingerprinting](tcp-stack-fingerprinting.md).

**Performance.** Up to 16,384 probes can be outstanding. Silent probes expire
from a bounded deadline queue, and transmit calls are batched when the rate
allows. A single packet reader feeds bounded queues and reusable decoder
workers, and receive buffers are pooled so receive work does not allocate per
packet.

## IPv6 raw SYN

IPv6 targets use the same engine, limits, token checks and output as IPv4:

```sh
sudo nyxr scan --tcp-mode syn --interface eth0 --protocols tcp \
  --ports 22,443 2001:db8:1::10 fe80::1%eth0
```

One scan can mix IPv4 and IPv6 targets; nyxr scans the IPv4 targets first.
Large CIDR streams stay IPv4-only, so IPv6 targets count against the normal
target limit. A dual-stack hostname scans both addresses.

**Sources.** Without `--source-ip`, nyxr picks an address on the interface
for each target, following the scope and longest-prefix rules of
[RFC 6724](https://www.rfc-editor.org/rfc/rfc6724.html). Link-local targets
use a link-local source. Other targets use a global or unique-local source,
preferring one whose prefix contains the target. Targets that need different
sources run one after the other on the same handles. A `--source-ip` serves
every target, so it cannot be combined with targets of the other family.

**Next hops.** nyxr reads the IPv6 routing table (`/proc/net/ipv6_route`,
`netstat -rn -f inet6`, or `Get-NetRoute` on Windows) and resolves each
distinct next hop with Neighbor Discovery. Solicitations to link-local
routers come from the interface's link-local address, and each advertisement
must match its target, the sender MAC and the ICMPv6 checksum. Silent hops are
solicited once more. A hop that never answers produces `no-response` with
`next-hop NDP unanswered; SYN not sent`. On macOS nyxr also learns the
Ethernet source the interface really transmits with, as it does for IPv4.

**Zones.** Link-local targets (`fe80::/10`) are always on-link. Write them
with a zone (`fe80::1%eth0`), or pass `--interface`. A zone selects the
interface when `--interface` is omitted, and it must name the scan interface.
One scan covers one link. Results report link-local targets with the
interface as their zone. Global addresses with a zone are rejected.

**Replies.** The decoder walks at most eight hop-by-hop, routing,
destination-options or authentication headers to reach TCP or ICMPv6.
Fragmented replies, ESP and longer or truncated chains are dropped. ICMPv6
destination unreachable (type 1) is classified `filtered` only when its quote
carries the probe's address, ports and sequence token.

**Not supported for IPv6.** AF_XDP (`--xdp-pin-dir`) is IPv4 only, and such
scans are rejected. Without an OS interface (Npcap device IDs), set an IPv6
`--source-ip` and `--source-mac`; automatic next hops then need an OS route
too, otherwise also set `--next-hop-mac`.

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
| Linux (opt-in) | AF_XDP copy mode | Root or suitable BPF/network capabilities, an XDP-capable interface, pinned Nyxr maps |
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

## Linux AF_XDP

AF_XDP is an optional backend for IPv4 raw TCP SYN scans; IPv6 SYN uses the
default backend. Nyxr opens one
preallocated UMEM and RX socket per NIC queue, batches RX and TX descriptors,
and sends from queue zero. The XDP program redirects matching SYN/ACK,
RST/ACK, and ICMP unreachable replies to those sockets; unrelated traffic
continues through the kernel. ARP resolution and packet evidence still use
AF_PACKET. The default backend remains AF_PACKET on Linux.

On a Linux host with `clang` (BPF target), `bpftool`, `iproute2`, GCC, and a
mounted bpffs at `/sys/fs/bpf`, attach the supplied program once per interface:

```sh
sudo bash tools/xdp/setup.sh eth0 /sys/fs/bpf/nyxr-eth0
sudo nyxr scan --tcp-mode syn --interface eth0 \
  --xdp-pin-dir /sys/fs/bpf/nyxr-eth0 --protocols tcp --ports 80,443 192.0.2.10
```

The pin directory must be unique to that interface. Setup fails if the
directory exists or the interface already has an incompatible XDP program.
Nyxr reserves its scan source port in the host TCP stack, and permits one
active AF_XDP scan per pin directory. It clears its redirect and socket-map
entries when the scan ends. To remove the program after all scans finish,
run `sudo ip link set dev eth0 xdp off`, then remove that program's pin
directory. Only detach a program you attached yourself.

`--xdp-pin-dir` is unavailable through `nyxr-packetd` or remote API requests.
If AF_XDP setup fails, remove the option to use AF_PACKET. The current backend
uses copy mode and 4 KiB single-frame UMEM slots; larger frames are rejected
instead of truncated. Measure live throughput and drops before treating it as
faster than AF_PACKET on a specific NIC.

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
open-and-timeout smoke test has passed. The Linux namespace gate covers IPv4
and IPv6 raw SYN (ULA through automatic NDP and a zoned link-local target). Live receive and transmit on BPF and
Npcap, privileged Linux scanning and real NIC drop measurements are still
pending; see [Runtime gates](../development/runtime-gates.md) and
[Performance](../development/performance.md).
