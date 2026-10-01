# Research packets

The `research` profile sends hand-crafted raw packets for firewall, IDS and
protocol-stack experiments: arbitrary TCP flags, SCTP, raw IP protocols,
fragmentation and deliberately malformed headers. Because these packets can
upset fragile stacks, the profile is fenced by strict limits.

> Run research scans only against systems you own or are explicitly authorized
> to test.

## Safety limits

| Control | Value |
| --- | --- |
| Interface | `--interface` is required |
| Target allowlist | `--allow-targets` is required before any frame is sent |
| Scope | At most 256 targets and 1,024 ports |
| Concurrency | One outstanding probe at a time |
| Rate | Capped at five frames per second; each IP fragment uses one rate slot |
| Remote use | Not available through the API or web UI |
| Default | One TCP SYN to port 80 on each target |

The profile needs the same raw packet privileges as [raw SYN mode](raw-packets.md).
Review the resolved scope and packet controls first with `--dry-run --json`.

## Examples

```sh
# XMAS scan of 443, planned only
sudo nyxr scan --profile research --protocols tcp --tcp-flags xmas \
  --ports 443 --interface eth0 --allow-targets 192.0.2.0/24 \
  --dry-run 192.0.2.10

# SCTP INIT to port 2905
sudo nyxr scan --profile research --protocols sctp --ports 2905 \
  --interface eth0 --allow-targets 192.0.2.0/24 192.0.2.10

# Raw IP protocol 47 (GRE)
sudo nyxr scan --profile research --protocols ip --ip-protocol 47 \
  --interface eth0 --allow-targets 192.0.2.0/24 192.0.2.10
```

## Packet controls

| Flag | Effect |
| --- | --- |
| `--protocols` | One of `tcp`, `udp`, `icmp`, `sctp`, `ip` |
| `--research-kind` | Alias that selects one research protocol when a configuration file already sets `protocols` |
| `--tcp-flags` | `fin,syn,rst,psh,ack,urg`, `null`, `xmas`, or a numeric mask |
| `--ip-protocol` | IP protocol number for `--protocols ip` |
| `--forge-payload-hex` | Raw payload bytes |
| `--fragment-size` | IP payload bytes per fragment; a multiple of eight |
| `--bad-checksum` | Deliberately corrupt the transport checksum |
| `--ip-length` | Override the IP length field |
| `--next-hop-mac` | Required for IPv6; IPv4 resolves the route and ARP neighbor automatically |

Malformed overrides and arbitrary TCP flags are rejected by every other
profile.

## How replies are interpreted

The research path never treats an uncorrelated reply as proof of an open port:

| Probe | Correlation |
| --- | --- |
| SCTP | INIT verification tag |
| TCP | Per-probe sequence token |
| ICMP errors | Quoted addresses, protocol and probe identifier |
| Raw IP protocol | Direct replies, reported with lower confidence because they carry no token |

## Packet builder

`internal/packet.ForgeFrames` builds validated Ethernet/VLAN, IPv4/IPv6,
TCP/UDP/ICMP/SCTP and raw IP protocol frames. It supports aligned IPv4 and TCP
options, bounded IPv6 extension-header chains, checksums and explicit
fragmentation. The CLI exposes the controls listed above; the remaining builder
fields are available to internal callers after research policy validation.

## Status

The research path is fixture-tested and cross-builds for every platform.
Privileged live transmit and receive behavior has not yet been verified on
Linux, macOS or Windows. See the [Roadmap](../roadmap.md).
