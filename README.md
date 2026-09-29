# nyxr scanner

An early cross-platform network scanner built around the architecture in
[ROADMAP.md](ROADMAP.md). This first implementation provides a CLI, bounded
concurrent TCP connect and UDP probes, IPv4 ICMP echo, address and port parsing,
rate limiting, structured observations, and a reusable gopacket receive decoder.
It does not yet implement the roadmap's SYN engine, service fingerprinting,
distributed control plane, or web UI.

## Build

Go 1.27.1 or newer is required. The scanner builds without cgo:

```sh
go test ./...
go build -o scanner ./cmd/scanner
```

CI tests the code and builds `linux`, `windows`, and `darwin` binaries for
`amd64` and `arm64`. A published GitHub release receives all six binaries.

## Scan

```sh
scanner scan --ports 22,80,443 --protocols tcp --json 192.0.2.1
scanner scan --profile udp --ports 53,123 192.0.2.1
scanner scan --protocols tcp,udp,icmp --timeout 2s --rate 50 192.0.2.0/28
scanner scan --profile ot-safe 192.0.2.10
scanner decode capture.pcap
sudo scanner sniff --interface eth0 --count 100
```

Targets may be IP addresses, hostnames, CIDRs, or inclusive IP ranges. A scan
is limited to 65,536 unique addresses. Ports accept commas and inclusive ranges.
Use `--json` for newline-delimited observations. UDP/53 sends a DNS A request,
UDP/123 sends an NTP client request, and other UDP ports receive a single byte.
No response is reported as `open|filtered` with low confidence; it is never
reported as definitely open. TCP uses ordinary connect calls, so it works
without raw packet privileges. The `ot-safe` profile limits rate and concurrency
and uses TCP connect only.

Configuration can be supplied as YAML:

```yaml
targets: [192.0.2.10]
ports: "22,80,443"
protocols: "tcp"
timeout: 2s
rate: 100
workers: 32
profile: discovery
```

Pass it with `scanner scan --config scan.yaml`; command-line options override
matching file fields. Positional targets are added to file targets.

## Packet I/O and platform limits

The Ethernet decoder uses `gopacket.DecodingLayerParser` and preallocated
Ethernet, IPv4/IPv6, TCP, UDP, and ICMP layers. `scanner decode` demonstrates
this path on pcap files without `PacketSource`. The packet I/O interface accepts
batches of raw Ethernet frames and keeps acquisition separate from decoding.

- **Linux:** `sniff` uses an AF_PACKET backend. Opening it requires root or
  `CAP_NET_RAW`; a suitable interface and link-layer permissions are also
  required. The CLI does not yet transmit SYN probes.
- **macOS:** TCP/UDP scans and pcap decoding work. Live Ethernet I/O needs a
  BPF backend and suitable `/dev/bpf` permissions; that backend is pending.
- **Windows:** TCP/UDP scans and pcap decoding work. Live Ethernet I/O needs
  an Npcap backend and Npcap installation; that backend is pending.
- **ICMP:** IPv4 echo uses a raw socket and generally needs elevated privileges
  on all platforms. IPv6 echo is not implemented. Permission and unsupported
  conditions appear as observations instead of silently changing scan methods.

The current packet decoder expects Ethernet pcap frames. Other link types and
pcapng files are not yet supported.
