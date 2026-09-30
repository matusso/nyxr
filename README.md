# nyxr scanner

An early cross-platform network scanner built around the architecture in
[ROADMAP.md](ROADMAP.md). This first implementation provides a CLI, bounded
concurrent TCP connect and UDP probe campaigns, IPv4 ICMP echo, address and port parsing,
rate limiting, structured observations, and a reusable gopacket receive decoder.
It does not yet implement the roadmap's SYN engine, service fingerprinting,
distributed control plane, or web UI.

## Build

Go 1.27.1 or newer is required. The scanner builds without cgo:

```sh
make check      # go test + go vet
make build      # ./scanner for the host platform
make package    # dist/: archives for all platforms + SHA256SUMS
make help       # list all targets
```

`VERSION` defaults to `git describe` and can be overridden, e.g.
`make package VERSION=v0.1.0`.

CI runs `make check` and `make package` on every push and pull request,
covering `linux`, `windows`, and `darwin` on `amd64` and `arm64`. Pushing a
`v*` tag runs the release workflow, which creates a GitHub release with the
`.tar.gz`/`.zip` archives and `SHA256SUMS`. Tags containing `-` (such as
`v0.2.0-rc1`) are marked as pre-releases.

## Scan

```sh
scanner scan --ports 22,80,443 --protocols tcp --json 192.0.2.1
scanner scan --profile udp --ports 53,123 192.0.2.1
scanner scan --profile udp-deep --udp-retries 1 --json 192.0.2.1
scanner scan --protocols udp --ports 9999 --send-hex "010203" 192.0.2.1
scanner scan --protocols udp --ports 9999 --payload my-probe.yaml 192.0.2.1
scanner scan --protocols tcp,udp,icmp --timeout 2s --rate 50 192.0.2.0/28
scanner scan --profile ot-safe 192.0.2.10
scanner decode capture.pcap
sudo scanner sniff --interface eth0 --count 100
```

Targets may be IP addresses, hostnames, CIDRs, or inclusive IP ranges. A scan
is limited to 65,536 unique addresses. Ports accept commas and inclusive ranges.
Use `--json` for newline-delimited observations. UDP/53 attempts DNS A then
DNS NS, UDP/123 sends an NTP client request, and UDP/161 sends a read-only
SNMPv2c `sysDescr.0` GET. Other UDP ports receive a single byte. The
`udp-deep` profile includes port 161 and retries each probe once. `--rate`
limits application-level probe sends, including UDP retries. A matching DNS
transaction ID, NTP originate timestamp, or SNMP request ID raises confidence;
the token is derived from a per-scan secret. An unmatched UDP response is retained as an unknown
fingerprint with a hex evidence sample. No response is `open|filtered` with
low confidence; it is never reported as definitely open. Connected UDP sockets
also classify ICMP port-unreachable errors when the OS delivers them. TCP uses
ordinary connect calls, so it works without raw packet privileges. The
`ot-safe` profile limits rate and concurrency
and uses TCP connect only.

For a custom UDP payload, choose one of `--payload` (native YAML definition),
`--send-hex`, `--send-base64`, or `--payload-file`. An explicit custom payload
replaces built-in probes for the scan. A native definition can target particular
ports and set its own timeout and retry count:

```yaml
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

Supported payload encodings are `ascii`, `hex`, `base64`, and `raw_file`
(relative to the YAML file). Matchers are `any`, `dns`, `ntp`, and `snmp`. This first
version accepts only `safety: safe`; additional matcher and extraction types
are planned. A probe with no applicable port falls back to the generic byte.

Configuration can be supplied as YAML:

```yaml
targets: [192.0.2.10]
ports: "22,80,443"
protocols: "tcp"
timeout: 2s
rate: 100
workers: 32
profile: discovery
udp_retries: 0
udp_probe_file: my-probe.yaml
```

Pass it with `scanner scan --config scan.yaml`; command-line options override
matching file fields. Positional targets are added to file targets. A relative
`udp_probe_file` path is resolved beside the scan configuration file.

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

UDP port-unreachable reporting varies by operating system and firewall. A
silent or rate-limited ICMP path remains `open|filtered`. The current UDP
engine uses safe single-protocol probes; broad protocol coverage and raw ICMP
correlation remain future roadmap work.
