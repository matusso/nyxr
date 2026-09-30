# nyxr

An early cross-platform network scanner built around the architecture in
[ROADMAP.md](ROADMAP.md). This first implementation provides a CLI with a shared
configuration contract, a full profile catalog, bounded concurrent TCP connect
and UDP probe campaigns, IPv4 ICMP echo, address and port parsing, rate
limiting, structured observations, and a reusable gopacket receive decoder.
It does not yet implement the roadmap's SYN engine, service fingerprinting,
distributed control plane, or web UI.

## Build

Go 1.27.1 or newer is required. nyxr builds without cgo:

```sh
make check      # go test + go vet
make build      # ./nyxr for the host platform
make package    # dist/: archives for all platforms + SHA256SUMS
make help       # list all targets
```

`VERSION` defaults to `git describe` and can be overridden, e.g.
`make package VERSION=v0.1.0`.

CI runs `make check`, `make package`, and a Docker image smoke test on every
push and pull request. The archives cover `linux`, `windows`, and `darwin` on
`amd64` and `arm64`. Pushing a semantic version tag such as `v0.2.0` runs the
release workflow, which creates a GitHub release with the `.tar.gz`/`.zip`
archives and `SHA256SUMS`. It also pushes a Linux `amd64`/`arm64` image to
`ghcr.io/matusso/nyxr:v0.2.0`. Stable releases update `:latest`; tags
containing `-` (such as `v0.2.0-rc1`) are marked as pre-releases and do not
update `:latest`. The release workflow can also be started manually for an
existing tag.

Build or run the container locally:

```sh
docker build -t nyxr:local .
docker run --rm nyxr:local version
docker run --rm nyxr:local scan --ports 80,443 example.com
```

Network behavior depends on Docker networking. On Linux, use `--network host`
when scans need direct access to the host network, and add `--cap-add NET_RAW`
for raw socket features such as ICMP and packet capture.

## Scan

```sh
nyxr scan --ports 22,80,443 --protocols tcp --json 192.0.2.1
nyxr scan --profile udp --ports 53,123 192.0.2.1
nyxr scan --profile udp-deep --udp-retries 1 --json 192.0.2.1
nyxr scan --protocols udp --ports 9999 --send-hex "010203" 192.0.2.1
nyxr scan --protocols udp --ports 9999 --payload my-probe.yaml 192.0.2.1
nyxr scan --protocols tcp,udp,icmp --timeout 2s --rate 50 192.0.2.0/28
nyxr scan --profile ot-safe 192.0.2.10
nyxr scan --profile fast --ports top100 192.0.2.0/24
nyxr scan --profile udp-deep --dry-run 192.0.2.0/28
nyxr profiles
nyxr decode capture.pcap
sudo nyxr sniff --interface eth0 --count 100
```

Targets may be IP addresses, hostnames, CIDRs, or inclusive IP ranges. A scan
is limited to 65,536 unique addresses. Ports accept commas and inclusive ranges
(`80,443,8000-8100`) or a named set: `top100` for a curated list of common TCP
ports, or `all` for `1-65535`. Use `--json` for newline-delimited observations.
`--dry-run` resolves the configuration and prints the plan — profile, target
count, ports, protocols, pacing and scheduled task count — without sending any
packet; add `--json` for the machine-readable plan. UDP/53 attempts DNS A then
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

### Profiles

A profile supplies default ports, protocols, timeout and pacing; explicit flags
and configuration-file fields override those defaults. `nyxr profiles` lists the
catalog (add `--json` for machine-readable output). Profiles whose engine is not
implemented yet are listed as `planned` and refuse to run with a message naming
the roadmap phase they need, rather than silently downgrading to a weaker scan.

| Profile | Status | Summary |
| --- | --- | --- |
| `discovery` | available | Common TCP ports, unprivileged connect scan (default) |
| `fast` | available | Top 100 TCP ports at higher concurrency |
| `tcp` | available | TCP connect scan of common ports |
| `udp` | available | Protocol-aware UDP probes (DNS, NTP) |
| `udp-deep` | available | UDP probes including SNMP, one extra retry each |
| `ot-safe` | available | Low-rate, read-only, TCP-only OT identification |
| `custom` | available | Minimal profile; set protocols, ports and timeout explicitly |
| `service`, `deep`, `web`, `database`, `full` | planned | Service/version detection (roadmap Phase 3+) |
| `iot` | planned | Device fingerprinting (roadmap Phase 4) |
| `research` | planned | Packet-forge experiments (roadmap Phase 5) |

`ot-safe` is enforced, not merely a set of defaults: it refuses UDP or ICMP,
custom payloads, an unlimited or higher-than-5 rate, more than four workers, or a
timeout under three seconds, so an operator cannot accidentally turn it into a
disruptive scan.

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

The CLI and a future API share one configuration contract: flags and file
fields are merged into a single set of options, resolved against the selected
profile, then validated once before any scan runs (`internal/config`). This
keeps command-line parsing out of the engine and lets every interface produce
the same validated request.

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

Pass it with `nyxr scan --config scan.yaml`; command-line options override
matching file fields. Positional targets are added to file targets. A relative
`udp_probe_file` path is resolved beside the scan configuration file.

## Packet I/O and platform limits

The Ethernet decoder uses `gopacket.DecodingLayerParser` and preallocated
Ethernet, IPv4/IPv6, TCP, UDP, and ICMP layers. `nyxr decode` demonstrates
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
