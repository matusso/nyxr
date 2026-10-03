# CLI reference

```text
nyxr scan [flags] target [target...]   run a scan
nyxr profiles [--json]                 list scan profiles
nyxr decode [--tui] capture.pcap[ng]   summarize hosts and open ports, or browse packets
nyxr decode [--tui] --last             decode the last scan's capture (~/.nyxr/last.pcapng)
nyxr sniff --interface eth0 [flags]    capture and decode live frames
nyxr history [--db file] [flags]       list or query stored scans, assets and evidence
nyxr probe import file [--json]        import and summarize an nmap-service-probes file
nyxr serve [--db file] [flags]         serve the REST API and web UI (unprivileged)
nyxr completion <shell>                print a bash, zsh, fish or powershell completion script
nyxr version                           print the version
nyxr help                              show this help
```

**Global flag.** `--no-color` disables ANSI color for every subcommand. The
`NO_COLOR` environment variable does the same, and color is off automatically
when output is not a terminal.

Run `nyxr <command> -h` for the built-in help of any command.

## nyxr scan

Run a scan. Explicit flags override profile defaults and configuration-file
fields. Guide: [Scanning](../guide/scanning.md).

### Scope, pacing and output

| Flag | Meaning |
| --- | --- |
| `--profile NAME` | Scan profile (default `tcp-basic`); see `nyxr profiles` |
| `--ports LIST` | Ports, ranges (`80,443,8000-8100`) or a set: `all`, `top100`, `top1000`, `top2000`, `top5000`, `top8387`, `database` |
| `--protocols LIST` | `tcp`, `udp`, `icmp`, `arp`, `ndp`; `research` also accepts `sctp`, `ip` |
| `--timeout DURATION` | Per-probe timeout, for example `1s` or `750ms` |
| `--rate N` | Max probes per second (`0` = unlimited) |
| `--host-rate N` | Max probes per second per address |
| `--subnet-rate N` | Max probes per second per IPv4 /24 or IPv6 /64 |
| `--interface-rate N` | Max probes per second on the selected raw interface |
| `--workers N` | Concurrent probe workers |
| `--allow-targets LIST` | Approved IP/CIDR targets (required for `ot-safe` and `research`) |
| `--known-open` | Rescan only ports the database last saw open; targets, if given, narrow it |
| `--config FILE` | YAML scan configuration |
| `--json` | Newline-delimited JSON output |
| `--dry-run` | Resolve and print the plan without sending packets |
| `--open` | Show only open ports and responsive hosts (the database still stores everything) |
| `--no-progress` | Hide the progress bar |
| `--no-summary` | Hide the closing statistics on stderr |

### UDP

| Flag | Meaning |
| --- | --- |
| `--udp-retries N` | Extra retries per UDP probe |
| `--payload FILE` | Native YAML UDP probe definition |
| `--send-hex HEX` | Custom UDP payload as hex |
| `--send-base64 B64` | Custom UDP payload as base64 |
| `--payload-file FILE` | Custom raw UDP payload file |
| `--nmap-udp-probes FILE` | Add UDP payloads from a local Nmap probe file |

Guide: [UDP scanning](../guide/udp.md).

### Raw packets

| Flag | Meaning |
| --- | --- |
| `--tcp-mode MODE` | `connect` (default) or raw Ethernet `syn` |
| `--interface NAME` | Ethernet interface for raw modes and capture |
| `--source-ip IP` | Interface IPv4 address for SYN mode (automatic if unique) |
| `--source-mac MAC` | Source Ethernet MAC (for Npcap adapter names) |
| `--next-hop-mac MAC` | Destination or gateway MAC; overrides automatic resolution |
| `--packetd SOCKET` | Use nyxr-packetd for raw I/O instead of local privilege |

Guide: [Raw packet scanning](../guide/raw-packets.md).

### Research profile

| Flag | Meaning |
| --- | --- |
| `--research-kind NAME` | `tcp`, `udp`, `icmp`, `sctp` or `ip` |
| `--ip-protocol N` | IP protocol number for research IP scans |
| `--tcp-flags LIST` | TCP flags (`syn`, `ack`, `fin`, `null`, `xmas` or a numeric mask) |
| `--fragment-size N` | IP payload bytes per fragment, a multiple of eight |
| `--bad-checksum` | Deliberately corrupt the transport checksum |
| `--ip-length N` | Override the IP payload or total length field |
| `--forge-payload-hex HEX` | Raw research payload bytes |

Guide: [Research packets](../guide/research-packets.md).

### Service identification, evidence and storage

| Flag | Meaning |
| --- | --- |
| `--service` | Deep probes on open TCP ports (on for `tcp-common`, `tcp-full`, `deep-scan`, `windows`, `filesystem`, `web`, `database`, `iot`, `ot-safe`) |
| `--service-probes LIST` | `banner`, `ssh`, `tls`, `http`, `dns`, `socks`, `modbus`, `ethernetip`, `nmap`, `database`, `smb`, `rdp`, `msrpc`, `ldap`, `kerberos`, `nfs` |
| `--service-fallback LIST` | Probes for silent ports without a port hint, or `none` |
| `--service-timeout DURATION` | Upper bound for each service probe |
| `--service-workers N` | Concurrent service probe workers |
| `--service-rate N` | New service connections per second (`0` = unlimited) |
| `--nmap-service-probes FILE` | Match banners against a local `nmap-service-probes` file |
| `--nse-scripts LIST` | Run selected installed NSE scripts in Nmap's `safe` category on open ports |
| `--nse-timeout DURATION` | Maximum Nmap time per host (default `30s`) |
| `--fingerprint` | Classify devices from independent observations |
| `--pcapng FILE` | Capture scan traffic on `--interface` as pcapng evidence |
| `--pcapng-max-mb N` | pcapng size budget (default 1024) |
| `--no-last-pcapng` | Do not keep this scan's traffic in `~/.nyxr/last.pcapng` (see `decode --last`) |
| `--db FILE` | SQLite database (default `~/.nyxr/nyxr.db`) |
| `--no-db` | Do not store the scan |

Guides: [Service identification](../guide/service-identification.md),
[OT and IoT](../guide/ot-and-iot.md),
[Packet capture](../guide/packet-capture.md).

## nyxr profiles

List the profile catalog. `--json` prints it as JSON.
Guide: [Scan profiles](../guide/profiles.md).

## nyxr decode

Summarize a pcap or pcapng capture (Ethernet link type).

| Flag | Meaning |
| --- | --- |
| `--last` | Decode `~/.nyxr/last.pcapng`, the traffic of the last scan, instead of a file |
| `--all` | Also list closed and filtered ports |
| `--packets` | List every decoded packet |
| `--json` | One JSON object per decoded packet |
| `--tui` | Browse and inspect packets interactively |

Guide: [Packet capture and analysis](../guide/packet-capture.md).

## nyxr sniff

Capture and decode live frames. Needs raw packet privileges.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--interface NAME` | | Network interface |
| `--count N` | 100 | Number of decoded packets |
| `--timeout DURATION` | 10s | Capture duration |

## nyxr history

Query and maintain the scan database.

| Flag | Meaning |
| --- | --- |
| `--db FILE` | SQLite database |
| `--scan ID` | Observations and packet evidence of one scan |
| `--assets` | Asset inventory: latest state and service per port |
| `--open` | Only open ports |
| `--scope LIST` | IPs, CIDRs or ranges (with `--assets`) |
| `--unknown` | Unknown fingerprints |
| `--address IP` | Restrict to one address (with `--scan` or `--unknown`) |
| `--limit N` | Maximum rows (default 50) |
| `--prune-older-than DURATION` | Delete scans older than this |
| `--keep N` | Keep only the newest N scans |
| `--json` | JSON output |

Guide: [Storage and history](../guide/storage-and-history.md).

## nyxr probe import

Import an `nmap-service-probes` file and print what can be used from it. The
file is read at runtime and never bundled. `--json` prints a machine-readable
summary.

## nyxr serve

Serve the REST API, live scan events and the web UI, unprivileged.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--listen ADDR` | `127.0.0.1:8484` | Listen address; non-loopback requires a token |
| `--db FILE` | `~/.nyxr/nyxr.db` | SQLite database |
| `--packetd SOCKET` | | nyxr-packetd socket for raw packet I/O |
| `--evidence-dir DIR` | | Directory for pcapng captures requested through the API |
| `--token-file FILE` | | Require this bearer token (or set `NYXR_API_TOKEN`) |
| `--max-scans N` | 1 | Concurrent scans |
| `--allow-packet-send` | off | Enable single-frame send and resend from the web UI (requires `--packetd`) |
| `--allow-privileged` | off | Run even with root or raw-socket capabilities |

Guide: [Web UI and REST API](../guide/web-ui-and-api.md).

## nyxr completion

Print a completion script for `bash`, `zsh`, `fish` or `powershell`. See
[Getting started](../getting-started.md#shell-completion).

## nyxr-packetd

```text
nyxr-packetd --socket path --interface eth0[,eth1] [flags]
```

Relay raw Ethernet frames for the listed interfaces to unprivileged nyxr
processes over a Unix socket.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--socket PATH` | | Unix socket to create (required) |
| `--interface LIST` | | Interfaces clients may open (required) |
| `--socket-mode OCTAL` | `0660` | Socket file permissions; world access is refused |
| `--max-clients N` | 4 | Concurrent sessions |
| `--max-pps N` | unlimited | Transmit frames per second per session |
| `--version` | | Print the version |

Guide: [Deployment](../guide/deployment.md#privilege-separation-with-nyxr-packetd).

## Environment

| Variable | Effect |
| --- | --- |
| `NO_COLOR` | Disable color output |
| `NYXR_API_TOKEN` | Bearer token for `nyxr serve` |
