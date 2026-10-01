# Scanning

`nyxr scan` runs one scan: discovery, then any service, fingerprint, capture
and storage stages the profile or flags enable. This guide covers the options
every scan shares. For profile-specific behavior see [Scan profiles](profiles.md).

- [Targets](#targets)
- [Ports](#ports)
- [Protocols and TCP mode](#protocols-and-tcp-mode)
- [Plan before you scan](#plan-before-you-scan)
- [Output](#output)
- [Rescan stored open ports](#rescan-stored-open-ports)
- [Rate limits and concurrency](#rate-limits-and-concurrency)
- [Configuration files](#configuration-files)
- [Examples](#examples)

## Targets

Targets are positional arguments and can be mixed freely:

| Form | Example |
| --- | --- |
| IPv4 or IPv6 address | `192.0.2.10`, `2001:db8::10` |
| Hostname | `host.example` |
| CIDR | `192.0.2.0/24`, `2001:db8::/120` |
| Inclusive range | `192.0.2.10-192.0.2.50` |

Raw IPv4 SYN scans stream large ranges. Other scan modes accept at most 65,536
unique addresses per scan.

## Ports

`--ports` accepts single ports, comma lists and inclusive ranges
(`80,443,8000-8100`), or one of the named sets:

| Set | Contents |
| --- | --- |
| `top100` | Curated list of common TCP ports |
| `top1000`, `top2000`, `top5000` | The same TCP ports as `nmap --top-ports N` |
| `top8387` | Every TCP port ranked in nmap-services |
| `database` | Common SQL, NoSQL, graph, search, time-series, vector and cache ports |
| `all` | `1-65535` |

When `--ports` is omitted, the profile supplies its default port list.

## Protocols and TCP mode

`--protocols` takes a comma list of `tcp`, `udp`, `icmp`, `arp` and `ndp`. The
`research` profile also accepts `sctp` and `ip`.

TCP uses ordinary `connect()` calls by default, so it needs no privileges.
`--tcp-mode syn` sends raw IPv4 SYN packets instead; see
[Raw packet scanning](raw-packets.md). UDP behavior is described in
[UDP scanning](udp.md).

## Plan before you scan

`--dry-run` resolves the profile, flags and configuration file, validates them,
and prints the plan without sending a single packet:

```sh
nyxr scan --profile ot-safe --allow-targets 192.0.2.0/24 --dry-run 192.0.2.10
```

```text
profile     ot-safe
targets     1 (192.0.2.10)
allow       192.0.2.0/24
protocols   tcp
ports       80,443,502,44818
timeout     3s
rate        5/s
workers     4
tcp-mode    connect
tasks       4
service     modbus, ethernetip (fallback none)
svc-timeout 3s, 4 workers, 5/s
db          ~/.nyxr/nyxr.db
fingerprint enabled
```

Add `--json` for a machine-readable plan. The web UI and the API
(`POST /api/v1/plan`) produce the same plan.

## Output

By default, results are printed as aligned text, one line per observation,
followed by a summary on stderr.

| Flag | Effect |
| --- | --- |
| `--json` | Newline-delimited JSON records (see [Output records](../reference/output-records.md)) |
| `--open` | Show only open ports and responsive hosts; the database still stores everything |
| `--no-progress` | Hide the progress bar (shown on stderr only when it is a terminal) |
| `--no-summary` | Hide the closing statistics: time, tasks, rate, workers and packets on the wire |
| `--no-color` | Disable color; the `NO_COLOR` environment variable has the same effect |

Color is turned off automatically when output is not a terminal.

Every scan is also stored in the SQLite database unless `--no-db` is given. See
[Storage and history](storage-and-history.md).

## Rescan stored open ports

`--known-open` builds a service scan from ports whose latest stored state is
open. Positional targets are optional and narrow the stored hosts by IP, CIDR
or range:

```sh
nyxr scan --profile fast --ports top1000 192.0.2.0/24   # discovery first
nyxr scan --known-open 192.0.2.0/24                     # then identify what was found
nyxr scan --known-open 192.0.2.10                       # or one host
```

It requires the scan database, uses the `service` profile and enables service
probes by default.

## Rate limits and concurrency

| Flag | Limit |
| --- | --- |
| `--rate` | Probes per second across the whole scan, including UDP retries |
| `--host-rate` | Probes per second to one address |
| `--subnet-rate` | Probes per second to one IPv4 /24 or IPv6 /64 |
| `--interface-rate` | Raw SYN and neighbor discovery sends per second on the selected interface |
| `--workers` | Concurrent probe workers |
| `--timeout` | Per-probe timeout, for example `750ms` or `2s` |

All limits default to unlimited unless the profile sets them. Rate limits apply
to application-level probe sends. Service probes have their own controls; see
[Service identification](service-identification.md#tuning).

## Configuration files

Any scan can be described as a YAML document and passed with `--config`:

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

```sh
nyxr scan --config scan.yaml 192.0.2.11
```

Command-line flags override matching file fields, and positional targets are
added to the file's targets. A relative `udp_probe_file` is resolved next to the
configuration file. Unknown fields are rejected.

The same document, encoded as JSON, is the body of `POST /api/v1/scans`. The
full field list is in the [Configuration reference](../reference/configuration.md).

## Examples

```sh
# Common TCP ports on one host, JSON output
nyxr scan --ports 22,80,443 --protocols tcp --json 192.0.2.1

# Top 100 TCP ports across a /24, open results only
nyxr scan --profile fast --ports top100 --open 192.0.2.0/24

# Mixed TCP, UDP and ICMP, paced at 50 probes/s
nyxr scan --protocols tcp,udp,icmp --timeout 2s --rate 50 192.0.2.0/28

# Web services with TLS and HTTP identification
nyxr scan --profile web --json 192.0.2.10

# Deep UDP interrogation with one retry
nyxr scan --profile udp-deep --udp-retries 1 --json 192.0.2.1

# Do not store this scan
nyxr scan --profile fast --no-db 192.0.2.0/24
```
