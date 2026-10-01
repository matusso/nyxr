# Configuration reference

A scan is described by one document. The CLI reads it from YAML (`--config`)
and overlays flags; the API accepts the same field names as JSON in
`POST /api/v1/scans` and `POST /api/v1/plan`. Both go through the same
resolution: the profile supplies defaults, explicit fields override them, and
the result is validated once before anything is sent. Unknown fields are
rejected in both encodings.

```yaml
# scan.yaml
targets: [192.0.2.0/28]
profile: service
ports: "top100"
rate: 100
service_timeout: 3s
fingerprint: true
```

```sh
nyxr scan --config scan.yaml --ports 22,443   # flags override file fields
```

Positional targets are added to the file's `targets`. A relative
`udp_probe_file` is resolved next to the configuration file.

## Fields

Durations are strings such as `750ms` or `2s`. Omitted fields keep the
profile default.

### Scope and pacing

| Field | Flag | Type | Meaning |
| --- | --- | --- | --- |
| `targets` | positional | list | IPs, hostnames, CIDRs or ranges |
| `allow_targets` | `--allow-targets` | list | Approved IPs or CIDRs; required by `ot-safe` and `research` |
| `profile` | `--profile` | string | [Scan profile](../guide/profiles.md) |
| `ports` | `--ports` | string | Ports, ranges or a named set |
| `protocols` | `--protocols` | string | Comma list of `tcp`, `udp`, `icmp`, `arp`, `ndp` (plus `sctp`, `ip` for `research`) |
| `timeout` | `--timeout` | duration | Per-probe timeout |
| `rate` | `--rate` | integer | Probes per second overall (`0` = unlimited) |
| `host_rate` | `--host-rate` | integer | Probes per second per address |
| `subnet_rate` | `--subnet-rate` | integer | Probes per second per IPv4 /24 or IPv6 /64 |
| `interface_rate` | `--interface-rate` | integer | Raw sends per second on the interface |
| `workers` | `--workers` | integer | Concurrent probe workers |
| `known_open` | `--known-open` | boolean | Rescan only stored open ports; `targets` narrow the stored hosts |

### UDP

| Field | Flag | Type | Meaning |
| --- | --- | --- | --- |
| `udp_retries` | `--udp-retries` | integer | Extra retries per UDP probe |
| `udp_probe_file` | `--payload` | path | Native YAML probe definition |
| `send_hex` | `--send-hex` | string | Custom payload, hex |
| `send_base64` | `--send-base64` | string | Custom payload, base64 |
| `payload_file` | `--payload-file` | path | Custom payload, raw file |
| `nmap_udp_probes` | `--nmap-udp-probes` | path | Add UDP payloads from a local Nmap probe file |

### Raw packets

| Field | Flag | Type | Meaning |
| --- | --- | --- | --- |
| `tcp_mode` | `--tcp-mode` | string | `connect` (default) or `syn` |
| `interface` | `--interface` | string | Ethernet interface for raw modes and capture |
| `source_ip` | `--source-ip` | string | Source IPv4 address on the interface |
| `source_mac` | `--source-mac` | string | Source MAC (Npcap adapters) |
| `next_hop_mac` | `--next-hop-mac` | string | Override next-hop resolution |

### Research

Accepted only with the `research` profile. See [Research packets](../guide/research-packets.md).

| Field | Flag | Type | Meaning |
| --- | --- | --- | --- |
| `research_kind` | `--research-kind` | string | `tcp`, `udp`, `icmp`, `sctp` or `ip` |
| `ip_protocol` | `--ip-protocol` | string | IP protocol number |
| `tcp_flags` | `--tcp-flags` | string | Flag list, `null`, `xmas` or a numeric mask |
| `fragment_size` | `--fragment-size` | integer | IP payload bytes per fragment, a multiple of eight |
| `bad_checksum` | `--bad-checksum` | boolean | Corrupt the transport checksum |
| `ip_length` | `--ip-length` | integer | Override the IP length field |
| `forge_payload_hex` | `--forge-payload-hex` | string | Raw payload bytes |

### Stages

| Field | Flag | Type | Meaning |
| --- | --- | --- | --- |
| `service` | `--service` | boolean | Run the service stage on open TCP ports |
| `service_probes` | `--service-probes` | string | Allowed service probes |
| `service_fallback` | `--service-fallback` | string | Probes for silent ports without a hint, or `none` |
| `service_timeout` | `--service-timeout` | duration | Upper bound per service probe |
| `service_workers` | `--service-workers` | integer | Concurrent service workers |
| `service_rate` | `--service-rate` | integer | New service connections per second |
| `nmap_service_probes` | `--nmap-service-probes` | path | Local `nmap-service-probes` file for banner matching |
| `fingerprint` | `--fingerprint` | boolean | Device fingerprinting |
| `pcapng` | `--pcapng` | path | Capture file |
| `pcapng_max_mb` | `--pcapng-max-mb` | integer | Capture size budget in MiB (default 1024) |

Output and storage flags (`--json`, `--open`, `--dry-run`, `--db`, `--no-db`,
`--no-progress`, `--no-summary`) are CLI-only and are not part of the document.

## Remote requests

When the document arrives through the API:

- Fields that name server files are rejected: `udp_probe_file`,
  `payload_file`, `nmap_udp_probes`, `nmap_service_probes`.
- `pcapng` must be a bare `*.pcapng` file name; the server stores it in its
  `--evidence-dir`.
- The `research` profile and ICMP are refused.
- Raw SYN, ARP, NDP and capture require the server to be started with
  `--packetd`.
