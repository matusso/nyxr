# nyxr documentation

nyxr is a cross-platform network scanner that pairs fast discovery with deep,
evidence-backed service identification, first-class UDP, OT-safe scanning and a
built-in web UI.

New to nyxr? Start with **[Getting started](getting-started.md)**.

## User guide

| Guide | What it covers |
| --- | --- |
| [Getting started](getting-started.md) | Install, first scan, web UI, shell completion, privileges |
| [Scanning](guide/scanning.md) | Targets, ports, dry runs, output, rate limits, configuration files |
| [Scan profiles](guide/profiles.md) | The profile catalog and how to choose one; the database profile |
| [UDP scanning](guide/udp.md) | Result classification, probe strategies, built-in catalog, custom probes |
| [Service identification](guide/service-identification.md) | Banner, SSH, TLS, HTTP, SOCKS and database probes; evidence; Nmap interoperability |
| [OT and IoT](guide/ot-and-iot.md) | The `ot-safe` profile, Modbus, EtherNet/IP, BACnet, device fingerprinting |
| [Raw packet scanning](guide/raw-packets.md) | Raw SYN, ARP/NDP, ICMP, platform requirements |
| [Research packets](guide/research-packets.md) | Crafted TCP flags, SCTP, raw IP protocols, fragmentation |
| [Packet capture and analysis](guide/packet-capture.md) | pcapng evidence, `decode`, the terminal packet browser, `sniff` |
| [Storage and history](guide/storage-and-history.md) | The SQLite database, `nyxr history`, retention |
| [Web UI and REST API](guide/web-ui-and-api.md) | `nyxr serve`, UI tour, API endpoints, live events, security model |
| [Deployment](guide/deployment.md) | `nyxr-packetd` privilege separation, exposing the server, containers |

## Reference

| Reference | Content |
| --- | --- |
| [CLI](reference/cli.md) | Every command and flag |
| [Configuration](reference/configuration.md) | The scan request document shared by YAML files and the API |
| [Output records](reference/output-records.md) | The `nyxr/v1` JSON record schema |

## Architecture and project

| Document | Content |
| --- | --- |
| [Architecture overview](architecture/overview.md) | How nyxr is built today: process model, packages, hot path |
| [Design brief](architecture/design.md) | The long-term product and architecture target |
| [Roadmap](roadmap.md) | Delivery status by phase and what comes next |
| [Security policy](SECURITY.md) | Supported versions and how to report a vulnerability |

## Development

| Document | Content |
| --- | --- |
| [Building and releasing](development/building-and-releasing.md) | Make targets, platforms, container image, CI and releases |
| [Testing](development/testing.md) | Unit tests, packet fixtures, fuzzing |
| [Runtime gates](development/runtime-gates.md) | Privileged Linux lab and manual macOS/Windows gates |
| [Performance](development/performance.md) | Benchmark harness and recorded baseline |
