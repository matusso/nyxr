# Scan profiles

A profile supplies default ports, protocols, timeouts, pacing and stages for a
scan. Explicit flags and configuration-file fields override those defaults.

```sh
nyxr profiles          # list the catalog
nyxr profiles --json   # machine-readable
```

A profile whose engine is not implemented yet is listed as `planned` and
refuses to run with a message naming the roadmap phase it needs. nyxr never
silently downgrades a planned profile to a weaker scan.

## Catalog

| Profile | Summary | Privileges |
| --- | --- | --- |
| `discovery` | Common TCP ports, unprivileged connect scan (the default) | None |
| `fast` | Top 100 TCP ports at higher concurrency | None |
| `tcp` | TCP connect scan of common ports | None |
| `udp-basic` | Empty UDP datagram; classifies a reply or ICMP response | None |
| `udp-common` | Payloads associated with each port; 32 default ports | None |
| `udp` | Compatibility name for `udp-common`; DNS and NTP ports by default | None |
| `udp-deep` | Every available UDP payload on each port; 32 default ports | None |
| `service` | Top 100 TCP ports, then banner, SSH, TLS, HTTP, DNS and SOCKS identification | None |
| `deep` | As `service`, and tries TLS and HTTP on every silent open port | None |
| `web` | Common web ports with TLS and HTTP identification | None |
| `full` | All TCP ports plus deep service identification | None |
| `database` | Database ports with response-validated identity probes | None |
| `iot` | TCP service identity and multi-source device fingerprinting | None |
| `ot-safe` | Allowlisted, paced TCP connect scan plus Modbus and EtherNet/IP identity reads | None |
| `research` | Allowlisted, paced raw TCP/UDP/ICMP/SCTP/IP packet experiments | Raw Ethernet |
| `custom` | Minimal profile; set protocols, ports and timeout explicitly | Depends on protocols |

ICMP, ARP, NDP and raw SYN need raw packet access with any profile. See
[Getting started](../getting-started.md#privileges-at-a-glance).

## Choosing a profile

| Goal | Profile |
| --- | --- |
| Find live hosts and open ports quickly | `fast`, then `--known-open` |
| Know what is running on each port | `service`, or `deep` for non-standard ports |
| Audit web endpoints and certificates | `web` |
| Inventory database servers | `database` |
| Find UDP services | `udp-common`, or `udp-deep` for thorough coverage |
| Classify IoT devices | `iot`, or a UDP profile with `--fingerprint` |
| Identify industrial controllers safely | `ot-safe` |
| Test firewall and IDS behavior with crafted packets | `research` |

## Service profiles

`service`, `deep`, `web` and `full` run the deep-probe stage on every open TCP
port. They differ in their port list and in the fallback probes used on ports
that send nothing:

| Profile | Ports | Fallback for silent ports |
| --- | --- | --- |
| `service` | `top100` | `http` |
| `deep` | `top100` | `tls,http` |
| `web` | 80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443 | `tls,http` |
| `full` | `all` | `tls,http` |

Details are in [Service identification](service-identification.md).

## UDP profiles

| Profile | Strategy |
| --- | --- |
| `udp-basic` | One empty datagram per port |
| `udp-common` | Payloads listed for each requested port, falling back to an empty datagram |
| `udp` | Same strategy as `udp-common`; kept for compatibility |
| `udp-deep` | Every available payload on every requested port until a reply validates a service; one retry per probe |

See [UDP scanning](udp.md).

## Database profile

```sh
nyxr scan --profile database 192.0.2.10
nyxr scan --profile database --dry-run --json 192.0.2.10   # review ports and probes
```

The `database` port set covers common SQL, document, key-value, graph, search,
time-series, vector and cache endpoints. Use `--ports` to narrow or extend it.

Built-in probes actively validate:

- Redis-compatible RESP and Memcached
- PostgreSQL-compatible SSL negotiation
- MongoDB `OP_MSG`
- Neo4j Bolt
- Cassandra CQL
- SQL Server TDS
- HTTP identities of Elasticsearch, OpenSearch, CouchDB, InfluxDB, ArangoDB,
  ClickHouse, Qdrant, Meilisearch and Neo4j

MySQL and MariaDB greetings are validated passively. A recognized port with an
unsupported or unrecognized response stays `unknown` and keeps its evidence;
nyxr does not infer the product from the port number. The port set also
includes products for which no active matcher exists yet.

Add `--nmap-service-probes FILE` to apply the passive banner rules of a local
Nmap probe file as well. See
[Nmap interoperability](service-identification.md#nmap-service-probe-interoperability).

## OT, IoT and research profiles

These profiles enforce extra safety rules and have their own guides:

- [`ot-safe` and `iot`](ot-and-iot.md)
- [`research`](research-packets.md)
