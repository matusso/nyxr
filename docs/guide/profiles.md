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

The `tcp-*` and `udp-*` families go from `basic` (find open ports) through
`common` (identify what answers on common ports) to `full` (every port or every
payload). `full` runs both transports.

| Profile | Summary | Privileges |
| --- | --- | --- |
| `tcp-basic` | Top 100 TCP ports, connect scan, open ports only (the default) | None |
| `tcp-common` | Top 1000 TCP ports, then banner, SSH, TLS, HTTP, DNS and SOCKS identification | None |
| `tcp-full` | All 65535 TCP ports, then service identification | None |
| `udp-basic` | Empty UDP datagram; classifies a reply or ICMP response | None |
| `udp-common` | Payloads associated with each port | None |
| `udp-full` | Every available UDP payload on each port, one retry | None |
| `full` | `tcp-full` plus `udp-common` | None |
| `web` | Common HTTP and HTTPS ports with TLS and HTTP identification | None |
| `database` | Database ports with response-validated identity probes | None |
| `iot` | TCP service identity and multi-source device fingerprinting | None |
| `ot-safe` | Allowlisted, paced TCP connect scan plus Modbus and EtherNet/IP identity reads | None |
| `research` | Allowlisted, paced raw TCP/UDP/ICMP/SCTP/IP packet experiments | Raw Ethernet |
| `custom` | Minimal profile; set protocols, ports and timeout explicitly | Depends on protocols |

ICMP, ARP, NDP and raw SYN need raw packet access with any profile. See
[Getting started](../getting-started.md#privileges-at-a-glance).

Earlier releases had `discovery`, `fast`, `tcp`, `service`, `deep`, `udp` and
`udp-deep`. Selecting one of them now fails with the name of its replacement:

| Removed | Use |
| --- | --- |
| `discovery`, `fast`, `tcp` | `tcp-basic` |
| `service`, `deep` | `tcp-common` |
| `udp` | `udp-common` |
| `udp-deep` | `udp-full` |

## Choosing a profile

| Goal | Profile |
| --- | --- |
| Find live hosts and open ports quickly | `tcp-basic`, then `--known-open` |
| Know what is running on each port | `tcp-common`, or `tcp-full` for every port |
| Inventory a host completely | `full` |
| Audit web endpoints and certificates | `web` |
| Inventory database servers | `database` |
| Find UDP services | `udp-common`, or `udp-full` for thorough coverage |
| Classify IoT devices | `iot`, or a UDP profile with `--fingerprint` |
| Identify industrial controllers safely | `ot-safe` |
| Test firewall and IDS behavior with crafted packets | `research` |

## TCP and service profiles

`tcp-common`, `tcp-full`, `full` and `web` run the deep-probe stage on every
open TCP port and try `tls,http` on ports that send nothing. `tcp-basic` only
reports port state; add `--service` to identify services with it.

| Profile | TCP ports | Rate |
| --- | --- | --- |
| `tcp-basic` | `top100` | 300/s |
| `tcp-common` | `top1000` | 500/s |
| `tcp-full` | `all` | 1000/s |
| `full` | `all` | 1000/s |
| `web` | `web`: 80, 81, 443, 591, 593, 2082, 2083, 2086, 2087, 2095, 2096, 3000, 3001, 4000, 4200, 4343, 4433, 4443, 5000, 5001, 5601, 5800, 7000, 7001, 7080, 7443, 8000, 8001, 8008, 8009, 8010, 8080–8083, 8088, 8090, 8181, 8443, 8444, 8800, 8880, 8888, 9000, 9001, 9080, 9090, 9200, 9443, 10000, 10443, 18080 | 200/s |

Details are in [Service identification](service-identification.md).

## UDP profiles

| Profile | Strategy |
| --- | --- |
| `udp-basic` | One empty datagram per port |
| `udp-common` | Payloads listed for each requested port, falling back to an empty datagram |
| `udp-full` | Every available payload on every requested port until a reply validates a service; one retry per probe |

All three default to the `udp` port set: the 32 ports that have a built-in
payload. `full` uses the same set for its UDP half while scanning every TCP
port. An explicit `--ports` applies to both transports.

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
