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
payload); `deep-scan` runs both transports.

| Profile | Summary | Privileges |
| --- | --- | --- |
| `tcp-basic` | Top 100 TCP ports, connect scan, open ports only (the default) | None |
| `tcp-common` | Top 1000 TCP ports, then banner, SSH, TLS, HTTP, DNS and SOCKS identification | None |
| `tcp-full` | All 65535 TCP ports, then service identification | None |
| `udp-basic` | Empty UDP datagram; classifies a reply or ICMP response | None |
| `udp-common` | Payloads associated with each port | None |
| `udp-full` | Every available UDP payload on each port, one retry | None |
| `deep-scan` | `tcp-full` plus `udp-common` | None |
| `windows` | Windows and Active Directory services: SMB, RDP, MSRPC, NetBIOS, WinRM, LDAP and Kerberos with deep identification | None |
| `filesystem` | Network file systems and object storage: NFS, SMB/CIFS, Ceph, GlusterFS, iSCSI, MinIO and S3-compatible storage | None |
| `web` | Common HTTP and HTTPS ports with TLS and HTTP identification | None |
| `database` | Database ports with response-validated identity probes | None |
| `iot` | TCP service identity and multi-source device fingerprinting | None |
| `ot-safe` | Allowlisted, paced TCP connect scan plus Modbus and EtherNet/IP identity reads | None |
| `research` | Allowlisted, paced raw TCP/UDP/ICMP/SCTP/IP packet experiments | Raw Ethernet |
| `custom` | Minimal profile; set protocols, ports and timeout explicitly | Depends on protocols |

ICMP, ARP, NDP and raw SYN need raw packet access with any profile. See
[Getting started](../getting-started.md#privileges-at-a-glance).

Earlier releases had `discovery`, `fast`, `tcp`, `service`, `deep`, `udp`,
`udp-deep` and `full`. Selecting one of them now fails with the name of its
replacement:

| Removed | Use |
| --- | --- |
| `discovery`, `fast`, `tcp` | `tcp-basic` |
| `service`, `deep` | `tcp-common` |
| `udp` | `udp-common` |
| `udp-deep` | `udp-full` |
| `full` | `deep-scan` |

## Choosing a profile

| Goal | Profile |
| --- | --- |
| Find live hosts and open ports quickly | `tcp-basic`, then `--known-open` |
| Know what is running on each port | `tcp-common`, or `tcp-full` for every port |
| Inventory a host completely | `deep-scan` |
| Identify Windows and Active Directory hosts | `windows` |
| Inventory file servers and object storage | `filesystem` |
| Audit web endpoints and certificates | `web` |
| Inventory database servers | `database` |
| Find UDP services | `udp-common`, or `udp-full` for thorough coverage |
| Classify IoT devices | `iot`, or a UDP profile with `--fingerprint` |
| Identify industrial controllers safely | `ot-safe` |
| Test firewall and IDS behavior with crafted packets | `research` |

## TCP and service profiles

`tcp-common`, `tcp-full`, `deep-scan`, `windows`, `filesystem` and `web` run the
deep-probe stage on every open TCP port and try `tls,http` on ports that send
nothing. `tcp-basic` only reports port state; add `--service` to identify
services with it.

| Profile | TCP ports | Rate |
| --- | --- | --- |
| `tcp-basic` | `top100` | 300/s |
| `tcp-common` | `top1000` | 500/s |
| `tcp-full` | `all` | 1000/s |
| `deep-scan` | `all` | 1000/s |
| `windows` | `windows`: 88, 135, 139, 389, 445, 464, 593, 636, 1433, 2179, 3268, 3269, 3389, 5357, 5900, 5985, 5986, 47001, 49152–49154 | 300/s |
| `filesystem` | `filesystem`: 111, 139, 445, 548, 988, 2049, 3260, 3300, 3900, 6789, 6800, 6801, 7480, 8020, 8333, 9000, 9001, 9864, 9870, 20048, 24007, 50070 | 200/s |
| `web` | `web`: 80, 81, 443, 591, 593, 2082, 2083, 2086, 2087, 2095, 2096, 3000, 3001, 4000, 4200, 4343, 4433, 4443, 5000, 5001, 5601, 5800, 7000, 7001, 7080, 7443, 8000, 8001, 8008, 8009, 8010, 8080–8083, 8088, 8090, 8181, 8443, 8444, 8800, 8880, 8888, 9000, 9001, 9080, 9090, 9200, 9443, 10000, 10443, 18080 | 200/s |

Details are in [Service identification](service-identification.md).

## UDP profiles

| Profile | Strategy |
| --- | --- |
| `udp-basic` | One empty datagram per port |
| `udp-common` | Payloads listed for each requested port, falling back to an empty datagram |
| `udp-full` | Every available payload on every requested port until a reply validates a service; one retry per probe |

All three default to the `udp` port set: the 32 ports that have a built-in
payload. `deep-scan` uses the same set for its UDP half while scanning every TCP
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

## Windows profile

```sh
nyxr scan --profile windows 192.0.2.10
nyxr scan --profile windows --dry-run --json 192.0.2.10   # review ports and probes
```

The `windows` port set covers the TCP services a Windows host and an Active
Directory domain propagate: the MSRPC endpoint mapper (135), NetBIOS session
(139), SMB (445), RDP (3389), WinRM (5985/5986/47001), RPC-over-HTTP (593),
LDAP, Global Catalog and Kerberos for domain controllers (88, 389, 464, 636,
3268, 3269), SQL Server (1433), Hyper-V VMConnect (2179), WSDAPI (5357), VNC
(5900) and the usual dynamic RPC range (49152–49154). Its UDP half adds
Kerberos, NetBIOS name service, SNMP, the CLDAP domain locator, SSDP, mDNS and
LLMNR.

Three deep probes gather as much as an unauthenticated client is shown:

- **SMB** completes an SMB2 negotiate (dialect, signing policy, server GUID,
  capabilities and clock) and reads the NTLM challenge the server returns to an
  anonymous session setup, which reveals the NetBIOS and DNS computer and domain
  names, the forest and the OS build. No credentials are sent and authentication
  never completes. A host that only speaks SMBv1 is still identified and flagged.
- **RDP** performs the X.224 security negotiation, reporting the selected
  security layer and whether Network Level Authentication is required, and
  records the TLS certificate when the server offers one.
- **MSRPC** binds to the endpoint-mapper interface and reports the server's
  secondary address, or the rejection, as proof of a DCE/RPC endpoint mapper.
- **LDAP** reads the rootDSE anonymously. On a domain controller it names the
  Active Directory domain and forest, the DC's DNS name, the domain and forest
  functional levels and the SASL mechanisms; other directories report their
  vendor and naming contexts.
- **Kerberos** sends one AS-REQ for a non-existent principal and reads the KDC's
  error reply, which confirms the KDC and discloses its realm. It never submits
  or guesses a credential.

Every exchange is kept as evidence, and a port only ever claims a service from a
matched response. Add `--service-probes smb,rdp,msrpc,ldap,kerberos` to run these
probes under another profile, for example against a single `--ports 445` target.

## Filesystem profile

```sh
nyxr scan --profile filesystem 192.0.2.10
nyxr scan --profile filesystem --dry-run --json 192.0.2.10   # review ports and probes
```

The `filesystem` port set covers network file systems and object storage: the
ONC RPC portmapper (111), SMB/CIFS (139, 445), AFP (548), Lustre (988), NFS
(2049), iSCSI (3260), Ceph monitors and OSDs (3300, 6789, 6800, 6801), Garage
(3900), the Ceph RADOS Gateway (7480), HDFS (8020, 9864, 9870, 50070),
SeaweedFS (8333), MinIO (9000, 9001), NFS mountd (20048) and GlusterFS
management (24007).

Identification combines several probes:

- **NFS** sends an ONC RPC NULL to the NFS program on 2049, reporting the
  advertised versions, and on the portmapper (111) dumps the registered RPC
  programs, which reveals the whole NFS stack (`nfs`, `mountd`, `nlockmgr`,
  `status`).
- **SMB/CIFS** is identified by the SMB probe (see the Windows profile).
- **Ceph** monitors and OSDs send a messenger banner on connect, which the
  passive banner probe recognizes.
- **Object storage** — MinIO, the Ceph RADOS Gateway, SeaweedFS and other
  S3-compatible endpoints speak HTTP, so the HTTP probe identifies them from the
  `Server` header and the Amazon S3 request-id response header.

## OT, IoT and research profiles

These profiles enforce extra safety rules and have their own guides:

- [`ot-safe` and `iot`](ot-and-iot.md)
- [`research`](research-packets.md)
