# nyxr

An early cross-platform network scanner built around the architecture in
[ROADMAP.md](ROADMAP.md). This first implementation provides a CLI with a shared
configuration contract, a full profile catalog, bounded concurrent TCP connect
and UDP probe campaigns, IPv4/IPv6 ICMP echo, ARP/NDP discovery, address and port parsing, rate
limiting, structured observations, a reusable gopacket receive decoder, and an
explicit raw IPv4 TCP SYN mode. Service identification and device fingerprinting
are available, as are a REST API with live events and a web UI served by an
unprivileged `nyxr serve`, with raw packet I/O isolated in `nyxr-packetd`. The
distributed control plane remains on the roadmap.

## Build

Go 1.27.1 or newer is required. nyxr builds without cgo:

```sh
make check      # go test + go vet
make build      # ./nyxr and ./nyxr-packetd for the host platform
sudo make install  # copy both into /usr/local/bin (PREFIX, DESTDIR honored)
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
nyxr scan --profile udp-basic --ports 53,123 192.0.2.1
nyxr scan --profile udp-common --ports 53,123 192.0.2.1
nyxr scan --profile udp-deep --udp-retries 1 --json 192.0.2.1
nyxr scan --protocols udp --ports 9999 --send-hex "010203" 192.0.2.1
nyxr scan --protocols udp --ports 9999 --payload my-probe.yaml 192.0.2.1
nyxr scan --protocols tcp,udp,icmp --timeout 2s --rate 50 192.0.2.0/28
nyxr scan --profile ot-safe --allow-targets 192.0.2.10 --dry-run 192.0.2.10
nyxr scan --profile ot-safe --allow-targets 192.0.2.0/24 --json 192.0.2.10
nyxr scan --profile iot --fingerprint --json 192.0.2.10
nyxr scan --profile udp --ports 47808 --fingerprint --json 192.0.2.10
nyxr scan --profile fast --ports top100 192.0.2.0/24
nyxr scan --profile fast --ports top100 --open 192.0.2.0/24
nyxr scan --profile udp-deep --dry-run 192.0.2.0/28
nyxr scan --profile service --db nyxr.db 192.0.2.0/28
nyxr scan --profile web --json 192.0.2.10
sudo nyxr scan --profile deep --interface eth0 --pcapng scan.pcapng 192.0.2.10
nyxr history --db nyxr.db --assets
nyxr profiles
nyxr decode capture.pcap
sudo nyxr sniff --interface eth0 --count 100
```

Targets may be IP addresses, hostnames, CIDRs, or inclusive IP ranges. Raw IPv4
SYN scans stream larger ranges; other scan modes remain limited to 65,536 unique
addresses. Ports accept commas and inclusive ranges
(`80,443,8000-8100`) or a named set: `top100` for a curated list of common TCP
ports, or `all` for `1-65535`. Use `--json` for newline-delimited observations.
`--open` shows only open ports and responsive hosts, hiding closed and
filtered results from text and JSON output; `--db` still stores everything.
`--dry-run` resolves the configuration and prints the plan — profile, target
count, ports, protocols, pacing and scheduled task count — without sending any
packet; add `--json` for the machine-readable plan. UDP has three levels:
`udp-basic` sends an empty datagram and classifies a reply or ICMP error;
`udp-common` uses payloads listed for each requested port, falling back to an
empty datagram when none apply; `udp-deep` tries every available payload on
each requested port until a reply validates a service or the catalog is
exhausted. The existing `udp` profile uses the `udp-common` strategy for
compatibility. The native catalog includes DNS status, lookup and CHAOS TXT;
DHCP, NTPv2/v3/v4, NBNS, mDNS, LLMNR, Kerberos, CLDAP search, RADIUS
authentication, IKE, L2TP, SNMPv1/v2c/v3, SSDP, SLP, BACnet, CoAP, RPC,
IPMI, TFTP, Citrix, DB2, SIP, Source, Quake, GameSpy, TeamSpeak, STUN,
memcached, and an empty datagram. `udp-deep` selects 32 common UDP ports by
default and retries each
probe once; `--ports` replaces the default port list. An empty UDP datagram is
valid under [RFC 768](https://www.rfc-editor.org/rfc/rfc768), and a silent port
remains `open|filtered` because [RFC 1122](https://www.rfc-editor.org/rfc/rfc1122)
only says a closed port should send ICMP Port Unreachable.
`--rate` limits application-level probe
sends, including UDP retries. A matching DNS transaction ID, NTP originate
timestamp, SNMP request or message ID, STUN transaction ID, SIP Call-ID or
CoAP token
raises confidence;
the token is derived from a per-scan secret. An unmatched UDP response is retained as an unknown
fingerprint with a hex evidence sample. No response is `open|filtered` with
low confidence; it is never reported as definitely open. With raw-socket
permission, a shared ICMPv4/v6 listener matches quoted UDP addresses, ports,
length and checksum to sent probes. Without that permission, the result notes
that raw ICMP is unavailable and connected UDP sockets still classify
port-unreachable errors when the OS delivers them. TFTP accepts a reply from
the server's new transfer port. Later ports on a host gain one adaptive retry
when feedback suggests loss or ICMP rate limiting. TCP uses
ordinary connect calls by default, so it works without raw packet privileges. The
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
| `udp-basic` | available | Empty UDP datagram; classify reply or ICMP response |
| `udp-common` | available | Payloads associated with each port; 32 default ports |
| `udp` | available | Compatibility name for `udp-common`; DNS and NTP ports by default |
| `udp-deep` | available | Every available UDP payload on each port; 32 default ports |
| `ot-safe` | available | Allowlisted TCP connect scan plus Modbus/EtherNet/IP identity reads |
| `custom` | available | Minimal profile; set protocols, ports and timeout explicitly |
| `service` | available | Top 100 TCP ports, then banner/SSH/TLS/HTTP/DNS/SOCKS identification |
| `deep` | available | As `service`, and tries TLS and HTTP on every silent open port |
| `web` | available | Common web ports with TLS and HTTP identification |
| `full` | available | All TCP ports plus deep service identification |
| `database` | planned | Database protocol handshakes (a later Phase 3 slice) |
| `iot` | available | TCP service identity and multi-source device fingerprinting |
| `research` | available | Allowlisted, paced raw TCP/UDP/ICMP/SCTP/IP packet experiments |

### Research packets

The `research` profile sends raw Ethernet frames and needs the same packet I/O
privileges as SYN mode. It requires `--interface` and `--allow-targets` before
any frame is sent. It accepts at most 256 targets and 1,024 ports, uses one
outstanding probe at a time, and caps the configured send rate at five frames
per second. Fragmented datagrams consume one rate slot per fragment. The
default is one TCP SYN on port 80 per target. Use `--dry-run --json` to review
the resolved scope and packet controls.

```sh
sudo nyxr scan --profile research --protocols tcp --tcp-flags xmas \
  --ports 443 --interface eth0 --allow-targets 192.0.2.0/24 \
  --dry-run 192.0.2.10
sudo nyxr scan --profile research --protocols sctp --ports 2905 \
  --interface eth0 --allow-targets 192.0.2.0/24 192.0.2.10
sudo nyxr scan --profile research --protocols ip --ip-protocol 47 \
  --interface eth0 --allow-targets 192.0.2.0/24 192.0.2.10
```

`--research-kind` is an alias for choosing exactly one research protocol when
the normal `--protocols` field is already set by a configuration file. The
builder also accepts `--forge-payload-hex`, `--fragment-size` (a multiple of
eight), `--bad-checksum`, and `--ip-length` for a deliberate length override.
TCP flags accept `fin,syn,rst,psh,ack,urg`, `null`, `xmas`, or a numeric mask.
Malformed overrides and arbitrary TCP flags are rejected outside `research`.
The research path never treats an uncorrelated reply as proof of an open port:
SCTP uses the INIT tag, TCP uses the sequence token, and ICMP errors use the
quoted addresses, protocol and probe identifier. Direct IP-protocol replies
have lower confidence because they have no transaction token. IPv6 raw
research currently requires an explicit `--next-hop-mac`; IPv4 resolves the
route and ARP neighbor automatically. Remote API requests cannot use the
research profile.

`internal/packet.ForgeFrames` provides validated Ethernet/VLAN, IPv4/IPv6,
TCP/UDP/ICMP/SCTP and raw IP protocol construction. It supports aligned IPv4
and TCP options, bounded IPv6 extension chains, checksums, and explicit
fragmentation. The CLI exposes the controls above; the additional builder
fields are available to internal callers after research policy validation.
Live raw behavior still needs privileged runtime testing on each platform.

`ot-safe` requires `--allow-targets` (literal IPs or CIDRs); every resolved
target must be inside it. It permits TCP connect on ports 80, 443, 502 and
44818 only, with a rate of 1–5 attempts per second, at most four workers and
a discovery timeout of at least three seconds. It rejects UDP/ICMP, custom
payloads, raw SYN, extra ports and unapproved service probes. The service stage
runs after discovery so its separately paced identity reads cannot overlap the
discovery sends. `--dry-run --json` includes the allowlist and service plan.
For packet-level evidence, add `--pcapng` and `--interface` with capture
privileges; the normal record stream reports each discovery attempt and retains
the request/response bytes of each identity read.

Modbus uses function 43/14 (basic Read Device Identification) on TCP/502;
EtherNet/IP uses ListIdentity on TCP/44818. Both are read-only requests and
return product/version fields with raw exchange evidence. `udp-common` sends
BACnet Who-Is on UDP/47808; `udp-deep` tries it on every requested UDP port.
If Who-Is is silent, the scanner tries a read-only Device object-identifier
query and a BBMD Foreign Device Table read. After a BACnet reply confirms the port is open,
it reads Device name, vendor, application software, firmware, model, description,
and location properties, plus the BBMD Foreign Device Table when available.
Missing optional replies leave the validated open result intact. It parses
unicast or broadcast I-Am device and vendor IDs. The scanner prefers local
UDP/47808 for these IPv4 probes and uses
an ephemeral source port if that port is busy. I-Am and FDT responses have no
transaction token, so their confidence is lower than token-validated replies.
These probes have local simulator fixtures. A live Siemens PXC22.1-E.D scan
also returned its Device identifier, name, vendor, application software,
firmware, model, description, and one FDT entry. The reported FDT timeout is
the remaining time at the moment of the scan and may change between runs.

`--fingerprint` combines matched service/UDP identities, MAC OUI prefixes and
open port patterns into a `device` record when at least two independent signals
support a claim. `iot` enables this stage by default. Its class and confidence
are accompanied by the contributing signals; a port alone never claims a device
type. An OUI prefix is retained as evidence, not expanded to a vendor name
without a vendor database. Run `--fingerprint` with UDP profiles to combine
BACnet, SNMP, mDNS, SSDP or CoAP observations from the same scan.

The identity requests follow the [Modbus application and TCP/IP guides](https://www.modbus.org/modbus-specifications),
the [BACnet Who-Is/I-Am encoding examples](https://bacnet.org/wp-content/uploads/sites/4/2022/08/Encoding.pdf),
and [ODVA's ListIdentity format](https://jp.odva.org/wp-content/uploads/2020/05/PUB00081R1_Performance_Methodology_v1.0.pdf).

For a custom UDP payload, choose one of `--payload` (native YAML definition),
`--send-hex`, `--send-base64`, or `--payload-file`. An explicit custom payload
replaces built-in probes for the scan. A native definition can target particular
ports and set its own timeout and retry count:

```yaml
schema: nyxr/udp/v1
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
(relative to the YAML file). Matchers include `any`, `dns`, `dns-status`, `dhcp`,
`nbns`, `kerberos`, `cldap`, `radius`, `ike`, `l2tp`, `snmpv1`, `ntp`, `snmp`,
`snmpv3`, `stun`, `tftp`, `ssdp`, `sip`, `coap`, `bacnet`, `bacnet-read`,
`bacnet-fdt`, `rpc`, `slp`, `ipmi`, `citrix`, `db2`, `source`, `quake`,
`gamespy`, `teamspeak`, and `memcached`. The optional `schema` defaults to
`nyxr/udp/v1` for older definitions; unknown versions are rejected. The
`extract` list can request `dns.rcode`, `dns.txt`, `cldap.attributes`,
`ntp.stratum`, `stun.message_type`,
`snmp.engine_id`, `tftp.error_code`, `ssdp.server`, `sip.status`, `coap.code`,
`bacnet.device_id`, `bacnet.vendor_id`, or `bacnet.fdt_entries`; values appear
in the observation's `fields` map. SNMPv3 engine discovery also adds
`snmp.version`, `snmp.enterprise`, `snmp.engine_id_format`,
`snmp.engine_id_data`, `snmp.engine_boots`, `snmp.engine_time_seconds`, and
`snmp.engine_time` from a valid Report. BACnet enrichment also adds
`bacnet.object_name`, `bacnet.vendor_name`, `bacnet.application_software`,
`bacnet.firmware`, `bacnet.model_name`, `bacnet.description`, and
`bacnet.location` when returned. FDT entries appear as `bacnet.fdt.0`,
`bacnet.fdt.1`, and so on, with IP, port, TTL, and remaining timeout.
`cldap.attributes` records the root DSE attributes returned by a connectionless
search, including directory naming contexts and capabilities when available.
Only `safety: safe` is accepted. A probe with no applicable port falls back to
the empty UDP datagram. Untokened protocol replies have lower confidence.

The CLI and the API share one request document, `config.Request`: the CLI
reads it from YAML and overlays flags, the API accepts the same field names as
JSON, and both call the same `Resolve` to apply the profile and validate once
before any scan runs (`internal/config`). Unknown fields are rejected in both
encodings. Every field below, including the stage fields (`service`,
`service_probes`, `service_fallback`, `service_timeout`, `service_workers`,
`service_rate`, `fingerprint`, `pcapng`, `pcapng_max_mb`) and the payload
fields (`send_hex`, `send_base64`, `payload_file`), is accepted by both, with
the remote restrictions described under [API and web UI](#api-and-web-ui).

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

## Service identification, evidence and storage

The `service`, `deep`, `web` and `full` profiles, or `--service` with any TCP
profile, feed every open TCP port from discovery into a bounded deep-probe
queue with a fixed worker pool. Each port gets a service observation:

1. **banner**: connect and wait for the server to speak first. An RFC 4253
   identification string is reported as `ssh` with product and version
   (`OpenSSH` `9.6p1`); any other banner is kept as an unknown fingerprint.
2. **port-hinted probes** for silent ports: `dns` (TCP/53, CHAOS
   `version.bind`), `socks` on TCP/1080, `tls` then `http` on TLS ports such
   as 443/8443/993, and `http` then `tls` on HTTP ports such as 80/8080.
3. **fallback probes** on other silent ports (`--service-fallback`; `http`
   for `service`, `tls,http` for `deep`, `web` and `full`, or `none`).

TLS is one shared subsystem. It records the version, cipher suite, ALPN, OCSP
stapling, SCT count and the presented certificate chain (subject, issuer,
serial, SANs, validity, key algorithm and size, signature algorithm,
self-signed flag, SHA-256), without verifying trust. It then identifies the
service inside TLS: HTTP (`https`, re-asking for HTTP/1.1 when ALPN chose h2)
or a server-first banner such as IMAPS. HTTP reports status, `Server`
(parsed into product/version), title, content type, location and
authentication headers.

The `socks` service probe identifies SOCKS4 or SOCKS5 on an open TCP port.
For SOCKS5 servers that accept no-authentication negotiation, it requests a
UDP association and records the relay address and port returned by the server.
The relay exists for that TCP session and is reported as a transient allocated endpoint;
the scanner does not infer that an unrelated static UDP port is open. TCP/1080
is in the curated `top100` port set; use `--service-fallback socks` for other
proxy ports.

Every exchange is kept as evidence: probe, layer (`tcp` or `tls`), start time,
duration, the bytes sent and received (4 KiB per direction by default, flagged
when truncated), the matcher that recognized it, or the error. A service is
claimed only from a matched response, never from the port number alone.
Unrecognized or absent responses produce `fingerprint: "unknown"` with their
raw bytes retained, so they can seed future signatures. All probes are
unauthenticated, read-only handshakes; `ot-safe` permits only Modbus and
EtherNet/IP identity reads. `--service-probes`, `--service-timeout`,
`--service-workers` and `--service-rate` override the profile. The stage
consumes discovery results, not packets: when its queue is full it slows the
discovery consumer, never the packet receive path.

With a Phase 3 stage active, output uses the versioned record stream from
`internal/observe`. Every JSON line carries `schema: "nyxr/v1"`, a `scan_id` and
a `kind`: `host`, `port`, `service`, `packet-evidence`, and finally one `scan`
summary. Plain discovery scans still print the original observation lines.

`--pcapng file` (with `--interface`) opens a separate capture handle and
records every frame to or from a target, including router ICMP errors that
quote a probe. A reader goroutine copies matching frames into a bounded queue
and a writer goroutine does the encoding and disk I/O, so scan RX workers never
wait on the file. Frames carry direction flags, a packet ID and a one-line
summary as a pcapng comment. At the end of the scan, `packet-evidence` records
link each target/transport/port to its packet IDs. Queue overflow, the size
budget (`--pcapng-max-mb`, default 1024) and backend drops are counted in the
scan summary rather than silently lost. Timestamps are taken when user space
receives a frame. ICMP errors with complete quoted UDP headers are indexed
under the UDP target and port flow. `nyxr decode` reads
these pcapng files as well as classic pcap.

### Nmap service-probe interoperability

nyxr can import a user-supplied [`nmap-service-probes`](https://nmap.org/book/vscan-fileformat.html)
file at runtime and use it to identify services from the banner a server sends
on connect. The data file is the Nmap Project's and is licensed under the Nmap
Public Source License; nyxr never bundles or redistributes it. You point nyxr at
a copy you already have, and its provenance (path and SHA-256) is recorded.

```sh
nyxr probe import /usr/share/nmap/nmap-service-probes            # summarize a database
nyxr probe import /usr/share/nmap/nmap-service-probes --json     # machine-readable
nyxr scan --service --nmap-service-probes /usr/share/nmap/nmap-service-probes \
  --ports 21,25,80,110,143 192.0.2.10
nyxr scan --profile udp-deep --nmap-udp-probes /usr/share/nmap/nmap-service-probes \
  --ports 111,2049,47808 192.0.2.10
```

`probe import` reports how many probes and match rules were read, how many
patterns compiled, and how many were skipped. Match patterns are compiled with
Go's RE2 engine; patterns that rely on PCRE features RE2 does not support
(backreferences, lookaround, possessive quantifiers) are skipped and counted
rather than failing the import, so a database always loads as far as it safely
can.

At scan time the `nmap` service probe (enabled automatically by
`--nmap-service-probes`, or named in `--service-probes`) matches the passively
read banner against the database's `NULL` probe rules and emits a service with
product and version. A hard match is reported at 90% confidence and a softmatch
at 75%, each with the matching probe and rule line kept in the observation's
`nmap.*` attributes and the banner retained as evidence. This sends no traffic
beyond the banner the deep-probe stage already reads; the built-in matchers
(SSH, TLS, HTTP, DNS) still take precedence. `--nmap-udp-probes` separately
adds usable UDP payloads from the same kind of file. `udp-common` uses its
`ports` directives to select probes; portless probes apply to any port.
`udp-deep` tries every imported probe on each requested port and uses the port
directives only to prioritize them. Built-in UDP probes are also tried. Imported
requests are limited to the maximum UDP payload size;
empty and oversized requests are skipped. Any datagram returned to an imported
request confirms an open UDP port, but without a
protocol-specific matcher its service identity is unconfirmed. This option
requires a local file and cannot be combined with a custom UDP payload.
`ot-safe` never permits these UDP probes. Remote API requests may not name a
server-side probes file.

`--db file` stores the scan in SQLite through a cgo-free driver, so every
release binary can open it. The schema is versioned with forward-only
migrations, and a database from a newer nyxr is refused. It keeps scans,
assets (address, first/last seen), observations with their full JSON record,
evidence bytes in their own table, and the packet index. Writes are batched
per transaction. Query and maintain it with `nyxr history`:

```sh
nyxr history --db nyxr.db                         # scans, newest first
nyxr history --db nyxr.db --scan <scan-id>        # observations and packet evidence
nyxr history --db nyxr.db --assets                # latest state and service per port
nyxr history --db nyxr.db --unknown --json        # unknown fingerprints for signature work
nyxr history --db nyxr.db --prune-older-than 720h # retention (or --keep 20)
```

Pruning deletes scans with their observations, evidence and packet index,
then removes assets that no longer have any records. pcapng files are left on
disk.

## API and web UI

`nyxr serve` runs the REST API, live scan events and an embedded web UI
(dashboard, scan creation with dry-run plan, running and past scans with live
results, assets, services, profiles, live packet watching, packet editing and
resending, packet evidence and pcapng download):

```sh
nyxr serve --db nyxr.db                      # http://127.0.0.1:8484
NYXR_API_TOKEN=$(openssl rand -hex 16) nyxr serve --db nyxr.db --listen 0.0.0.0:8484
```

| Method and path | Purpose |
| --- | --- |
| `GET /api/v1/profiles` | profile catalog (same as `nyxr profiles --json`) |
| `POST /api/v1/plan` | resolve a request and return the dry-run plan |
| `POST /api/v1/scans` | start a scan; `201` with the running `scan` summary |
| `GET /api/v1/scans` | stored scans, newest first, with live counters for running ones |
| `GET /api/v1/scans/{id}` | one scan summary |
| `POST /api/v1/scans/{id}/cancel` | stop a running scan; partial results are kept |
| `GET /api/v1/scans/{id}/observations` | stored records; filters `address`, `kind`, `transport`, `port`, `service`, `unknown`, `limit` |
| `GET /api/v1/scans/{id}/evidence` | packet-evidence records |
| `GET /api/v1/scans/{id}/events` | Server-Sent Events: `observation`, `packet-evidence`, `scan` |
| `GET /api/v1/scans/{id}/pcapng` | capture file, for captures in `--evidence-dir` only |
| `GET /api/v1/assets`, `GET /api/v1/observations` | asset inventory and cross-scan queries |
| `GET /api/v1/packets/watch?interface=eth0` | live Ethernet frames as Server-Sent Events; requires `--packetd` |
| `POST /api/v1/packets/send` | submit one hex Ethernet frame on an interface; requires `--packetd --allow-packet-send` |

```sh
curl -s -H 'Content-Type: application/json' localhost:8484/api/v1/scans \
  -d '{"targets":["192.0.2.10"],"ports":"22,80,443","protocols":"tcp","service":true}'
curl -N localhost:8484/api/v1/scans/<scan_id>/events
```

The request body is the `--config` document in JSON, and results are the same
`nyxr/v1` records the CLI prints. A test runs the same loopback scan through
`nyxr scan` and the API and requires identical observations apart from IDs and
timings. Remote requests may not name server files (`udp_probe_file`,
`payload_file`); `pcapng` must be a bare `*.pcapng` name, which the server
places in `--evidence-dir`.

Live events are bounded. Each running scan keeps its last 4096 events for
replay and each subscriber a 256-event queue. A subscriber that falls behind
receives `lagged` and is disconnected rather than slowing the scan. It can
resume with `Last-Event-ID` or read the stored observations. `--max-scans`
(default 1) limits concurrent scans so they do not exceed each other's rate
budgets.

Security defaults: the server listens on loopback and rejects foreign `Host`
headers, which blocks DNS rebinding. A non-loopback listener requires a bearer
token of at least 16 characters (`NYXR_API_TOKEN` or `--token-file`).
POSTs must be `application/json`, so a browser cannot submit them
cross-origin without a preflight, and the server approves no CORS requests.
The UI is served with a strict same-origin CSP and renders every scanned value
as text. Authentication beyond one shared token, RBAC, approvals and audit
trails are Phase 9 work.

The **packets** page opens a live watch on a packetd-allowed interface. It
keeps the latest 500 frames in the browser and displays up to 100 frames per
second; a busy interface reports skipped display frames. Select **clone** to
copy a captured frame into the hex editor, **send edited frame** to submit it,
or **resend** to submit its original bytes. Start the server with
`--packetd SOCKET --allow-packet-send` to enable transmission. The send API
accepts one 14–9216 byte frame per request and returns `submitted` after
packetd accepts the write; packetd's interface and source-MAC policy can still
reject it before transmission. Capture rows are not saved on the server.

### Privilege separation with nyxr-packetd

`nyxr serve` refuses to start as root or, on Linux, with `CAP_NET_RAW` or
`CAP_NET_ADMIN`, unless given `--allow-privileged`. Raw packet I/O goes through
`nyxr-packetd`, a separate binary, so the capabilities never reach the API,
UI or database code:

```sh
sudo setcap cap_net_raw,cap_net_admin+ep ./nyxr-packetd
./nyxr-packetd --socket /run/nyxr/packetd.sock --interface eth0 &
nyxr serve --db nyxr.db --packetd /run/nyxr/packetd.sock --evidence-dir ./evidence
nyxr scan --packetd /run/nyxr/packetd.sock --tcp-mode syn --interface eth0 ...
```

packetd only relays Ethernet frames, over a Unix socket (mode `0660` by
default; world access is refused). It opens only the interfaces listed in
`--interface`. It drops transmit frames that are shorter than an Ethernet
header or carry a source MAC other than the interface's. Frames are capped at
9216 bytes, sessions at `--max-clients` (default 4), and transmit rate at
`--max-pps`. Scan logic, parsing and storage stay in the unprivileged
process. Raw SYN, ARP/NDP and API pcapng capture use packetd; the API refuses
them when started without `--packetd`. Limits: ICMP echo still needs a raw IP
socket in the scanning process, so the API refuses ICMP requests for now. The
`research` profile is CLI-only. The relay was exercised end to end on macOS,
where it behaves like the local BPF backend, whose live RX/TX gate is still
open (see below). It has not yet been run on privileged Linux.

## Shell completion

`nyxr completion <shell>` prints a completion script for `bash`, `zsh`,
`fish`, or `powershell`. It completes subcommands, flags, profile names, port
sets, protocols and network interfaces:

```sh
source <(nyxr completion bash)                                  # bash, current shell
nyxr completion bash > ~/.local/share/bash-completion/completions/nyxr
nyxr completion zsh > "${fpath[1]}/_nyxr"                      # zsh, then restart the shell
nyxr completion fish > ~/.config/fish/completions/nyxr.fish     # fish
nyxr completion powershell | Out-String | Invoke-Expression     # PowerShell; add to $PROFILE
```

## Packet I/O and platform limits

The Ethernet decoder uses `gopacket.DecodingLayerParser` and preallocated
Ethernet, IPv4/IPv6, TCP, UDP, and ICMP layers. `nyxr decode` demonstrates
this path on pcap files without `PacketSource`. The packet I/O interface accepts
batches of raw Ethernet frames and keeps acquisition separate from decoding.

TCP scanning uses portable connect mode by default. To send raw IPv4 SYNs,
select an Ethernet interface. The scanner loads the routing table once, then
resolves each distinct next-hop MAC before sending a SYN. On macOS, an existing
valid entry in the selected interface's ARP cache avoids a raw ARP exchange;
otherwise the scanner sends a padded ARP request and retries silent neighbors:

```sh
sudo nyxr scan --tcp-mode syn --interface eth0 \
  --protocols tcp --ports 80,443 192.0.2.10
```

Use `--source-ip` if the interface has several IPv4 addresses. The source IP
must belong to that interface. On Windows, Npcap adapter IDs may differ from
OS interface names; supply the Npcap adapter ID with `--interface` and specify
both `--source-ip` and `--source-mac`. If the adapter cannot be mapped to an OS
route, also supply `--next-hop-mac`. This flag remains available to override
automatic route and neighbor resolution on any platform. Raw SYN mode requires
TCP-only IPv4 targets;
the `ot-safe` profile always uses connect mode. `--dry-run` includes the chosen
mode and link details; route and neighbor discovery occurs only when the scan
runs. ARP uses a separate receive handle from SYN capture. An unresolved next
hop produces a `no-response` observation without sending a SYN. On macOS,
`netstat -rn -f inet` shows the route table and `arp -n GATEWAY_IP` shows a
cached MAC.
`--next-hop-mac` can use that MAC directly. An incorrect manual MAC can cause
every probe to time out. A SYN/ACK is
`open`, a matching RST/ACK is
`closed`, and a matching ICMP destination-unreachable or timeout is `filtered`.
Replies must match the target, ports and a per-probe sequence token. Raw SYN
keeps up to 16,384 probes outstanding, expires silent probes from a bounded
deadline queue, and batches transmit calls when the configured rate permits.
A single SYN packet reader feeds bounded queues and reusable decoder workers;
received buffers are pooled so receive work does not allocate a buffer per packet.

Use `--protocols arp` for on-link IPv4 neighbors or `--protocols ndp` for
on-link IPv6 neighbors. Both require `--interface` and raw packet privileges;
results include a verified MAC address in JSON and text output. For example:

```sh
sudo nyxr scan --profile custom --protocols arp --interface eth0 --timeout 1s 192.0.2.10
sudo nyxr scan --profile custom --protocols ndp --interface eth0 --timeout 1s 2001:db8:1::10
```

`--rate` limits all probe types globally. `--host-rate` and `--subnet-rate`
limit one address and one IPv4 /24 or IPv6 /64 respectively. `--interface-rate`
applies to raw SYN and neighbor discovery sends on the selected interface.
All limits default to unlimited unless a profile specifies `--rate`.

- **Linux:** `sniff` and SYN mode use AF_PACKET. Opening it requires root or
  `CAP_NET_RAW` and an Ethernet interface.
- **macOS:** `sniff` and SYN mode use `/dev/bpf`; the process needs access to
  a free BPF device and an Ethernet interface.
- **Windows:** `sniff` and SYN mode load Npcap's `wpcap.dll` at runtime. Npcap
  must be installed and the named adapter must expose Ethernet frames.
- **ICMP:** IPv4 and IPv6 echo use raw sockets and generally need elevated
  privileges on all platforms. Permission and unsupported conditions appear as
  observations instead of silently changing scan methods.

The current packet decoder expects Ethernet frames (including a VLAN tag).
Other link types and pcapng files are not yet supported. The raw path has
deterministic [PCAP fixtures](tests/pcaps/phase0.pcap), fake-responder fault
tests, fuzz targets and six-target cross-build coverage. The
[benchmark baseline](tests/performance/README.md) records decoder and
synthetic scan throughput, allocations, CPU and injected packet loss. The
[Linux namespace lab and platform gates](tests/lab/README.md) cover live
packet behavior. A macOS BPF open and timeout smoke test passed previously,
but live RX/TX on BPF/Npcap and privileged Linux scanning remain unverified;
real NIC drop measurements are still pending.

UDP port-unreachable reporting varies by operating system and firewall. A
silent or rate-limited ICMP path remains `open|filtered`. Raw ICMP correlation
has fixture tests but still needs privileged live runtime gates on Linux,
macOS and Windows. The new protocol matchers have packet fixtures but no live
device gates. BACnet has simulator fixtures but no live OT device gate yet.

The reference checklist names a few operations that cannot be represented by
an ordinary UDP request. SOCKS4 and SOCKS5 start with a TCP connection; a
SOCKS5 UDP association also needs that TCP session. LDAP bind is a TCP
operation, so the UDP catalog uses a connectionless LDAP search instead.
DHCPDISCOVER goes to server port 67; port 68 is the client reply port. The
scanner listens on port 68 for offers when it can bind that port, and falls
back to an ephemeral port when another process owns it. Packet capture can
record offers but does not classify them by itself. The port 1813 RADIUS probe
sends a deliberately unauthenticated accounting-shaped request. A protocol
reply identifies RADIUS; silence remains `open|filtered`, since compliant
servers may discard it without a shared secret. GameSpy and Quake port lists
are hints; `udp-deep` tries those payloads on every selected port.
