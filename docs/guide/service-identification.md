# Service identification

Discovery tells you a port is open. The service stage tells you what is
listening, and keeps every byte it exchanged so the claim can be checked.

- [Enable the service stage](#enable-the-service-stage)
- [How a port is identified](#how-a-port-is-identified)
- [TLS](#tls)
- [HTTP](#http)
- [SOCKS](#socks)
- [Evidence](#evidence)
- [Tuning](#tuning)
- [Nmap service-probe interoperability](#nmap-service-probe-interoperability)
- [Nmap NSE scripts](#nmap-nse-scripts)

## Enable the service stage

The `service`, `deep`, `web`, `full`, `database`, `iot` and `ot-safe` profiles
run it automatically. Add `--service` to run it with any other TCP profile:

```sh
nyxr scan --profile service 192.0.2.0/28
nyxr scan --profile deep 192.0.2.10
nyxr scan --profile tcp --ports 1-1024 --service 192.0.2.10
```

The stage consumes discovery results, not packets. Every open TCP port goes into
a bounded queue served by a fixed worker pool. When the queue is full it slows
the discovery consumer, never the packet receive path.

## How a port is identified

For each open port, nyxr first listens for a banner. It then keeps a
probability distribution over protocol families and chooses each active probe
from the current evidence:

1. **Banner.** Connect and wait for the server to speak first. An
   [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253) identification string is
   reported as `ssh` with product and version (for example `OpenSSH 9.6p1`).
   SMTP greetings containing `SMTP` or `ESMTP`, POP3 greetings identifying
   Dovecot or POP3, and complete ManageSieve capability greetings are also
   recognized. A bare `220` or `+OK` stays unknown because other protocols
   use those codes. Unrecognized banners remain in the final evidence.
2. **Port hints** raise the initial probability of familiar protocols and
   make their probes eligible. They do not assert an identity:

   | Port | Candidate probes |
   | --- | --- |
   | TCP/53 | `dns` (CHAOS `version.bind`) |
   | TCP/1080 | `socks` |
   | TLS ports such as 443, 8443, 993 | `tls`, `http` |
   | HTTP ports such as 80, 8080 | `http`, `tls` |

3. **Fallback probes** on other ports, set by `--service-fallback`:
   `http` for `service`; `tls,http` for `deep`, `web` and `full`; or `none`.

After each active response, Nyxr updates `P(protocol family | evidence)` using
the probe's match likelihood. It estimates each untried probe's expected
reduction in Shannon entropy and divides that gain by the probe's relative
cost. The highest scoring eligible probe runs next. The likelihoods and costs
are explicit estimates in the planner, so these probabilities are planning
signals, not empirically calibrated product or version confidence. A validated
response still supplies the service identity and its separate confidence.

Response shape can add a safe follow-up that was not in the initial candidate
set. A RESP error to an HTTP request makes a Redis PING eligible, including on
an unusual port. A TLS listener's “HTTP request to an HTTPS server” error
causes a TLS handshake instead of a false plain-HTTP match. Each probe runs at
most once. The target's enabled probes and fallback setting still bound the
active work.

When an HTTP response itself contains a recognizable database identity (for
example an Elasticsearch product header), Nyxr extracts it from that exchange
without sending a second GET, including when HTTP is carried inside TLS.

A service is claimed only from a matched response, never from the port number.
Unrecognized or absent responses produce `fingerprint: "unknown"` with the raw
bytes retained, so they can seed future signatures.

All probes are unauthenticated, read-only handshakes. `ot-safe` permits only
the Modbus and EtherNet/IP identity reads.

Available probes for `--service-probes`: `banner`, `ssh`, `tls`, `http`, `dns`,
`socks`, `modbus`, `ethernetip`, `database`, `nmap`.

## TLS

TLS is one shared subsystem. For every handshake it records:

- Protocol version, cipher suite, ALPN, OCSP stapling and SCT count.
- The presented certificate chain: subject, issuer, serial, SANs, validity,
  key algorithm and size, signature algorithm, self-signed flag and SHA-256.

Trust is not verified; the chain is recorded as presented. nyxr then identifies
the service inside TLS: HTTP (reported as `https`, re-asking for HTTP/1.1 when
ALPN selected h2) or a server-first banner such as IMAPS.

SNI for hostname targets and alternative ClientHello profiles are not
implemented yet.

## HTTP

The HTTP probe sends `GET /` and reports the status, the `Server` header parsed
into product and version, the page title, content type, `Location` and
authentication headers.

## SOCKS

The `socks` probe identifies SOCKS4 and SOCKS5. For SOCKS5 servers that accept
no-authentication negotiation, it requests a UDP association and records the
relay address and port the server returns. That relay exists only for the TCP
session and is reported as a transient allocated endpoint; nyxr does not infer
that an unrelated static UDP port is open.

TCP/1080 is in `top100`. Use `--service-fallback socks` to try it on other
proxy ports.

## Evidence

Every exchange is kept with the observation:

| Field | Content |
| --- | --- |
| Probe and layer | Which probe ran, over `tcp` or `tls` |
| Timing | Start time and duration |
| Bytes | Request and response, up to 4 KiB per direction, flagged when truncated |
| Result | The matcher that recognized the response, or the error |

Service records also include `service_hypotheses` (the final family
probabilities) and `probe_decisions` (the selected probe, expected information
gain in bits, cost-adjusted score, and probabilities at selection time). These
make the adaptive path inspectable in JSON and stored history.

The web UI shows these exchanges under each service observation, and
`nyxr history --scan <id> --json` returns them from the database. `nyxr history
--unknown --json` lists every unrecognized response for signature work.

With a service stage active, output uses the versioned `nyxr/v1` record stream
described in [Output records](../reference/output-records.md).

## Tuning

| Flag | Default comes from | Effect |
| --- | --- | --- |
| `--service-probes` | Profile | Comma list of probes to allow |
| `--service-fallback` | Profile | Probes for silent ports without a port hint, or `none` |
| `--service-timeout` | Profile | Upper bound for each probe |
| `--service-workers` | Profile | Concurrent service workers |
| `--service-rate` | Profile | New service connections per second (`0` = unlimited) |

## Nmap service-probe interoperability

nyxr can load a user-supplied
[`nmap-service-probes`](https://nmap.org/book/vscan-fileformat.html) file at
runtime. The file belongs to the Nmap Project and is licensed under the Nmap
Public Source License. **nyxr never bundles or redistributes it.** You point
nyxr at a copy you already have, and its path and SHA-256 are recorded as
provenance.

```sh
# Summarize what can be used from a database
nyxr probe import /usr/share/nmap/nmap-service-probes
nyxr probe import /usr/share/nmap/nmap-service-probes --json

# Match banners against it during a service scan
nyxr scan --service --nmap-service-probes /usr/share/nmap/nmap-service-probes \
  --ports 21,25,80,110,143 192.0.2.10
```

`probe import` reports how many probes and match rules were read, how many
patterns compiled and how many were skipped. Patterns are compiled with Go's
RE2 engine. Patterns that need PCRE features RE2 lacks (backreferences,
lookaround, possessive quantifiers) are skipped and counted, so a database
always loads as far as it safely can.

At scan time, the `nmap` probe, enabled automatically by
`--nmap-service-probes`, matches the passively read banner against the
database's `NULL` probe rules:

- A hard match is reported at 90% confidence, a softmatch at 75%.
- The matching probe and rule line are kept in the observation's `nmap.*`
  attributes, and the banner is kept as evidence.
- No traffic is sent beyond the banner read that already happens.
- The built-in SSH, TLS, HTTP and DNS matchers take precedence.

Imported *active* TCP probes are not sent yet. For UDP payloads from the same
file, see [Using Nmap UDP probes](udp.md#using-nmap-udp-probes). Remote API
requests may not name a server-side probes file.

## Nmap NSE scripts

With Nmap installed locally, the CLI can run selected NSE scripts after nyxr
discovers open TCP or UDP ports:

```sh
nyxr scan --profile tcp --ports 80,443 --nse-scripts http-title,ssl-cert \
  --nse-timeout 30s --json 192.0.2.10
```

Use individual script names from the local Nmap installation. nyxr verifies
that every named script belongs to Nmap's `safe` category and excludes scripts
also tagged `intrusive`, `exploit`, `dos`, `external`, `fuzzer` or `brute`.
Category names, wildcards, paths, script expressions and script arguments are
not accepted. Scripts in other categories cannot run through this bridge.

Nmap rechecks nyxr's discovered open ports before applying each script's
portrule. It runs one Nmap process per host, with at most four processes at
once and a per-host timeout. The bridge accepts at most 16 named scripts and
1024 discovered open ports per scan. Nmap's scan is subject to the configured
overall or per-host rate when either is set. UDP NSE scans require the local
privileges Nmap normally requires for `-sU`.

Each result is a `script` observation in text, JSON and stored history. Its
`nse` object keeps Nmap's readable output and nested XML fields. Host script
results have `transport: "host"`. This bridge is available to local CLI scans;
the API does not execute local Nmap scripts.
