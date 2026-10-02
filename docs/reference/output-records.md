# Output records

nyxr reports every result as a versioned JSON record. The CLI prints them with
`--json` (one record per line), the database stores them, and the API and web
UI serve them. The same scan produces the same records on every interface.

## Envelope

Every record carries:

| Field | Meaning |
| --- | --- |
| `schema` | `nyxr/v1`. Consumers should reject an unknown major version |
| `kind` | `host`, `port`, `service`, `script`, `device`, `packet-evidence` or `scan` |
| `scan_id` | Sortable scan identifier, such as `20261001T195109Z-c3b4a07e3884` |

A stream may interleave kinds, so readers should switch on `kind`. The `scan`
summary is always emitted last.

| Kind | Describes |
| --- | --- |
| `host` | ICMP, ARP or NDP reachability of one address |
| `port` | Discovery state of one transport port |
| `service` | Deep-probe identity of an open port |
| `script` | Nmap NSE result on a discovered open port or its host |
| `device` | Multi-source device classification |
| `packet-evidence` | Captured frames that belong to one flow |
| `scan` | Summary of the run |

> **Note.** A scan with no service stage, no capture and `--no-db` still prints
> the older envelope-less observation lines (the same fields without `schema`,
> `kind` and `scan_id`). Every other scan, including the default, which stores
> to the database, uses `nyxr/v1`.

## Observation fields

`host`, `port`, `service`, `script` and `device` records share these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `timestamp` | RFC 3339 time | When the observation was made |
| `target` | IP address | The address observed |
| `transport` | string | `tcp`, `udp`, `icmp`, `arp`, `ndp`, `sctp` or `ip` |
| `port` | integer | Port, when applicable |
| `state` | string | Ports: `open`, `closed`, `filtered`, `open\|filtered`. Hosts: `responsive`, `no-response`. Also `unknown`, `unsupported` or `error` when a probe could not decide |
| `confidence` | 0–100 | How strongly the evidence supports the state |
| `reason` | string | Why the state and confidence were assigned |
| `probe` | string | The probe that produced it, for example `tcp-connect` or `ssh` |
| `service`, `product`, `version` | string | Identified service, when matched |
| `fingerprint` | string | `matched` or `unknown` |
| `mac` | string | Verified MAC address (ARP, NDP) |
| `rtt_ns` | integer | Round-trip time in nanoseconds |
| `packets_tx`, `packets_rx` | integer | Packets sent and received for this observation |
| `probes_attempted` | list | Service probes tried, in order |
| `response_hex` | string | Sample of an unrecognized UDP response |
| `fields` | map | Extracted protocol fields, such as `dns.rcode` or `bacnet.device_id` |
| `attributes` | map | Service details, such as `ssh.software` or `nmap.*` provenance |
| `tls` | object | [TLS details](#tls), for services reached over TLS |
| `nse` | object | For `script`: Nmap script `id`, readable `output`, and recursive XML `fields` (`kind`, `key`, `value`, `children`) |
| `evidence` | list | [Probe exchanges](#evidence) |
| `signals` | list | For `device`: the observations that support the claim (`source`, `transport`, `port`, `detail`) |

NSE `script` records have `state: "reported"`, `probe: "nse/<script-id>"`, and
the discovered port and transport. Host scripts use `transport: "host"` and
omit `port`. Their `nse.output` is Nmap's text; `nse.fields` retains nested
`<table>` and `<elem>` values from Nmap XML.

### Example service record

```json
{
  "schema": "nyxr/v1",
  "kind": "service",
  "scan_id": "20261001T195109Z-c3b4a07e3884",
  "timestamp": "2026-10-01T19:51:09.528379Z",
  "target": "192.0.2.10",
  "transport": "tcp",
  "port": 22,
  "state": "open",
  "confidence": 100,
  "reason": "SSH identification string",
  "probe": "ssh",
  "service": "ssh",
  "product": "OpenSSH",
  "version": "9.6p1",
  "fingerprint": "matched",
  "rtt_ns": 0,
  "packets_tx": 0,
  "packets_rx": 0,
  "probes_attempted": ["banner"],
  "attributes": {
    "ssh.comment": "Ubuntu-3ubuntu13",
    "ssh.protocol": "2.0",
    "ssh.software": "OpenSSH_9.6p1"
  },
  "evidence": [
    {
      "probe": "banner",
      "layer": "tcp",
      "started": "2026-10-01T19:51:09.52838Z",
      "duration_ns": 211090000,
      "response": "U1NILTIuMC1PcGVuU1NIXzkuNnAxIFVidW50dS0zdWJ1bnR1MTMNCg==",
      "matched": "ssh"
    }
  ]
}
```

### Evidence

| Field | Meaning |
| --- | --- |
| `probe` | Probe name |
| `layer` | `tcp`, or `tls` when the payload was carried inside TLS |
| `started`, `duration_ns` | Timing |
| `request`, `response` | Bytes, base64-encoded in JSON; up to 4 KiB per direction |
| `truncated` | The response exceeded the retention limit |
| `matched` | Matcher that recognized the response; absent when unrecognized |
| `error` | Error, if the exchange failed |

### TLS

| Field | Meaning |
| --- | --- |
| `version`, `cipher_suite`, `alpn` | Negotiated parameters |
| `server_name` | SNI sent, if any |
| `ocsp_stapled`, `scts` | OCSP stapling and Signed Certificate Timestamp count |
| `certificates` | Chain as presented, leaf first: `subject`, `issuer`, `serial`, `dns_names`, `ip_addresses`, `not_before`, `not_after`, `public_key_algorithm`, `key_bits`, `signature_algorithm`, `self_signed`, `sha256` |

## Packet evidence

Emitted at the end of a scan with `--pcapng`, one per flow:

| Field | Meaning |
| --- | --- |
| `target`, `transport`, `port` | The flow |
| `capture` | pcapng file path |
| `packets` | Indexed frames: `id`, `timestamp`, `direction` (`tx` or `rx`), `length`, `summary` |
| `truncated` | More frames belonged to the flow than were indexed |

## Scan summary

| Field | Meaning |
| --- | --- |
| `profile` | Profile used |
| `started`, `finished` | Timing |
| `status` | `running`, `completed` or `failed` |
| `error` | Failure reason |
| `targets`, `observations`, `services` | Counters |
| `capture` | With `--pcapng`: `path`, `interface`, `written`, `bytes`, `dropped_queue`, `dropped_limit`, `backend_drops`, `flows_indexed`, `flows_truncated` |
