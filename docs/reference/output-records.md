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

All discovery scans, including `--no-db`, use this pipeline. JSON readers that
previously decoded a single envelope-less discovery object must now read JSONL
and select `kind: "host"` or `"port"`; the final line is a `"scan"` summary.
Existing discovery field names, state values and confidence units are unchanged.
Plain text still prints the original discovery lines and now also the scan
summary. `--open` filters display only; the summary counts all observations.

CLI output, live API events, history and API observation queries share the same
observation and exchange references **within a run**. Separate scans have distinct
IDs and hashes even if response bytes are equal. History returns observations and
packet evidence; scan summaries are queried separately through history's scan list
or `GET /api/v1/scans/<id>`.

## Observation fields

`host`, `port`, `service`, `script` and `device` records share these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `observation_id` | string | Measurement occurrence ID: scan ID plus stream sequence; migrated/imported records use a database namespace and stored row ID |
| `source` | object | Immutable source reference; see [Source references](#source-references) |
| `claim_status` | string | `observed`, `inferred` or `unknown`; independent of confidence and planner probabilities |
| `evidence_truncated` | boolean | Some discovery exchanges were omitted by the per-observation count bound |
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
| `service_hypotheses` | list | Final protocol-family hypotheses: `family`, `probability` (0–1); planning estimates, separate from service confidence |
| `probe_decisions` | list | Selected probe, expected `information_gain` in bits, cost-adjusted `score`, and selection-time `hypotheses`; includes nested database/application/product planning |
| `probe_updates` | list | Probe `outcome` (`matched`, `unmatched`, `inconclusive`), optional response `signal`, `before` and `after` hypotheses, `evidence_start` inclusive and `evidence_end` exclusive zero-based indices |
| `probe_stop_reason` | string | Identification, exhaustion, insufficient gain, budget limit, cancellation or connection failure |
| `response_hex` | string | Sample of an unrecognized UDP response |
| `fields` | map | Extracted protocol fields, such as `dns.rcode` or `bacnet.device_id` |
| `attributes` | map | Service details, such as `ssh.software` or `nmap.*` provenance |
| `tls` | object | [TLS details](#tls), for services reached over TLS |
| `nse` | object | For `script`: Nmap script `id`, readable `output`, and recursive XML `fields` (`kind`, `key`, `value`, `children`) |
| `evidence` | list | [Probe exchanges](#evidence) |
| `signals` | list | For `device`: the observations that support the claim (`source`, `transport`, `port`, `detail`) |
| `tcp_stack` | object | Fingerprinted SYN replies: `signature`, `status`, `probe_profile`, `observation_window_ns`, `collection_complete`, family `candidates` with confidence/reasons, up to eight `samples`, `ip_id_behavior`, `retransmission_behavior`, `repeat_intervals_ns`, `rst_behavior` and optional `truncated` |

Samples preserve TTL/initial-TTL estimate, IPv4 DF/IP ID, window, flags,
sequence/ACK, option bytes/order, optional MSS/window scale, SACK, timestamps,
ECN and option validity. See [TCP/IP stack fingerprinting](../guide/tcp-stack-fingerprinting.md).
Port confidence still describes port state; stack candidate confidence describes
an OS-family hypothesis. Device attributes may include `device.os_family`,
`device.os_confidence`, or `device.os_conflict`, separate from class confidence.

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
| `layer` | `tcp`, `udp`, or `tls` when the payload was carried inside TLS |
| `source` | Exact container and exchange pointer, including scan provenance |
| `parser_version` | Native interpretation contract (`nyxr-parser/v1`); `unknown` for migrated history |
| `claim_status` | `observed` for a matched response; `unknown` for unmatched/inconclusive exchanges |
| `completeness` | `partial` on truncation or I/O error; otherwise `unknown` unless a producer explicitly proves completeness. Retained bytes do not prove a complete session |
| `started`, `duration_ns` | Timing |
| `request`, `response` | Bytes, base64-encoded in JSON; up to 4 KiB per direction |
| `truncated` | A direction exceeded its retention limit |
| `matched` | Matcher that recognized the response; absent when unrecognized |
| `error` | Error, if the exchange failed |

### Source references

`source` has `owner` (`next-gen` or `horizon`), `sourceSchema`, `artifactID`
(`sha256:` followed by 64 lowercase hex digits), RFC 6901 `pointer`, and `runID`.
The full tuple identifies the reference. Filename, time, flow tuple and payload
similarity are insufficient identities. A retry of the same source uses the same
reference; a changed, redacted or reformatted container has a new hash.

For ordinary observations the source is the immutable `nyxr/v1` JSON artifact
produced by `observe.Observation.Seal`: the full observation, with normalized
parser/claim/completeness metadata and all retained exchanges in original order,
excluding derived `source` fields on the observation and exchanges. References
point to `""` (the root observation) or `/evidence/0`, `/evidence/1`, etc. The store
retains those exact bytes; consumers must hash those bytes rather than reserialize
a history/API representation. Half-open `probe_updates` ranges are unchanged.
`Seal` also reconstructs and verifies the source mapping from an exported stream
record. With `--no-db`, callers must retain/export the source themselves; a local
store cannot resolve bytes it never retained.

`POST /api/v1/evidence/resolve` accepts a source reference as JSON and returns
`reference`, `status` (`available` or `unavailable`), optional `reason`, and, when
available, `artifact` as base64 of the exact bytes. It validates the hash, run and
pointer before returning bytes. Pruned, external and missing source artifacts
return `unavailable` with the original provenance. Invalid reference syntax gets
HTTP 400. Resolution never opens a caller-supplied file or retrieves a URL.

UDP discovery retains matched **and unknown** responses before reusing its socket
buffer, with at most 32 exchanges and 4 KiB per direction. Overflow keeps the
first 31 and latest exchange and sets `evidence_truncated`; oversized directions
set `truncated`. `response_hex` remains the original 128-byte compatibility sample.
A socket-scoped or unrecognized response does not claim a protocol match. Service
and discovery exchange completeness does not assert a full transport session.

`nyxr horizon references report.json` validates the sealed envelope using the
existing HORIZON offline replay implementation and emits a `nyxr/v1`
`experiment-reference` adapter record. Its references hash the **original file
bytes**, not Replay's re-encoded output. It preserves experiment hash, run, pair,
arm, flow token and quality flags; pointers include `/report`,
`/report/experiment`, `/report/trials/0` and `/report/trials/0/evidence/0`.
This adapter uses `source.runID` for experiment provenance instead of a scan ID.
Trials with retained RX evidence are `observed`; those without it are `unknown`.
Keep the envelope unchanged to resolve them through `horizon.ResolveReference`.
Raw captures and comparison/graph ownership stay with HORIZON. This adapter
neither merges inventory assets nor enables experiment API/UI or live execution.

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
| `capture_artifact_id` | SHA-256 of the retained pcapng container; combine with `scan_id`, packet `id` and direction. Absent for historical captures whose exact container was not hashed |
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
| `capture` | With `--pcapng`: `path`, `artifact_id`, `interface`, `written`, `bytes`, `dropped_queue`, `dropped_limit`, `backend_drops`, `flows_indexed`, `flows_truncated` |
