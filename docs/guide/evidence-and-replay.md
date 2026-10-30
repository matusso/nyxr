# Evidence navigation and probe replay

A stored service claim can be followed down to the bytes and packets behind it,
and one of its exchanges can be cloned into an editable
[Protocol DSL](protocol-dsl.md) definition and replayed. This connects the
existing pieces (retained exchanges, the detection path, pcapng evidence and the
packet editor) without a second capture store or packet engine.

```text
service claim → planner decisions → retained exchange → indexed pcapng packets → packet editor
                                         ↓
                                   clone probe → edit → dry run → offline replay | live resend
```

## Navigate a claim

An observation ID is the `observation_id` of a stored record: `<scan_id>/<n>`
for a scan, or `store:<namespace>/<n>` when the store assigned it. Find it with
`nyxr history --scan <id> --json` or the API's observation queries.

```sh
nyxr evidence show 20261030T060608Z-70dc21e9bf78/2
nyxr evidence show --frames 20261030T060608Z-70dc21e9bf78/2     # also print the frames as hex
nyxr evidence show --json 20261030T060608Z-70dc21e9bf78/2       # nyxr/evidence-trace/v1
```

The trace lists:

- **Decisions:** the planner's `probe_updates`, and the half-open range of
  exchanges each one cites.
- **Exchanges:** each retained exchange with its source reference, outcome,
  completeness, truncation, byte counts, the decisions that cite it, and the
  packet IDs captured while it ran.
- **Packets:** the capture index for the claim's flow (`target`, `transport`,
  `port`). Packet IDs are exact pcapng `epb_packetid` values. Associating a
  packet with one exchange uses capture time, so that link is an inference.
- **Replays:** every recorded replay of this claim's exchanges.

The packet side always carries a status. Missing evidence is reported, never
hidden:

| Status | Meaning |
| --- | --- |
| `available` | Packets were indexed for this flow and nothing was dropped |
| `partial` | Packets exist, but the flow index was truncated or the capture dropped frames (queue, size budget or backend). Missing packets are not evidence that nothing was sent |
| `unavailable` | The scan had no `--pcapng`, is still running, was pruned, or indexed no packets for this flow |

`--frames` and the API's frame endpoint read the capture only after checking
that it still has the recorded size and SHA-256. A modified capture is
reported as unavailable.

## Clone a probe

```sh
nyxr probe clone --exchange 1 -o redis-ping.yaml 20261030T060608Z-70dc21e9bf78/2
```

The draft is a `nyxr/protocol/v2` definition that sends the retained request,
reads at most as many bytes as were retained, and expects the first response
bytes. Its `provenance` names the source artifact and pointer. TLS-layer
exchanges start with `tls: true`. Native QUIC, DTLS and HTTP/3 handshakes cannot
be cloned into byte steps. `-o` never overwrites an existing file. A probe
that wrote several times is retained as one request, so split it into several
`send` steps if the protocol needs them.

## Dry run, offline replay and live resend

```sh
# Exact target, transport and traffic bounds; nothing runs
nyxr probe replay --exchange 1 --definition redis-ping.yaml --dry-run 20261030T060608Z-70dc21e9bf78/2

# Offline: feed the retained response to the edited parser; sends nothing
nyxr probe replay --exchange 1 --definition redis-ping.yaml 20261030T060608Z-70dc21e9bf78/2

# Live: one connection to the original target and port only
nyxr probe replay --exchange 1 --definition redis-ping.yaml --live --target 192.0.2.10 20261030T060608Z-70dc21e9bf78/2
```

The definition must be self-contained (no modules or `extends`), and its
transport and ports must cover the claim's port. The plan reports the mode,
definition hash, source reference, target, connection count, timeout, step
budget, and upper bounds on bytes sent and received, including bounded
repeats.

**Offline replay** never opens a socket. An in-memory peer serves the retained
response and discards whatever the definition sends. TLS steps are skipped
because TLS-layer evidence is already plaintext. The run sets
`request_matches_evidence: false` when the edited request differs from the
retained one. In that case the result shows how the parser reads the original
reply, not how the target would answer the edited request. With the same
definition and evidence, repeated offline runs produce the same outcome,
fields and bytes.

**Live resend** must be requested explicitly with `--live` and the original
target (`--target`). It opens one connection with the definition's timeout and
is refused for scans made with the `ot-safe` profile. Through the API it also
needs an API token and `serve --allow-packet-send`.

Every run, offline or live, is recorded as a new `nyxr/probe-run/v1` record.
The original observation, its exchanges and its source artifact are never
changed. A live run also becomes its own scan (profile `probe-replay`) holding
one `probe-replay` record, so its traffic appears in history. That record is
not a service claim and does not change an asset's service identity.

| Run status | Meaning |
| --- | --- |
| `matched` | The definition's expectations matched |
| `unmatched` | The exchange completed, but no expectation matched |
| `partial` | Some bytes were retained, but the run ended in an error, a cut-short framed response or truncation |
| `failed` | No response was retained: the connection failed or the peer stayed silent until an error |

## Web UI

Service observations with retained exchanges link to **Trace evidence**. The
page shows the claim, its decisions, its exchanges with their packet IDs, and
the capture status with its reasons. **Open in editor** loads an indexed frame
into the existing packet editor on the **packets** page; sending it from there
still needs `--allow-packet-send`. **Clone probe** opens an editable draft with
**dry run**, **offline replay** and **live resend**. Live resend asks for
confirmation and the original target. The replay table lists every recorded run.

## Retention

`nyxr history --prune-older-than` and `--keep` also remove replay records. A live
run is deleted with its own scan. An offline run is deleted when the scan it
replayed is pruned, because it only describes that scan's retained evidence.
pcapng files stay on disk for the operator to manage, as before.

## Limits

- At most 256 frames are resolved per request; the flow index itself is bounded
  by the capture recorder.
- Offline replay waits at most one second for bytes the retained response does
  not contain.
- A definition sent to the API is limited to 64 KiB; the CLI accepts the DSL's
  1 MiB file limit.
- Unit, loopback and replay tests cover these paths. They do not validate live
  resends against production services.
