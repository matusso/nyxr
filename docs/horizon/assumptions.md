# Integration assessment and inference assumptions

Shared changes follow the [NEXT GEN / HORIZON ownership and integration contract](../architecture/next-gen-horizon-contracts.md).
Inventory ownership remains NEXT GEN; experimental inference, graph, planner and
profiles remain HORIZON. This assessment is the canonical #61 integration baseline.

| Component | Existing implementation | PoC integration |
|---|---|---|
| Construction | `internal/packet/forge.go`, `ForgeFrames` | SYN and RST, existing checksums |
| Parser | `internal/packet/decoder.go`, `Decoder`/`gopacket.DecodingLayerParser` | Owned parser per trial; tuple, flags, TTL, options |
| Framing validation | `internal/packet/research_decode.go`, `DecodeResearch` | IP lengths/IPv4 checksum and fragment rejection |
| Transport | `internal/packetio`, `PacketIO` | Existing AF_PACKET/BPF/Npcap, no new driver |
| Privilege separation | `internal/packetd`, `Opener` | Existing daemon transport |
| Scheduler | `internal/scan/research.go`, `syn.go`, `syn_async.go` | Unchanged; opt-in bounded experiment runner |
| Capture | `internal/capture`, PCAPNG recorder | Bounded per-run PCAPNG export with packet/hash references; raw JSON remains authoritative |
| CLI | `cmd/nyxr/main.go` | Additive resolve/replay/explain |
| Storage/API/UI | `internal/storage`, `internal/api`, UI | Unchanged; private file export, #73 production workflow |

The synthetic lab implements PacketIO entirely in memory; it is not a second
network scan stack. Fast scan/service semantics stay unchanged. Parser
throughput benchmarks and measured baselines remain #66; no speedup is claimed.

Primary metric: SACK-permitted (kind 4, length 2) in correlated SYN/ACKs.
MSS is identical across arms; source port stays constant within pairs.
SACK padding/header size and unique sequence/IP ID tokens necessarily differ.
Ordering is randomized with an explicit seed. At least eight complete good
pairs and a two-sided exact paired sign test at alpha 0.05 are required.
Independence/stationarity are assumptions; the PoC does not validate them.
There is no multiple-feature screening, causal diagnosis or novelty claim.

| Risk/failure | Current behavior | Remaining gate |
|---|---|---|
| Loss, ICMP errors, NAT/path shift | ICMP and token-only path candidates retained; ambiguous candidates unresolved | #66 live ground truth |
| Stale/delayed replies | Fresh token checks; late evidence retains original flow ID | #66 live calibration |
| Duplicate replies | Preserve raw evidence; duplicate/retransmission/path-change quality gates | #66 live calibration |
| Transport checksum | TCP/ICMP checksums verified; offload artifacts can look like loss | #66 independent captures |
| Capture drops/caps | Drop metadata and encoded PCAPNG retention cap; incomplete capture gates inference | #66 independent captures |
| Queues, timestamp precision, clock drift | RTT descriptive; unknown precision/queue delay explicit, optional backend metadata | #69 clock calibration |
| Ambient load/throttling | Cause cannot be identified uniquely | #69 controls |
| Reused source-port state | Washout, cleanup, fresh ACK token; not proven independent | #69 cooldown/orthogonal controls |
| Cleanup failure/cancellation | Stop sends; bounded receive-only drain and cleanup outcome flags; state may expire later | #66 live backend validation |
| Kernel/target-generated traffic | Not included in runner send count | #66 independent capture |
| Fragile devices | Explicit scope still does not imply a universally safe rate | #67 policy profiles |
| Tampering | Integrity and structural replay, no signer/authentication | #73 |
| Synthetic behavior | Software validation only | #66 live ground truth |
| Generalization | Only the tested host/port is measured | #72 coverage/profile semantics |

The Phase 4 go/no-go gate remains: do not extend the inference stack if
cross-flow experiments fail to outperform matched isolated-probe controls.
