# NEXT GEN and HORIZON ownership and integration contracts

Contract revision: **`nyxr/integration/v1alpha1`**. Assessment: **2026-10-09**.
Delivery: [NEXT GEN #75](https://github.com/matusso/nyxr/issues/75),
[NEXT GEN project](https://github.com/users/matusso/projects/3),
[HORIZON project](https://github.com/users/matusso/projects/2).

This is the design contract for future integration changes. The adapter metadata
below is specified here, not implemented wire fields or new endpoints. Existing
records, DSLs, transport and admission remain authoritative until their owning
issues implement compatible adapters. Source review establishes a local baseline,
not code publication, external approval, live validation or production readiness.

## Responsibility owners

NEXT GEN owns ordinary discovery, application identification and its service
planner, physical/virtual inventory, observed topology, application-response
clustering and operational change monitoring. Extend the existing `internal/scan`,
`internal/service`, `internal/observe`, `internal/storage` and pipeline/API/UI.

HORIZON owns paired control/treatment experiments, experiment admission and
sequencing, cross-flow state inference, experimental statistics, transport-state
graph, experiment planner and behavior profiles. Extend `internal/horizon`.
An inferred shared firewall, NAT, proxy or backend is a typed experimental
relationship, never an automatic inventory join or observed physical device.

Shared dependencies are the existing packet forge/decoder, PacketIO, packetd,
capture, persistence primitives and telemetry/UI components. The package's
existing responsibility identifies its implementation owner. Changes affecting
both consumers require review by both workstreams; these are responsibility
owners, not assignments to invented people or teams. Do not create another
observation bus, packet stack, store, compiler or competing HORIZON graph/planner.
An open port is a selection input, not authorization to run an experiment.

## Complete roadmap coverage

**Implemented** means present in the assessed local source, often with incomplete
aspirational details. **NEXT GEN-owned** and **HORIZON-owned** identify remaining
delivery. **Shared dependency** means reuse existing primitives/canonical work.
**Deferred** means unavailable until the named gate passes. Record publication
separately with a remote commit/release and live validation with a dated runtime
artifact. Local fixtures satisfy neither. Issue numbers below refer to
`https://github.com/matusso/nyxr/issues/<number>`; acceptance details remain in
those canonical issues.

### NEXT GEN

All numbered [roadmap](../NEXT_GEN_ROADMAP.md) sections are mapped below.
The priority overview and recommended top five refer to the same feature rows.

| Section / feature | Implemented local baseline | Remaining classification and canonical delivery |
| --- | --- | --- |
| 1 Adaptive probing | Bounded classifier, information-gain service planner, native/DSL executor and decisions | NEXT GEN-owned calibration #78 and efficiency #90; experimental selection is HORIZON #72 |
| 2 Application DSL | `nyxr/protocol/v1`, TCP/UDP, bounded branch/repeat, TLS/STARTTLS and extraction | NEXT GEN-owned v2 transports, reuse, arithmetic/reload #79; experiment DSL stays HORIZON #67 |
| 3 Asset identity | Persistent local/global/scoped portable IDs, strong-key joins, review/membership history and imported LLDP/interface/VLAN clues | NEXT GEN-owned temporal topology #80, cloud collection #83 and reconciliation #99; experimental dependencies never merge assets |
| 4 Evidence/transcripts | Bounded exchanges, decision-to-evidence ranges, packet index, history and inspection/edit/send | NEXT GEN-owned uniform records/references #76 and linked probe workflow #82; shared experiment capture #68/presentation #73 |
| 5 Deep UDP | Native tokens, ICMP correlation, late replies, retries, DTLS and service exchanges | NEXT GEN-owned multi-datagram/timing #84, multicast/broadcast #91, remaining protocols #92; shared decoder/lab #66/#68 |
| 6 QUIC/HTTP3 | Native QUIC, HTTP/3, TLS and bounded transport evidence | NEXT GEN-owned verified 0-RTT/WebTransport semantics and stable fingerprints #93 |
| 7 Stack/application fingerprints | IPv4 raw SYN evidence, cautious family rules, TLS certificates and verified SSH keys | NEXT GEN-owned calibration #78, production IPv6 #81, TLS/SSH fingerprints #85 and endpoint signatures #86; controlled long/cross-flow experiments stay HORIZON #69/#70/#71 |
| 8 AF_XDP | Opt-in Linux copy-mode backend, portable backends and batched scan workers | NEXT GEN-owned live correctness/tuning #77; shared lab #66; zero-copy/NUMA/RSS optimization deferred until measured support |
| 9 OT/ICS | Read-only Modbus/CIP/BACnet and `ot-safe` admission | NEXT GEN-owned S7/OPC UA #87; gated DNP3, IEC-104, PROFINET, KNX, Moxa, Fox, FINS, MELSEC and Schneider slices #97; shared policy #67; control writes/stress excluded |
| 10 Unknown protocols | Unknown response bytes and inconclusive hypotheses retained | NEXT GEN-owned behavioral features, clustering/proprietary families #88; HORIZON profiles stay #72 |
| 11 Passive + active | Capture/sniff and offline passive IP/LLDP import | NEXT GEN-owned live ingestion #98 and separately authorized learned-target verification #100; shared capture #68 |
| 12 Differential/continuous | Scan, identity membership/review history and retention | NEXT GEN-owned comparable exposure diffs #89 and recurring monitoring/alerts #94; HORIZON profile drift stays #72 |
| 13 Distributed | Standalone engines, REST/SSE and local packetd | NEXT GEN-owned authenticated controller/agent leases #95 and central evidence/reconciliation #99; experimental dispatch deferred to #72/#73 admission |
| 14 Finding pipeline | User-supplied Nmap/NSE bridge and structured script records | NEXT GEN-owned downstream adapters #96; a vulnerability engine is deferred/outside this contract |
| 15 Confidence | Separate heuristic state, service, OS, device and identity scores | NEXT GEN-owned ordinary calibration #78; HORIZON-owned experimental statistics #69/#71; no shared score interpretation |
| 16 Intelligence metrics | Packet/capture counters, attempts, decisions and stop reasons | NEXT GEN-owned summaries/explicit fixed-plan savings baseline #90; shared exporters, separate experiment metrics #72/#73 |
| 17 Result model | `nyxr/v1` observations and stored asset graph | Shared dependency #76 references; NEXT GEN-owned temporal inventory #80; illustrative object does not replace current records |
| 18 Architecture | Existing pipeline, service workers, observe, capture and SQLite | Shared dependency #75/#76; optional HORIZON target adapter, no replacement bus/store |
| 19 Phases 1–5 | Adaptive core, DSL v1, identity/evidence, core UDP/QUIC and AF_XDP copy-mode exist | NEXT GEN-owned remaining slices above; do not rebuild foundations; shared live lab #66 before performance claims |
| 20 Phases 6–10 | Partial IPv6, fingerprints, OT and historical inventory | NEXT GEN-owned #80/#81/#85/#86/#87/#88/#89/#91/#94/#95/#97/#98/#99; deferred slices follow actual prerequisites |
| 21 CLI direction | Existing scan/history/identity/capture/packet research commands | NEXT GEN-owned evidence #82, diff #89, distributed #95, listen #98, learned targets #100; proposed flags/commands remain illustrative |
| 22 Example output | Current observations/counters | NEXT GEN-owned #90; aggregate confidence/savings deferred until comparable calibrated populations and explicit baselines exist |
| 23 Success criteria | Evidence-backed service and inventory foundations | NEXT GEN-owned acceptance across rows above; vision examples do not establish completion |

### HORIZON

All [roadmap](../HORIZON_ROADMAP.md) sections 1–16, phases and initial experiment
catalog entries are mapped below. #61–#65 describe the local PoC; #66–#74 retain
their independent research/product gates.

| Sections / feature | Implemented local baseline | Remaining classification and canonical delivery |
| --- | --- | --- |
| 1–2 Vision/constraints | Opt-in runner preserves fast scanning; no causal/topology claim | HORIZON-owned research; full coverage, authorization, bounds and uncertainty remain mandatory |
| 3 Modes | Restricted `resolve`, `replay`, `explain` CLI | HORIZON-owned `recognize`/`reconstruct` #72/#73, deferred until their gates |
| 4 Architecture; 6 Phase 0 | Integration map/assumptions #61 and synthetic PacketIO lab | Shared packet/packetio/packetd/capture/store; HORIZON-owned live topology corpus/baselines #66, not demonstrated by fixtures |
| 5 DSL; 6 Phase 1 | Restricted versioned HZ-001 compiler, independent authorization, dry-run/bounds #62 | HORIZON-owned general sequences, policy profiles and resource properties #67 |
| 6 Phase 2 | Paired executor, direct TCP tuple/token correlation, inline raw frames and cancellation #63 | HORIZON-owned richer correlation, ICMP/NAT, clocks, drain and bounded PCAPNG #68; shared primitives |
| 6 Phase 3; 7 HZ-001/002; 8 Statistics | Randomized SACK pairs, quality-gated exact sign comparison/replay #64/#65; HZ-001 synthetic effect/null/loss/noise | HORIZON-owned environmental controls, HZ-002/live calibration #69; screening/correction deferred; SACK association is not causal diagnosis |
| 6 Phase 4; 7 HZ-003/004/005 | Cross-port/washout inference unestablished | HORIZON-owned #70 after #69; go/no-go against matched isolated controls; HZ-005 needs validated cooldown/confounder controls |
| 7 HZ-006 | Direct IPv6 TCP execution/replay fixtures, no path-consistency inference | HORIZON-owned path/vantage experiments #66/#68/#69; deferred until comparable routing/clock evidence |
| 6 Phase 5; 11 Graph | Provenance and inferred/unresolved SACK comparison | HORIZON-owned hypotheses, contradiction/decay and transport graph #71; shared references, never inventory ownership |
| 6 Phase 6; 8 Adaptive criterion | No experimental adaptive planner/profile compression | HORIZON-owned #72 after #71/#66; tested/profile-inferred/not-tested coverage stays distinct |
| 6 Phase 7; 10 CLI/API; 13 Security | CLI/private evidence export, integrity/replay and bounded PoC | HORIZON-owned API/UI, access, retention, observability/hardening #73; shared components; proposed endpoints unavailable |
| 9 Evaluation; 12 Priorities | Synthetic tests and existing scanner benchmark foundations | Shared lab #66; HORIZON-owned false-positive/ablation/efficiency gates #69/#70/#72; provisional targets are not results |
| 14 Risks; 15 Patent; 6 Phase 8 | Assumptions/confounders documented; no novelty claim | HORIZON-owned prior-art/disclosure #74, deferred to evidence/counsel gate |
| 16 Immediate sprint | Thin HZ-001 local slice #61–#65 | Publication/review separate; signed-report ambition unimplemented: SHA-256 detects corruption, not forgery |

## Versioning and wire compatibility

Implementations explicitly negotiate `nyxr/integration/v1alpha1`; reject unsupported
revisions at the integration boundary. It is sidecar reference/metadata, not a
replacement record stream. Optional additions must preserve meaning and only be
ignored where a reader explicitly permits them. Incompatible changes need a new
revision, old/new fixtures and an explicit migration.

Preserve `nyxr/v1`, `nyxr/protocol/v1` and `horizon.nyxr.io/v1alpha1`
independently. Never route an Experiment to the application DSL parser or silently
upgrade a namespace. Both strict DSL readers and HORIZON replay retain unknown-field
rejection. Do not insert adapter metadata into sealed reports: the exact report is
hashed. The envelope-less `--no-db` fast-path exception remains legacy input until
#76; never fabricate a missing scan ID to adapt it.

## Adapter contracts

### Observation/evidence IDs — NEXT GEN #76, HORIZON #68/#71

A `SourceRef` has `owner` (`next-gen`/`horizon`), `sourceSchema`, `artifactID`,
`pointer`, optional `runID`. `artifactID` is `sha256:<64 lowercase hex digits>`
of the exact retained source bytes; `pointer` is an RFC 6901 JSON Pointer into
that artifact. This ordered tuple identifies the reference. Time/IP/port, local
filename and payload similarity are not unique observation IDs. For JSONL, retain
each line as its own JSON artifact, or define a versioned indexed container before
issuing refs. Keep the source bytes/container recoverable unchanged.

Ordinary observations now carry scan/sequence IDs and immutable source mappings
from #76; migration/import IDs retain their database namespace. Preserve evidence
array indices and half-open probe-update ranges. See the [source-reference wire
contract](../reference/output-records.md#source-references). Root observation pointer is `""`,
exchange pointer `/evidence/0`. For a sealed HORIZON envelope use `/report`,
`/report/trials/0`, `/report/trials/0/evidence/0`; retain run ID, experiment hash,
pair, arm and flow token. A flow tuple alone cannot identify an observation.
#76 may add stream/store IDs only with an explicit immutable-source mapping.

Packet refs use capture artifact ID plus existing pcapng packet ID and scan/run
provenance/direction. Validate container identity and bounds. A redacted/rewritten
artifact gets a new hash and derivation link. A delivery retry of the same artifact
uses the same refs; distinct measurement occurrences must retain source run or
container identity even when payload bytes match. Pruned/inaccessible evidence
returns `unavailable` with a reason; never fabricate bytes or erase provenance.

### Asset references — NEXT GEN #80/#99, HORIZON #71

An `AssetRef` has existing database-namespaced `globalID`, local `identityID`,
`observedAt` (UTC) and supporting `SourceRef` values. Global ID identifies database
lineage; local ID alone is not safe across stores. Portable IDs retain inventory
scope. An IP is an address observation, not a physical asset ID. Resolve membership
at observation time or return unknown, never current membership as historical fact.

HORIZON links typed `hypothesis-about`/`candidate-dependency` edges to assets or
scoped addresses with run/uncertainty. Those edges cannot cause automatic joins.
NEXT GEN retains strong-key rules, splits, manual audit and unknown pre-migration
history. Retention may make a link unavailable without deleting a retained hypothesis.

### Packet I/O — shared packetio/packetd, HORIZON #61/#68

Keep `packetio.PacketIO` (`ReceiveBatch`, `SendBatch`, `Stats`, `Close`) and
`packetio.Opener` as the frame boundary; decoding/correlation stay outside it.
Copy retained evidence before reusing receive buffers. Honor partial batch counts
and errors, account for accepted sends, preserve partial results and never silently
retry unsent frames. The opener's caller closes the handle; `horizon.Run` borrows it.

One RX owner consumes each handle. Concurrent scan/experiment use needs separate
handles or an explicit bounded demultiplexer, never racing readers. Record actual
backend/interface and run counter deltas. Reset/unavailable drop counts are unknown
quality, not zero loss. packetd remains the privilege boundary; no second raw stack.

### Cancellation — existing contexts, HORIZON #67/#68/#73

Propagate parent `context.Context` through planning, admission, waits, TX/RX and
consumers; earliest parent/workflow deadline wins. After observing cancellation,
admit no new probes, retries or experiments. Retain in-flight evidence and a partial
terminal result/stop reason; cancellation is not a completed negative measurement.

Cleanup/drain shares bounded scope, rate, packet/time limits. Current HZ-001 cleanup
is best effort and cancellation/error may prevent it. Future post-cancellation cleanup
requires an explicit owning admission allowance, never an unbounded background sender.
Replay stays offline and cannot open a transport or trigger active follow-up.

### Authorization/budgets — existing config/service, HORIZON #67/#68

An admission adapter receives independent operator target/port/interface scope,
workflow policy, deadline, rate, packet/send, response/capture-byte and concurrency
limits. Requested scope must be contained in authorization. Effective limits are
the strictest applicable parent/operator/workflow limits, compared in identical
units. Missing mandatory limits fail closed; unsupported accounting units are rejected.

Distinguish actual Ethernet packets, application exchanges, retained raw bytes and
serialized export bytes. Enforce parent and per-run limits, reserve before dispatch
and charge actual sends once including retries/cleanup. Every send is paced. Bound
RX queues, parser work and retention; expose overflow/quality reasons. Ordinary scan
counters alone are not a global experimental budget ledger: implement shared parent
accounting before combined execution, under the owning delivery issue.

HORIZON recompiles/re-admits at execution after dry-run. Current reservation includes
four possible packets per pair (two SYNs/two RSTs). Runner counts exclude kernel/target
traffic; disclose this and use independent capture for live assessment. Profiles and
results cannot expand authorization, bypass OT policy or substitute inferred coverage
for requested full-port measurement.

### Timestamps — capture/observe, HORIZON #68/#69

A `TimeQuality` sidecar has `wallTime` (RFC 3339 UTC), `clockSource`, `precisionNs`
(integer/null), `clockDomain`, `queueing` (`included`/`excluded`/`unknown`) and
`qualityFlags`. Use unknown/null for unmeasured precision, synchronization and drops.
Preserve original timestamps/run/flow provenance and integer nanosecond RTT/durations.

Use monotonic elapsed time for local deadlines/pacing; serialized UTC loses Go's
monotonic component. Do not infer latency by subtracting different clock-domain times
without measured alignment/uncertainty. Current HORIZON times include userspace/backend
queues; raw scan receive times can be batch estimates. Imported pcap precision comes
from the source, not display formatting. Bad/unknown timing quality gates timing
inference while descriptive observations remain visible.

### Capabilities — packetio/config, NEXT GEN #81/#95, HORIZON #68/#73

A `Capabilities` sidecar has `revision`, `build`, `backend`, `interface`, `vantage`,
supported source schemas and feature states (`supported`/`unsupported`/`unknown`,
each with reason and validation provenance). Report raw TX/RX, IPv4/IPv6, AF_XDP mode,
packetd privilege route, capture/link type, timing source/precision, drops, cancellation
and maximum batch/frame sizes separately. Build support, successful opening and live
validation are distinct facts.

Check required features before transmission; unknown/unsupported requirements fail
with an unavailable reason. Experiments never implicitly fall back to connect mode.
Deliberate ordinary-scan fallback identifies its actual mode/evidence limits. PacketIO
does not advertise this object today: #95/#73 implement metadata around the opener,
not a second transport. Copy-mode does not imply zero-copy; HORIZON IPv6 fixtures do
not imply production IPv6 SYN or live validation.

## Compatibility fixtures and change review

The following fixture families gate adapter delivery. Existing tests are regression
anchors, not evidence that unimplemented adapters already pass.

| Family | Existing anchors | Required adapter fixtures / owner |
| --- | --- | --- |
| Output/storage | `internal/pipeline/pipeline_test.go`, `internal/storage/sqlite_test.go` | #76: old nyxr/v1 round-trip, legacy envelope-less records, optional fields, unchanged confidence/state, distinct occurrence refs, retention/unavailable refs |
| Both DSLs | `internal/service/dsl_test.go`, `internal/horizon/dsl/compiler_test.go` | #79/#67: deterministic v1 inputs; reject wrong namespace/version, unknown fields, unauthorized scope and budget bypass; new grammar separately versioned |
| Evidence/assets/capture | `internal/capture/recorder_test.go`, `internal/storage/identity_test.go`, `internal/horizon/horizon_test.go` | #76/#80/#68/#71: pointers/ranges/packet IDs, changed hashes, pruned refs, identical local IDs across lineages, split/manual overrides; hypotheses never join inventory |
| Lifetime/transport | `internal/packetd/packetd_test.go`, pipeline/HORIZON tests | #67/#68/#73: partial sends, cancellation/deadline, RX ownership, buffer reuse, cleanup/parent budget exhaustion, drops/caps/reset, unavailable/unknown capability denial |
| Replay/inference | `TestSyntheticScenariosAndReplay`, `TestReplayRejectsTamperingEvenAfterReseal`, `TestPairedComparisonGates`, `TestIPv6ExecutionAndReplay` | #68/#69/#71: effect/null/loss/duplicate/partial fixtures; unchanged seal/pair/arm/token/uncertainty; reject mismatch/tampering; replay opens no network |
| Clocks/live behavior | Capture timestamp tests, [runtime gates](../development/runtime-gates.md), #66 corpus | #66/#68/#69/#77/#81: source precision, unsynchronized clocks, path changes and independent capture; synthetic tests cannot establish live accuracy/performance/platform support |

Before shared-interface changes, record revision, producer/consumer impact,
canonical issues, fixtures, bounds, migration/rollback and output semantics. Both
affected workstreams review shared changes; local changes need their owning review.
This document asserts no named human sign-off. Breaking output/DSL/reference changes
need explicit new versions and upgrade paths before integration. Keep old fixtures
readable, raw evidence immutable and new integrations opt-in until owning gates pass.

Storage extensions use existing forward-only migrations, access and retention rules.
Rollback disables the adapter without discarding evidence or opening an unsupported
database schema. Reuse existing API authentication/bounded fan-out. Future HORIZON
routes and telemetry remain #73, not part of this design task.

### Verification of this assessment

Documentation links, all 23 NEXT GEN section rows, adapter namespaces and source
anchors were checked. Existing service, pipeline, storage, capture and packetd
tests pass. The HORIZON suites currently fail fixture-dependent cases: the existing
`codex/horizon-poc` sample targets `192.168.1.1`, while the tests independently
authorize `192.0.2.0/24`. This is a baseline fixture mismatch, not adapter validation
or a reason to weaken authorization. The other branch's sample is preserved.
Resolve the fixture/reusable-example split in the owning HORIZON workstream before
using those suites as a clean integration gate.

## Delivery order and independent research gates

1. #75 defines boundaries; #76 delivers uniform ordinary records/references.
   NEXT GEN #78/#79/#80 extend calibration, DSL and inventory on the existing core.
2. Reuse HORIZON #61 assessment, #67 general admission, #68 correlation/capture/clocks,
   #71 experimental graph, #72 planner/profiles and #73 product integration. A link
   blocks only its related shared/live-validation slice; independent NEXT GEN work
   proceeds with compatible adapters or disabled integration.
3. Reuse #66 live fixtures. NEXT GEN performance, IPv6 and confidence claims still
   require their relevant runtime/calibration evidence; lab reuse does not unify scores.
4. #69 pre-registers controls. #70 must outperform matched isolated controls before
   inference expansion; a no-go leaves ordinary NEXT GEN delivery independent. #71
   keeps confounded cases unresolved. #72 requires measured benefit/honest coverage;
   #73 retains hardening and #74 retains prior-art/counsel gates. Project status never
   waives these gates.

For #75, publish the matrix/contract in the NEXT GEN project and keep repository
documentation on a dedicated local branch. Distinguish completed design work from
external review/code publication. Implement the future adapters in the canonical
issues above; this document does not mark them delivered.
