# NYXR HORIZON — Implementation Plan

**Project:** NYXR HORIZON  
**Working invention name:** Counterfactual Transport-State Tomography (CTST)  
**Primary language:** Go  
**Status:** Research and implementation proposal — not a demonstrated invention or a patentability opinion  
**Scope:** Authorized TCP/IP network measurement, active service characterization, and inference of shared network state

**Integration contract:** [NEXT GEN / HORIZON ownership and adapters](architecture/next-gen-horizon-contracts.md).
It maps phases to the local baseline/canonical issues, preserves both DSL namespaces
and separates inventory from experimental graphs. Layouts, signed-report ambitions
and API examples below are proposals; the [PoC guide](horizon/README.md) describes
implemented behavior/limits. Independent HORIZON research go/no-go gates remain intact.

## 1. Executive Summary

NYXR HORIZON extends Nyxr from a high-performance port scanner into a **controlled network experimentation and transport-state inference engine**. Instead of treating each probe as an independent request, HORIZON compiles **paired, randomized, repeatable packet sequences** into experiments, measures responses, tests competing explanations, and constructs an evidence-backed graph of observed transport behavior.

The core research hypothesis is that carefully controlled **cross-flow and cross-port counterfactual experiments** can expose shared network state (such as rate limiting, NAT/firewall tracking, proxies, load balancers, or endpoint resources) that conventional independent port scans do not characterize reliably.

HORIZON must **not** present an inference as a directly observed fact. The system will distinguish observation, statistical association, causal evidence, and unresolved hypotheses. It will preserve Nyxr's existing fast scan path; deep tomography is an opt-in second stage.

### Outcomes

1. A repeatable **Experiment DSL** with control/treatment sequences and safety bounds.
2. A packet execution system leveraging Nyxr's Go packet I/O and `gopacket.DecodingLayerParser` where appropriate.
3. A response correlator with timestamp, retransmission, and environmental-noise handling.
4. A causal inference system that compares hypotheses rather than guessing from a single response.
5. A versioned **transport-state evidence graph**, exposed through CLI and API/UI.
6. An adaptive experiment scheduler that minimizes additional traffic under an explicit uncertainty budget.
7. A laboratory validation corpus with ground truth and baseline comparisons.
8. A documented prior-art and invention-disclosure package for patent counsel.

## 2. Non-Goals and Hard Constraints

- **Not** a claim to scan every TCP port without testing it. Inference cannot substitute for full-coverage measurement.
- **Not** a guarantee of better throughput than Masscan, ZMap, or Nmap in every workload. Measure information gained per packet and accuracy as well as raw scan rate.
- **Not** permission to perform disruptive experiments on third-party networks. All active testing requires an explicit scope and budgets.
- **Not** a general-purpose fuzzing/exploitation framework. Exclude malformed-packet campaigns and application exploits from the default workflow.
- **Not** a claim of patent novelty. Adaptive probing, TCP fingerprinting, automata learning, and differential network measurement all have prior art.
- **Not** a replacement for Nyxr's current SYN/TCP/UDP/ICMP discovery, service detection, or fast scan engine.

## 3. Product Model

Three modes share the same data and evidence model:

| Mode | Description | Default behavior |
|---|---|---|
| `recognize` | Minimal-cost matching against validated behavior profiles | Low-risk, bounded probes |
| `resolve` | Tests competing hypotheses when a response is ambiguous | Paired experiments and controls |
| `reconstruct` | Attempts to recover deeper cross-flow/port state relationships | Explicit opt-in, strict scope/risk limits |

Outputs must mark each statement as one of: `observed`, `inferred`, `hypothesis`, or `unresolved`.

## 4. Architecture

```text
Nyxr target discovery / scan results
                 |
                 v
       HORIZON target selector
                 |
                 v
       Experiment planner <---------- Profile registry
                 |
                 v
       Experiment DSL/compiler
                 |
                 v
       Safety policy / admission
                 |
                 v
       Sequencer + TX/RX engine
                 |
                 v
       Packet response correlator
                 |
                 v
       Observation / evidence store
                 |
                 v
       Statistical analysis engine
                 |
                 v
        Hypothesis evaluator
                 |
          +------+------+
          |             |
          v             v
     Evidence graph  Adaptive planner
          |             |
          +------> CLI / API / UI
```

### Suggested repository layout

```text
internal/horizon/
  config/           # defaults, policy parsing, versioning
  model/            # experiments, events, observations, evidence
  dsl/              # schema, parser, compiler, static checks
  planner/          # target selection and next-experiment decisions
  experiment/       # control/treatment ordering and execution state
  safety/           # scope, budgets, stop rules, OT policies
  packet/           # construction, send/receive integration
  correlate/        # demultiplexing and response matching
  measure/          # timing, jitter, loss, TTL/options measurements
  inference/        # model comparison, statistical tests, confidence
  graph/            # evidence-backed graph projection
  profile/          # compact fingerprints and versioned signatures
  storage/          # experiments, captures, observations, indexes
  replay/           # deterministic offline event replay
  telemetry/        # OTel and Prometheus integration
  api/              # integration with existing Nyxr API
cmd/nyxr/           # horizon subcommands via existing CLI
web/                # integrate into existing Nyxr UI layout
lab/horizon/        # container/netns topology, fixtures, ground truth
```

Adapt these paths to the actual repository conventions instead of duplicating established Nyxr packages.

## 5. Experiment Data Model and DSL

An experiment is a bounded unit with a **baseline**, a **single controlled treatment variable** where feasible, response windows, replicates, and a declared comparison method. Cross-port experiments are a later extension of the same model.

### Required types

```go
type Experiment struct {
    ID          string
    Version     string
    Scope       Scope
    Hypothesis  HypothesisSpec
    Control     Sequence
    Treatment   Sequence
    Randomize   bool
    Replicates  int
    Capture     CaptureSpec
    Limits      SafetyLimits
    Analysis    AnalysisSpec
}

type Sequence struct {
    Steps []Step
}

type Step struct {
    Kind         string // "send", "wait", "observe", "cleanup"
    Flow         FlowSelector
    Packet       *PacketTemplate
    Wait         DurationSpec
    CaptureLabel string
}

type Observation struct {
    ExperimentID string
    RunID        string
    FlowID       string
    Timestamp    int64
    Direction    string
    Features     PacketFeatures
    QualityFlags []string
    RawRef       string
}
```

Use project-standard types for addresses, durations, serialization, and errors. Version the wire format from day one; do not serialize raw Go structs as an unversioned external API.

### Illustrative YAML

```yaml
apiVersion: horizon.nyxr.io/v1alpha1
kind: Experiment
metadata:
  name: tcp-option-response-difference
spec:
  scope:
    targets: ["192.0.2.10"]
    tcpPorts: [443]
  hypothesis:
    question: "Does one TCP option change the observed response?"
  control:
    steps:
      - send:
          protocol: tcp
          flags: [SYN]
          dstPort: 443
          optionsProfile: baseline
      - observe: {windowMs: 800}
  treatment:
    steps:
      - send:
          protocol: tcp
          flags: [SYN]
          dstPort: 443
          optionsProfile: variant_a
      - observe: {windowMs: 800}
  execution:
    replicates: 12
    randomizedOrder: true
    washoutMs: 300
  analysis:
    features: [responseClass, ttl, tcpOptions, rtt]
    method: paired_comparison
  limits:
    maxPackets: 72
    maxDurationSeconds: 90
    packetsPerSecond: 3
    maxConcurrentFlows: 1
    stopOnErrorRate: 0.2
```

The illustrative rates and repetitions are **not universally safe defaults**; tune for target class and policy. Never run unspecified experiments against production/OT assets.

### Compiler validation

- Reject targets or ports outside the authorized scope.
- Reject unknown packet types, illegal field combinations, unbounded loops, or hidden recursive experiment calls.
- Enforce a compile-time upper bound on sends, receives, time, memory, concurrency, and capture volume.
- Require explicit declaration for cross-port state tests.
- Normalize and hash the compiled experiment for exact reproducibility.
- Preserve treatment/control equivalence except for declared changed variables.

**Acceptance:** Deterministic compilation and explainable validation errors; fuzz/property tests prove budgets cannot be bypassed through nested sequences.

## 6. Implementation Milestones

### Phase 0 — Repository Assessment and Baselines

**Goal:** Integrate cleanly with the existing Nyxr implementation and establish an unbiased baseline.

1. Inventory existing TCP scanner, packet I/O, DSL/probe engine, service detection, scheduler, CLI, telemetry, persistence, and web API components.
2. Map current packet capture path and determine where `gopacket.DecodingLayerParser` is already used; benchmark before changing it.
3. Establish lab targets: Linux, Windows, BSD, containerized proxies/load balancers, stateful firewalls, controlled NAT, deliberate loss/jitter, IPv4 and IPv6.
4. Record baseline scan outcomes and traffic: accuracy, packets/target, p50/p95 latency, resource usage, timeout rate, false positives/negatives.
5. Create `docs/horizon/assumptions.md` describing where causal identifiability may be impossible.

**Deliverables:** Architecture map, benchmark harness, ground-truth inventory, initial risk register.

**Exit gate:** Reproducible baseline tests in CI and a reviewed integration plan.

### Phase 1 — Core Models, DSL, and Safety Admission

**Implemented bounded extension (#67):** v1alpha2 adds send/observe/wait/repeat,
lab/enterprise/fragile/ot-restricted ceilings, independent cross-port permission,
resource properties, exact dry-run probes and CLI/API/executor cancellation.
See the [operator guide](horizon/general-dsl.md). The API ships synthetic
execution only; arbitrary disruptive packets remain unsupported. Cross-port
inference, calibrated timing and live ground-truth research gates remain separate.


**Goal:** Define experiments as validated, bounded, versioned artifacts.

1. Implement experiment/observation/hypothesis model types and JSON/YAML schema.
2. Implement DSL compiler with strict static validation and content hashing.
3. Implement allowlisted CIDRs/hosts, port scope, permissions, resource limits, cancellation, and deadlines.
4. Add configurable policy profiles: `lab`, `enterprise`, `fragile`, `ot-restricted`; deny potentially disruptive actions unless allowed.
5. Add dry-run output listing exact planned probes, bounds, changed variables, and expected captures.
6. Add a kill switch at CLI, API, and executor levels.

**Deliverables:** Schema, compiler, policy engine, dry-run CLI, unit/property tests.

**Exit gate:** Out-of-scope or unbounded experiments are rejected before packet transmission.

### Phase 2 — Packet Execution and Correlation

**Goal:** Execute paired sequences reliably and associate responses with the correct experiments.

1. Reuse Nyxr raw packet TX/RX transport abstraction rather than create a second competing scan stack.
2. Implement experiment-scoped flow IDs and packet correlators for TCP 4-/5-tuples; handle NAT/path shifts cautiously.
3. Timestamp on send and receive; track clock source, precision, packet loss, capture drops, and queueing delay.
4. Parse IPv4/IPv6, TCP flags, options, sequence/ack behavior, and ICMP error messages; record exactly what was observed.
5. Support retransmission detection, duplicate suppression **without losing raw evidence**, delayed replies, and ambiguous correlation flags.
6. Implement cancellation and executor drain/cleanup so tests do not leave uncontrolled traffic behind.
7. Add PCAP/PCAPNG recording with bounded retention and optional payload minimization.

**Deliverables:** Executor, correlator, parsers, PCAP fixtures, metrics.

**Exit gate:** Deterministic replay produces identical parsed observations; traffic caps hold under packet loss/timeouts.

### Phase 3 — Counterfactual Experiment Runner

**Goal:** Test controlled changes rather than draw conclusions from isolated responses.

1. Support randomized A/B ordering with fixed reproducible seed.
2. Implement interleaved controls, washout periods, repetitions, and environmental reference probes.
3. Compare one declared variable at a time when feasible; flag unavoidable confounders.
4. Implement per-trial quality controls: RTT drift, route changes, packet loss, server throttling, clock instability.
5. Persist each trial's inputs, ordering, packet evidence references, and quality flags.
6. Start with low-impact hypotheses: TCP option negotiation differences and response-class stability.

**Deliverables:** Experiment runtime, baseline-vs-treatment reports, replayable test corpus.

**Exit gate:** Controlled synthetic tests detect known injected effects while meeting a pre-registered false-positive threshold.

### Phase 4 — Cross-Port / Cross-Flow State Interference

**Goal:** Investigate whether prior interactions alter later response behavior across different flows or ports.

1. Define an experiment primitive with `preconditionFlow`, `measurementFlow`, and matched no-precondition control.
2. Run target-local paired experiments across two authorized ports with randomized order and bounded washouts.
3. Introduce null controls (unrelated port/host when explicitly in scope), same-port controls, and time-separated controls.
4. Model temporal dependence, cooldown, and nonstationarity; reject spurious correlations caused by ambient load.
5. Report a **shared-state candidate**, not a middlebox classification, when treatment affects measurements.
6. Validate against lab ground truth: single endpoint, shared firewall, shared proxy, separate backend, shared load balancer.
7. Require at least one orthogonal signal before elevating `shared-state candidate` to an infrastructure hypothesis.

**Deliverables:** Cross-flow DSL, dependency analysis, experimental reports.

**Exit gate:** Demonstrate repeatable discrimination of selected known lab topologies with confidence intervals and explicit unresolved cases.

### Phase 5 — Hypothesis Engine and Evidence Graph

**Goal:** Represent uncertainty faithfully and choose among competing explanations.

1. Define hypothesis families: `endpoint-stack`, `firewall-tracking`, `nat-state`, `proxy`, `load-balancer`, `rate-limiter`, `unresolved`.
2. Implement observation likelihoods or well-calibrated statistical decision rules; expose all assumptions.
3. Track evidence provenance: experiment hash, trial ID, timestamps, PCAP refs, software build, topology tags.
4. Create a graph of `host`, `port`, `flow`, `experiment`, `observation`, `candidate dependency`, `hypothesis`, and `evidence`.
5. Separate `observation confidence` from `hypothesis probability`; avoid unsupported precise scores.
6. Add contradiction detection, confidence decay after configuration changes, and an `unknown` outcome.
7. Surface the graph via machine-readable JSON and existing Nyxr UI components.

**Deliverables:** Hypothesis evaluator, provenance-aware graph, JSON schema, UI integration.

**Exit gate:** Every reported hypothesis is traceable to evidence; known confounded scenarios remain appropriately uncertain.

### Phase 6 — Adaptive Experiment Planning and Profile Compression

**Goal:** Reduce repeated diagnostics while keeping coverage honest.

1. Define experiment cost as packet count, elapsed time, CPU, memory, and expected operational risk.
2. Estimate expected discrimination between current hypotheses for each permitted experiment.
3. Select the next experiment under remaining budget; stop when evidence is sufficient, cost is excessive, or hypotheses cannot be distinguished.
4. Build versioned behavior profiles for previously validated target classes.
5. Add profile expiry and invalidation rules for observed drift, host upgrades, network-path changes, and inconsistent results.
6. Record `tested`, `profile-inferred`, and `not-tested` separately for every relevant port.
7. Implement an explicit full-coverage mode that never suppresses tests based solely on profile predictions.

**Deliverables:** Scheduler, profile store, uncertainty dashboard, traffic savings report.

**Exit gate:** For selected lab tasks, match a defined diagnostic accuracy threshold with fewer packets or less time than the non-adaptive experimental baseline; publish counterexamples too.

### Phase 7 — Productization, Hardening, and Observability

**Goal:** Make HORIZON usable and maintainable in production environments.

1. Add `nyxr horizon recognize|resolve|reconstruct|explain|replay` commands.
2. Expose versioned API endpoints to create, cancel, inspect, and export experiments.
3. Add dashboards for experiment timelines, control/treatment comparisons, topology hypotheses, uncertainty, and raw evidence.
4. Apply redaction, access control, encryption at rest where supported, retention, and audit logging.
5. Add OTel traces, structured logs, and Prometheus metrics (probe rate, capture drops, correlation ambiguity, stop-rule triggers).
6. Test OS portability: Linux primary raw-packet path; macOS/Windows support dependent on privileged capture/injection capabilities and documented limitations.
7. Harden against malformed inbound packets, resource exhaustion, cancellation races, and serialization vulnerabilities.

**Deliverables:** CLI/API/UI features, operator guide, security tests, release notes.

**Exit gate:** Stable CI, reproducible integration tests, bounded resource use, operable rollback/feature flag.

### Phase 8 — Patent Research and Invention Disclosure

**Goal:** Decide whether a **specific implementation** supports defensible patent claims.

1. Conduct a documented prior-art search across EPO Espacenet, WIPO PATENTSCOPE, Google Patents, USPTO, and academic literature.
2. Compare claims/mechanisms involving adaptive network probes, remote OS fingerprinting, protocol automata learning, differential DPI fingerprinting, active network tomography, and cross-flow state correlation.
3. Describe the precise technical mechanism distinguishing HORIZON from each closest reference.
4. Demonstrate a measurable technical effect in controlled experiments, with ablations for each allegedly novel mechanism.
5. Preserve dated design notes, source commits, test results, inventor contributions, and failure cases.
6. Coordinate filing and public disclosure timing with qualified patent counsel; do not assume that publishing implementation details is harmless.
7. Draft candidate claims only after actual prior-art and experimental analysis.

**Deliverables:** Claim chart, novelty/risk matrix, reproducible results, invention disclosure.

**Exit gate:** Counsel-supported file/no-file decision; no marketing claim of being patented unless factually true.

## 7. Experiment Catalog (Initial Safe Set)

| ID | Experiment | Controlled variable | Core observation | Interpretation constraint |
|---|---|---|---|---|
| HZ-001 | TCP option differential | One option/profile | Response class, option echo/selection, RTT | Can reflect route or endpoint variance |
| HZ-002 | Repeated SYN stability | Timing/order | RST/SYN-ACK stability and jitter | Background load can dominate |
| HZ-003 | Cross-port predecessor | Authorized flow to port A before probe to B | Conditional response change at B | Does **not** by itself identify shared middlebox |
| HZ-004 | Reversed cross-port order | A→B vs B→A | Directionality of observed coupling | Stateful effects can be asymmetric |
| HZ-005 | Washout sensitivity | Inter-trial spacing | Duration of observable effect | Must account for rate limits and ephemeral load |
| HZ-006 | Path consistency | IPv4/IPv6 or scoped vantage point | Hop/TTL/options consistency | Different routing invalidates direct comparison |

**Default exclusions:** Fragmentation-based stress tests, aggressive invalid TCP state manipulation, high-rate floods, application exploit probes, and any behavior that may destabilize embedded/OT devices.

## 8. Statistical Method and False-Positive Controls

For candidate experiment `e`, let `H` be current hypotheses, `Y` a future observation, and `D` collected evidence:

\[
e^* = \arg\max_e \left[I(H;Y\mid e,D) - \lambda C(e) - \mu R(e)\right]
\]

This is an established class of decision criterion; **it is not a novelty claim**.

Implement at minimum:

- Pre-registered primary metrics per experiment to avoid cherry-picking features.
- Randomized paired trials and repeated baseline checks.
- Confidence intervals or posterior uncertainty, not only point estimates.
- Multiple-testing correction when screening many ports/feature combinations.
- Negative controls and shuffled-label placebo analysis.
- Per-network measurement of capture loss, background traffic, path drift, and RTT variance.
- An explicit `insufficient evidence` result with reasons.
- Calibration and held-out evaluation for any ML-driven hypothesis scoring.

A potential causal result must survive repetition, negative controls, and a plausible alternative-explanations review.

## 9. Performance and Research Evaluation

### Baselines

- Nyxr's existing scanner without HORIZON.
- Nyxr with fixed, non-adaptive experiments.
- Nmap OS/service scanning where the comparison is semantically equivalent.
- Masscan and ZMap for raw discovery-rate comparisons only; they do not solve the identical inference task.
- Relevant published active-measurement/fingerprinting methods wherever reproducible code is available.

### Metrics

| Dimension | Metric |
|---|---|
| Correctness | Open/closed/filtered classification precision and recall (where measured) |
| Inference | Hypothesis top-1 accuracy, calibration error, unresolved rate |
| Efficiency | Bytes/packets per supported conclusion; time to resolution |
| Robustness | Accuracy under 0–5% loss, induced jitter, route changes, and response throttling |
| Scalability | Hosts/sec, concurrent experiments, CPU/GB, capture drops |
| Safety | Limit violations (target: zero), cancellations respected, device-impact incidents |
| Explainability | Evidence completeness and reproducibility of emitted conclusions |

### Ablation tests

Compare HORIZON with and without (a) randomized controls, (b) cross-flow experiments, (c) orthogonal corroboration, (d) adaptive selection, and (e) profile compression. Any claimed advantage must be attributable to a component rather than a different scan budget.

### Initial acceptance targets (provisional, to be ratified against baselines)

- **100%** of experimental transmissions within the compiled scope and packet/time budgets in controlled testing.
- **100%** of inference edges include provenance and an explicit observed/inferred status.
- No graph edge labeled `confirmed causal` without a repeated matched-control protocol.
- Demonstrated decrease in packets **or** time for at least one predefined inference task at matched quality.
- No material false-positive increase relative to the fixed experiment baseline; define an allowed margin before experimentation.
- All claims include confidence/uncertainty estimates and counterexamples.

Do not invent a throughput multiplier or claim 10x speedups without equivalent benchmark measurements.

## 10. CLI / API Contract (Proposed)

```bash
# Preview exact traffic scope without sending packets
nyxr horizon resolve --target 192.0.2.10 --ports 443,8443 --dry-run

# Run low-risk behavior recognition in authorized scope
nyxr horizon recognize --target 192.0.2.10 --ports 443 --policy enterprise

# Run approved cross-port hypothesis experiments
nyxr horizon reconstruct --target 192.0.2.10 --ports 443,8443 \
  --experiment hz-cross-port-v1.yaml --policy lab --output horizon.json

# Explain a conclusion by tracing the underlying observations
nyxr horizon explain --report horizon.json --hypothesis-id HYP-17

# Replay stored evidence without generating traffic
nyxr horizon replay --input evidence-run-001.pcapng
```

Suggested API resources:

```text
POST   /api/v1/horizon/experiments/validate
POST   /api/v1/horizon/runs
GET    /api/v1/horizon/runs/{run_id}
POST   /api/v1/horizon/runs/{run_id}/cancel
GET    /api/v1/horizon/runs/{run_id}/observations
GET    /api/v1/horizon/runs/{run_id}/evidence-graph
GET    /api/v1/horizon/runs/{run_id}/report
```

Use the current Nyxr authorization model and existing event-stream mechanism; do not create unauthenticated active-probe endpoints.

## 11. Evidence Graph Output Example

```yaml
target: 192.0.2.10
scanCoverage:
  testedTcpPorts: [443, 8443]
  fullTcpCoverage: false
observations:
  - id: OBS-001
    subject: tcp/443
    result: syn_ack
    evidenceRef: pcap://run-01/packet-12
hypotheses:
  - id: HYP-17
    type: shared_state_candidate
    subjects: [tcp/443, tcp/8443]
    status: inferred
    confidence:
      method: calibrated_model_v1
      value: null # no numeric score until calibrated
    supportingEvidence: [OBS-001]
    alternatives:
      - shared_endpoint_resources
      - shared_middlebox
      - ambient_load
    limitations:
      - "Topology not uniquely identifiable from these measurements"
```

## 12. Work Breakdown / Dependency Order

| Priority | Work item | Depends on | Demonstrable output |
|---|---|---|---|
| P0 | Existing Nyxr integration review | — | Architecture map |
| P0 | Laboratory topology and baseline fixture set | — | Reproducible ground truth |
| P0 | Scope/budget safety policy | — | Out-of-scope requests fail closed |
| P0 | Versioned Experiment DSL/compiler | Safety model | Deterministic dry-run |
| P0 | Packet TX/RX adapter and response correlator | Compiler, current Nyxr packet layer | Packet-to-trial tracing |
| P1 | Randomized control/treatment runtime | TX/RX adapter | Replayable A/B reports |
| P1 | Cross-port predecessor experiment | Control/treatment runtime | Measured dependency candidates |
| P1 | Inference and confidence evaluation | Cross-port experiment | Evidence-backed hypothesis reports |
| P1 | Graph projection and explain command | Inference/store | Inspectable provenance |
| P2 | Adaptive scheduler | Calibrated inference | Cost-aware next experiment |
| P2 | Behavior profile registry | Baseline corpus | Fast recognition with honest coverage |
| P2 | Web/API integration | Stable graph schema | Operator-facing workflow |
| P2 | Patent disclosure package | Ground-truth evidence and prior-art search | Counsel-ready materials |

## 13. Definition of Done

A milestone is complete only when it includes:

- Working code using existing Nyxr conventions, with no redundant parallel scanning stack.
- Unit, integration, replay, and adversarial/noisy-network tests relevant to the change.
- Structured instrumentation, documented failure cases, and bounded resource consumption.
- A reproducible demonstration on a known lab topology.
- Updated operator documentation and versioned output examples.
- A precise statement of what is **observed**, what is **inferred**, and what remains **unknown**.
- A security review before any default-active probe behavior is enabled.

## 14. Research Risks and Decision Gates

| Risk | Mitigation / decision rule |
|---|---|
| Shared response shifts cannot uniquely identify a middlebox | Use competing hypotheses; return unresolved when underdetermined |
| Random delay, path changes, or server load mimic state coupling | Negative controls, randomized order, sufficient repetitions |
| Stateful probes affect fragile targets | Conservative policies, no default reconstruct mode, kill switch |
| Packet/capture timing skew creates false effects | Stable clocks, calibrated timing, uncertainty flags |
| Profiles overgeneralize after upgrades | Drift detection, expiry, mandatory revalidation |
| Existing patents/publications cover the proposed technique | Detailed claim-chart review; redesign or publish as research if not novel |
| Port inference is mistaken for full coverage | Separate tested and inferred coverage in all outputs |

**Go/no-go after Phase 4:** If cross-flow experiments do not reliably outperform matched isolated-probe controls on a known, reproducible discrimination task, stop extending the inference stack and publish the negative result internally. Avoid building sophisticated AI on an unvalidated signal.

## 15. Patent and Publication Position

The **candidate invention** is not "AI chooses the next port." The narrower investigation is a particular combination of: (1) compile-time controlled counterfactual transport sequences, (2) randomized cross-port/cross-flow precondition-and-measure experiments, (3) separable endpoint-versus-path hypotheses, and (4) evidence-gated adaptive continuation. Each element and their combination require prior-art examination; **no patentability conclusion is made here**.

Potential title: *Method and System for Causal Reconstruction of Distributed Transport-Layer States Using Controlled Counterfactual Network Probe Sequences*.

Before any external technical disclosure, coordinate with counsel on priority and filing strategy. Record inventor contributions and dated experimental proof. A patent attorney should evaluate novelty, inventive step/non-obviousness, claim scope, and relevant European computer-implemented invention standards.

## 16. Immediate Engineering Sprint

Start with a thin vertical slice, **not** the adaptive planner:

1. Review Nyxr's current packet and probe execution interfaces.
2. Add `internal/horizon/model` and the versioned `Experiment` schema.
3. Add strict scope and traffic budget validation with dry-run.
4. Implement one fixed HZ-001 TCP option A/B experiment using existing TX/RX.
5. Save packet-correlated control/treatment observations in a replayable format.
6. Add a simple comparison report that permits `no detectable difference`.
7. Run against a lab Linux host with controlled loss/jitter and capture ground truth.
8. Record precision, false-positive behavior, traffic cost, and limitations.
9. Only then proceed to HZ-003 cross-port state-coupling experiments.

**First sprint demo:** `nyxr horizon resolve --target <lab-ip> --ports 443 --experiment hz-001.yaml` outputs a signed/versioned evidence report showing the exact treatment variable, individual trials, quality flags, and supported conclusion—without claiming a specific middlebox or OS from insufficient evidence.
