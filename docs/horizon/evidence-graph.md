# HORIZON Phase 5: hypotheses and provenance graph

Issue [#71](https://github.com/matusso/nyxr/issues/71). `nyxr horizon graph`
turns replayed HORIZON reports into a versioned evidence graph
(`horizon.nyxr.io/graph/v1`). Every hypothesis is linked to the runs it rests
on. Evidence quality and hypothesis status are separate fields, and the graph
never publishes a numeric probability.

```sh
./nyxr horizon graph --report hz001-a.json --report hz002-a.json \
  --study main=main.json,same-port=same.json,time-separated=timed.json \
  --change 2026-10-23T12:00:00Z@host:10.77.0.2@kernel-upgrade \
  --ttl 24h --output graph.json
./nyxr horizon explain --graph graph.json --hypothesis HYP-1
```

Every input is replayed (integrity, raw packet correlation and recomputed
comparison/environment) before projection. `--study` takes the cross-port
roles from [#70](cross-port.md). `--now` fixes the evaluation time for
reproducible output; by default it is the current time. `--output` refuses
overwrites. A graph holds at most 256 runs.

## Graph contents

| Node | Statement | Provenance attributes |
| --- | --- | --- |
| `run:<id>` | observed | report SHA-256, experiment hash, build, backend, start/finish, completion, comparison, correlation/environment versions |
| `trial:<run>/<i>` | observed | arm, pair, probe, flow ID, response class, TTL, quality flags, PCAPNG packet IDs |
| `experiment:<hash>`, `build:<b>`, `host:<ip>`, `port:<ip>/tcp/<p>`, `capture:<id>` | — | name/version, capture packet and drop counts |
| `hypothesis:<HYP-n>` | inferred, hypothesis or unresolved | family, subject, status |

Edges: `part-of`, `probes`, `instance-of`, `built-by`, `targets`,
`captured-in`, `control-for:<role>` (from cross-port control runs to their
main run), `supported-by` and `weighed-against` (from each hypothesis to its
runs). `coverage.testedTcpPorts` lists only probed ports;
`fullTcpCoverage` is always false.

## Hypothesis families and decision rules

| Family | Source | Supported when | Not supported when |
| --- | --- | --- | --- |
| `endpoint-stack` | HZ-001 SACK runs (one subject per target/port) | inferred treatment-only SACK difference | inferred no detectable difference |
| `shared-state` | cross-port study | study classification `shared-state` | `no-coupling` or `per-port-state` |
| `rate-limiter` | cross-port candidate | elevated with an orthogonal **cooldown** signal | — (otherwise unresolved) |
| `firewall-tracking` | cross-port candidate | elevated with an orthogonal **TTL-divergence** signal | — (otherwise unresolved) |
| `nat-state`, `proxy`, `load-balancer` | none implemented | listed under `notEvaluated` | — |

Anything else is `unresolved`, with the reasons listed: unresolved runs,
a reverse-direction difference, or a missing control. Each hypothesis records
its alternatives (competing explanations), assumptions and reasons. The
statement kind is `inferred` for supported/not-supported results,
`hypothesis` for an elevated infrastructure explanation, and `unresolved`
otherwise.

`probability` is always `null`, and `probabilityMethod` says why: no held-out
calibration supports a numeric score. `ValidateGraph` rejects any hypothesis
with a probability, without a linked run, or linked to a missing node.

## Observation quality (separate from status)

Each run gets a grade in `observationQuality`:

- `poor`: incomplete, backend drops, or any environment gating flag.
- `degraded`: descriptive environment flags (other than unknown clock
  precision) or flagged trials. Timeouts are not flags in precondition runs,
  where they are the outcome.
- `good`: everything else. Reports from before environment assessment
  existed say so in their reasons.

A hypothesis's `observationGrade` is the worst grade among its supporting
runs (or its weighed-against runs when nothing supports it). A supported
hypothesis can therefore rest on degraded evidence, and the graph says so.

## Contradictions and confounding

- Current runs that both support and do not support the same family and
  subject produce a `contradictions` entry, and the hypothesis is
  `unresolved`.
- A significant HZ-002 A/A difference on a host contradicts every hypothesis
  on that host.
- Cross-port location stays `endpoint-or-path-unresolved` unless every
  supporting study shares one distinguishing location. Endpoint-hosted and
  path-hosted limiters with identical observations are therefore never
  assigned a location.

## Confidence decay

- **TTL:** `validUntil = observedAt + ttl`. After it, the hypothesis is
  `stale`.
- **Declared changes:** `--change TIME@host:IP[@detail]` or
  `TIME@network[@detail]`.
- **Detected changes:** for consecutive runs against one host, a reply TTL
  set with no overlap, or a different non-SACK option layout in the target's
  SYN/ACK, is recorded as a `detected` change at the later run's start.
- A run that **started** before the latest change in its scope is stale and
  moves to `weighed-against`. If no current evidence remains, the hypothesis
  is `stale`.

## Live demonstration: FreeBSD native SACK toggles

The [2026-10-12 FreeBSD corpus](../../lab/horizon/corpus/2026-10-12-freebsd-arm64/RESULTS.md)
alternated native `net.inet.tcp.sack.enable` between effect and null runs on
one IPv4 target (`192.168.254.131:443`). Graphs over its six IPv4 reports:

| Inputs | `endpoint-stack` status | Detail |
| --- | --- | --- |
| No declared changes | unresolved | contradiction: 3 supporting, 3 not supporting runs |
| Change declared at the final toggle (16:39:40Z) | not-supported | 5 earlier runs stale; only `null-002` is current |
| Change declared one toggle earlier (16:39:10Z) | unresolved | `effect-002` and `null-002` still disagree |
| No changes, evaluated two days later (TTL 24h) | stale | evidence older than the confidence TTL |

A SACK sysctl change does not alter the reply TTL or the non-SACK option
layout, so it is not detected automatically. The graph surfaces it as a
contradiction instead of averaging it away, and declared changes resolve it.

Cross-port graphs over the live ground-truth lab, including the confounded
endpoint-versus-path case, are in [cross-port studies](cross-port.md).

## Limitations

- Decision rules are pre-registered heuristics over replayed runs; they are
  not posterior probabilities, and a supported status is not a causal proof.
- Change detection only sees reply TTL and option layout. Configuration
  changes invisible to those features must be declared.
- `nat-state`, `proxy` and `load-balancer` have no discriminating experiment
  yet and are reported as not evaluated.
- The UI/API projection of the graph remains Phase 7 work (#73).
