# HORIZON bounded sequence DSL

Issue #67 extends admission and execution with `horizon.nyxr.io/v1alpha2`.
The original [v1alpha1 schema](experiment-v1alpha1.schema.json), experiment
identity, reports and offline replay remain supported. New fields/primitives
are rejected in v1alpha1. The [v1alpha2 schema](experiment-v1alpha2.schema.json)
is structural: the compiler also checks authorization, expansion, arm
comparability and all computed budgets.

## Operator policy

Profiles are fixed conservative ceilings, not permission to run against any
particular network. Target class and suitable windows still need operator
review. Authorization comes independently from CLI flags or server startup,
never from the experiment document. v1alpha2 requires a named profile.
Omitting the profile for legacy v1alpha1 retains the PoC `lab` ceilings.

| Profile | Maximum declared packets | Packets/s including cleanup | Raw capture ceiling | Cross-port capability |
| --- | ---: | ---: | ---: | --- |
| lab | 200 | 10 | 8 MiB | Explicit permission required |
| enterprise | 100 | 5 | 4 MiB | Explicit permission required |
| fragile | 16 | 1 | 1 MiB | Rejected |
| ot-restricted | 8 | 1 | 64 KiB | Rejected |

The single target must be a global unicast IPv4/IPv6 literal within independent
`--allow-targets`; every declared nonzero TCP port must be in `--allow-ports`.
There are at most eight distinct declared ports. Multiple ports require both
`spec.crossPort: true` and `--permit cross-port`; single-port experiments must
not declare cross-port operation. Scope does not permit undeclared sends.
Permissions have exact names; unknown permissions are errors.

Only TCP SYNs with `baseline` (MSS 1460) or `sack-permitted` (MSS 1460 + SACK)
options are supported. Arbitrary RSTs, malformed flags/options, spoofing,
payloads, application writes and stress primitives fail closed. An explicit
permission does not enable unsupported disruptive actions. The only RST is
cleanup of this runner's own correlated SYN/ACK, under the same rate, packet
and capture budgets. Cancellation can prevent cleanup; remote state then
expires. No established session is targeted for reset.

## Bounded sequences

Each arm contains `steps` with exactly one primitive per step:

- `send`: the existing scoped TCP SYN definition.
- `observe: {windowMs: 10..5000}`: immediately after each send.
- `wait: {durationMs: 0..5000}`: before, between or after send/observe pairs.
- `repeat: {count: 1..16, steps: [...]}`: bounded nesting, up to four repeat
  levels and 64 expanded primitive steps per arm. Expansion checks space
  before appending or allocating repeated content. No recursive calls,
  unbounded loops, conditional sends or parallel branches are supported.

Execution still requires 2–50 randomized pairs, an explicit seed if desired,
0–5000 ms washout after each complete arm, and one concurrent flow.
`changedVariable: sackPermitted` requires identical expanded probe counts,
ports, windows and waits, differing only in baseline versus SACK permission.
`changedVariable: sequence` explicitly declares an exploratory sequence
contrast; it may change ports/order/count/windows/waits within all bounds.

Every SYN gets its own trial, `probe` index and fresh sequence token. Matching
probe positions share the source port across paired arms; each probe position
has a different source port. Raw responses correlate to that exact probe.
Multi-probe and exploratory sequence reports remain **unresolved**, with their
individual observations retained. Cross-port causal/state inference is not
implemented by this admission extension. Only the existing single-probe SACK
comparison uses the existing evidence-gated sign test.

## Resource admission and dry-run

v1alpha2 adds required limits:

- `maxReceiveFrames`: 1–4096 received frames **per probe**, including unrelated
  traffic. One additional frame can trigger the cap; the plan includes it.
- `maxMemoryBytes`: at least `capture.maxBytes + 1048576`, at most 16 MiB.
  This bounds retained executor data: raw evidence plus a conservative fixed
  allowance for bounded trial/evidence metadata, plan and receive buffer.
  It is not a process RSS/Go allocator limit or a budget for the transport,
  YAML parser, JSON export, HTTP buffers or offline replay.

Capture remains 4096 bytes–8 MiB, further restricted by profile. Frames exceed
2048 bytes only by failing capture before copying them. At most 17 correlated
replies per probe are retained; the 17th triggers the duplicate cap. At most
19 evidence frames per probe include SYN, replies and cleanup. These counts,
receive work, memory allowance and concurrency are exposed in the plan.

Declared packet limits reserve one SYN and one possible RST per planned probe.
The conservative duration includes every receive window, all waits, two rate
intervals per probe, washout per arm and two seconds of overhead. Plans below
these bounds are rejected before opening a backend. Execution re-admits and
uses that plan; exhaustion/cancellation/failure returns partial evidence.

```sh
nyxr horizon resolve --experiment lab/horizon/sequence-v1alpha2.yaml \
  --policy lab --allow-targets 192.0.2.0/24 --allow-ports 443,8443 \
  --permit cross-port --dry-run

nyxr horizon resolve --experiment lab/horizon/sequence-v1alpha2.yaml \
  --policy lab --allow-targets 192.0.2.0/24 --allow-ports 443,8443 \
  --permit cross-port --simulate sack --output sequence.json
nyxr horizon replay sequence.json
```

The exact plan lists randomized pair/arm/probe order, destination port, SYN
flags, option bytes, receive window and waits, fixed wire fields and conditional
RST cleanup. Source link addresses and cryptographic run tokens are runtime
substitutions, explicitly described in `wireTemplate`. Dry-run opens no backend.
The sample executes 12 probes and at most 24 runner-emitted packets; simulations
send no network traffic. Live CLI execution uses the existing explicit
interface/source/next-hop/packetd settings. Ctrl-C and SIGTERM cancel waits,
receive windows and rate gates, and export partial evidence.

## API and executor kill switch

HORIZON endpoints are disabled by default. An operator can enable a synthetic
API session with fixed independent policy; this ships no live API transport
configuration. IPv4 synthetic source is 192.0.2.1; IPv6 live/synthetic CLI
execution remains available. The server does not accept client-supplied policy,
permission, link or transport settings in the experiment request.

```sh
nyxr serve --horizon-simulate sack --horizon-policy lab \
  --horizon-allow-targets 192.0.2.0/24 --horizon-allow-ports 443,8443 \
  --horizon-permit cross-port
```

| Endpoint | Behavior |
| --- | --- |
| `POST /api/v1/horizon/plan` | Strict experiment JSON; compile only |
| `POST /api/v1/horizon/resolve` | Strict experiment JSON; synchronous sealed report |
| `POST /api/v1/horizon/stop` | Permanently cancel current work and reject new runs/plans |

These endpoints use the existing Host, bearer-token and JSON request guards.
One active experiment is allowed per controller; concurrent runs return 429.
A failure/cancellation returns 409 with a sealed partial report and stop reason
when execution has started. Disabled endpoints return 403. Stop is idempotent,
returns 202 and cannot be undone by an API request; restart the operator session
to re-enable. Request cancellation and server shutdown cancel execution too.
The same `horizon.Controller.Stop` provides an executor-level kill switch for
embedded callers, with synchronous context cancellation and `Close` waiting
for work to finish. Backends must honor PacketIO context cancellation.

Offline replay re-admits the recorded experiment for consistency (not live
authorization), verifies each planned port/profile/probe and source/token
schedule, validates raw replies and cleanup, and checks accounting. References
preserve the report's actual version, probe index and immutable evidence
pointers. SHA-256 remains corruption detection, not authentication.

## Verification

Tests cover legacy identity, strict wire versions/types, nested expansion,
profile/permission rejection, controlled-variable equivalence, exact-plan
execution, IPv4/IPv6, rates, deadlines, cancellation, capture/receive bounds,
aggregate concurrency, permanent API/executor stops and resealed tampering.
`FuzzSequenceBounds` varies repetition, rate, receive, memory, concurrency and
time budgets with overflow seeds; it is included in `make fuzz`. Live ground
truth and causal validation remain separate research gates (#66 and later).
