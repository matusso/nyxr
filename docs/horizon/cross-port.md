# HORIZON Phase 4: HZ-003/HZ-004 cross-port state experiments

Issue [#70](https://github.com/matusso/nyxr/issues/70). These experiments ask
whether an authorized flow to one port changes the answer to a later probe of
another port, and whether that beats matched isolated probes on a known
discrimination task. The result is a **shared-state candidate** with competing
explanations, never a device or topology identification.

## Precondition primitive

`changedVariable: precondition` (v1alpha2) requires:

- **Treatment:** 1–4 baseline SYN `send`/`observe` precondition probes,
  optional waits, then one baseline measurement probe.
- **Control:** one identical measurement probe after a `wait` equal to the
  treatment's precondition waits plus response windows. Absence of the
  precondition flow is the only declared difference.

Multi-port scope still needs `crossPort: true`, a `lab` or `enterprise`
policy and the independent `--permit cross-port`. Same-port controls use
single-port scope. Rate-gate spacing and RST cleanup are not part of the
matched wait; they differ between arms and are recorded confounders. The
primary metric is whether the measurement was answered (SYN/ACK or RST). The
paired exact sign test treats timeouts as outcomes; any other quality flag
removes its pair. Environment gating applies, except that throttling and
reference loss are descriptive here because a shared limiter legitimately
causes them.

## Study roles

The study experiments live in [`lab/horizon/cross-port/`](../../lab/horizon/cross-port/).
Each role is a separately compiled, executed and replayed experiment:

| Role | Precondition → measurement | Purpose |
| --- | --- | --- |
| `main` (HZ-003) | 8443 → 443 | Cross-port dependence |
| `reverse` (HZ-004) | 443 → 8443 | Direction: symmetric or one-way |
| `same-port` | 443 → 443 | Distinguishes per-port from shared state |
| `time-separated` | 8443 → (1.5 s) → 443 | Cooldown: does the dependence decay? |
| `null` | 9443 (unrelated) → 443 | Dependence not specific to the declared ports |

```sh
./nyxr horizon cross-port --main main.json --same-port same.json \
  --reverse reverse.json --time-separated timed.json --null null.json
```

`horizon cross-port` replays every report, checks each role's structure
against `main`, and classifies the study:

1. Main unresolved → `unresolved`.
2. The null control also shows dependence → `unresolved` (not port-specific).
3. Main shows dependence → `shared-state`.
4. Otherwise the same-port control decides: `per-port-state` or
   `no-coupling` (`unresolved` if it is missing or unresolved).

The **matched isolated classification** judges the same target using only the
no-precondition control probes of `main` and `same-port`. It reports
`no-coupling` when every isolated probe was answered, and `unresolved`
otherwise.

A `shared-state` study yields one candidate with its subjects, direction
(`symmetric`, `one-way` or `untested`), the evidence (role, run ID and
experiment hash), four competing explanations and any orthogonal signals:

- `cooldown`: the time-separated control shows no dependence.
- `ttl-divergence`: precondition and measurement replies arrive with
  disjoint TTL sets (a different responder).

Infrastructure hypotheses (`rate-limiter`, `firewall-tracking`) stay
`not-elevated` without an orthogonal signal. When elevated they carry no
probability. Their location is `endpoint-or-path-unresolved` unless TTL
divergence indicates the path.

## Synthetic checks

`--simulate shared-limit` (one token bucket shared by 443/8443) and
`--simulate port-limit` (one bucket per port) exercise the full pipeline
without traffic. Unit tests run every role through the simulator and replay,
and check that shared, per-port and absent limiters are classified correctly
and that matched isolated probes cannot tell them apart.

## Live ground-truth lab

PENDING

## Limitations

- Each candidate reports observed dependence between authorized flows. It does
  not identify a device, operating system or topology.
- Sign tests and intervals assume independent, stationary pairs. Repeated
  studies against one lab kernel are not independent hosts.
- The ground truth covers SYN token-bucket limiters only. Connection
  tracking, NAT, proxies and load balancers are not represented.
