# HORIZON Phase 7: operations, API and hardening

Issue [#73](https://github.com/matusso/nyxr/issues/73). This guide covers the
operator-facing workflow: modes, the versioned run API, the audit trail,
metrics, retention, the web UI, platform privileges and capture limits. The
security review is in [security-review.md](security-review.md).

**Nothing in HORIZON is active by default.** The CLI sends packets only with
an explicit `--interface`, `--source-ip` and `--next-hop-mac` (or a
`--simulate` scenario). The API exists only when `serve` is started with
`--horizon-simulate`, and it drives synthetic transports only; there is no
live-transport API.

## Modes

Every experiment belongs to exactly one mode, determined by what it does to
target state:

| Mode | Experiments | Default |
| --- | --- | --- |
| `recognize` | `changedVariable: none` (HZ-002 A/A: identical baseline arms) | enabled |
| `resolve` | one controlled variable, one probe per arm (HZ-001 SACK) | enabled |
| `reconstruct` | `precondition` flows, `crossPort: true` (HZ-003/HZ-004), or any arm that sends more than one probe | **opt-in** |

The operator enables modes with `serve --horizon-modes`. Every API run request
names a mode, and the experiment must belong to it: a `resolve` request
carrying a cross-port experiment is refused (`mode-mismatch`). Cross-port
experiments still also need `--horizon-permit cross-port` and a `lab` or
`enterprise` policy. The CLI keeps its existing explicit flags
(`--permit cross-port`).

## Run API

`serve --horizon-simulate S --horizon-policy P --horizon-allow-targets CIDR
--horizon-allow-ports PORTS --horizon-audit FILE --token-file F
[--horizon-modes ...] [--horizon-max-runs 8] [--horizon-retention 24h]`

The HORIZON API always requires a bearer token and an audit file; the
handler itself refuses HORIZON requests when no token is configured. All
endpoints sit behind the API's token, JSON-only POST, 1 MiB body limit and
loopback Host allow-list.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/horizon` | Enabled modes and the run API version (`horizon.nyxr.io/run/v1`). |
| `POST /api/v1/horizon/plan` | Compile under the server policy; opens no transport. |
| `POST /api/v1/horizon/runs` | `{"mode": M, "experiment": {...}}` → `202` `HorizonRun` (`running`). |
| `GET /api/v1/horizon/runs[/{id}]` | Retained runs, newest first, or one run. |
| `POST /api/v1/horizon/runs/{id}/cancel` | Cancel one run; the controller stays usable. |
| `GET /api/v1/horizon/runs/{id}/report` | Export the sealed, replayable report (`409` while running). |
| `GET /api/v1/horizon/runs/{id}/evidence-graph` | Evidence graph of that run. |
| `POST /api/v1/horizon/resolve` | Synchronous run (kept for compatibility), under the same mode and audit rules. |
| `POST /api/v1/horizon/stop` | Kill switch: cancels everything and refuses new runs until restart. |
| `GET /api/v1/horizon/metrics` | Prometheus text metrics. |

Status codes: `403` mode disabled, `422` admission or mode mismatch, `429`
busy (one run at a time), `409` stopped or conflicting state, `404` unknown
or expired run. A run's final state is `completed`, `cancelled`, `stopped`
(kill switch) or `failed`. Cancelled and stopped runs keep their partial,
replayable evidence.

**Retention:** at most `--horizon-max-runs` (1–16) runs are kept in memory;
each report is bounded by its capture budget (8 MiB plus encoding), about
200 MiB in the worst case.
The oldest finished run is dropped to make room, and finished runs older than
`--horizon-retention` are dropped. A running run is never dropped. Export a
report before it expires. Nothing is written to disk except the audit trail.

## Audit trail

`--horizon-audit FILE` is an append-only JSONL file (mode 0600). Each entry
records the time, actor (remote address and whether a token was used, never
the token), action, run ID, mode, experiment hash, target, ports and outcome.
Actions are `run.create`, `run.finish`, `run.cancel`, `resolve`,
`kill-switch`, `denied`, and `cli.run`/`cli.finish` for CLI runs with
`--audit FILE` (`resolve` and live `adapt`). Each entry hashes its
predecessor, and each write is synced to disk. Refusals are recorded up to
30 per minute; the metric counts all of them, and the next recorded refusal
states how many were skipped, so a token holder cannot flood the disk with
refusals.

- A run is admitted only after its `run.create` or `resolve` entry has been
  durably written. If the audit write fails, the run is refused
  (**fail closed**). Cancel and kill-switch requests take effect even if their
  audit write fails, and the API response then says so.
- A failed write (full disk, I/O error) **latches** the trail: every later
  write fails, so no further run starts, and `nyxr_horizon_audit_failures_total`
  counts it. A run whose outcome entry could not be written already happened
  and is visible in that metric. Clients see only "audit trail unavailable";
  paths and OS errors stay server-side.
- `serve` verifies the existing chain before appending, refuses a broken
  chain or a group- or world-writable file, and on Unix holds an exclusive
  lock, so two processes cannot fork the chain.
- `nyxr horizon audit-verify FILE` checks a chain offline.

The chain detects edits, deletions and reordering by anyone who cannot
recompute it. It does **not** detect truncation of the tail (dropping the
newest entries leaves a valid shorter chain), and it has no external anchor:
someone with write access can rewrite the whole chain. It is tamper-evident,
not a signature. Ship entries to separate storage, or record the latest hash
elsewhere, if that matters.

## Metrics

`GET /api/v1/horizon/metrics` exposes process-local counters:
`nyxr_horizon_runs_total{mode,state}`,
`nyxr_horizon_admission_denied_total{reason}` (mode-disabled, mode-mismatch,
policy, busy, stopped, audit), `nyxr_horizon_stop_rules_total{rule}`
(curtailed, cancelled, stopped, deadline), `nyxr_horizon_packets_tx_total`,
`nyxr_horizon_capture_drops_total`, `nyxr_horizon_trials_total`,
`nyxr_horizon_ambiguous_correlations_total`, `nyxr_horizon_audit_failures_total`,
`nyxr_horizon_active_runs` and `nyxr_horizon_kill_switch_engaged`. OpenTelemetry tracing is not implemented.
Metrics and the audit trail are the supported observability.

## Web UI

The **HORIZON** page lists retained runs with their state and conclusion. It
can cancel a run and engage the kill switch (after confirmation), and shows
the metrics. A run's page shows its status, a trial timeline (send time by
arm, colored by response class), the control/treatment comparison, the
evidence-graph hypotheses (status, observation grade, support) and the
report's limitations, and can download the sealed report. Runs are created
through the API, not the UI. Everything is rendered as text.

## Platform privileges

| Platform | Live backend | Privilege |
| --- | --- | --- |
| Linux | `AF_PACKET` raw socket (optional AF_XDP) | `CAP_NET_RAW`, or a separately run `nyxr-packetd` (`--packetd SOCKET`) |
| macOS | BPF (`/dev/bpf*`) | read/write access to BPF devices (root, or a BPF group) |
| Windows | Npcap `wpcap.dll`, loaded at runtime | Npcap installed; `\\Device\\NPF_{GUID}` adapter names need `--source-mac` |
| other | none | live mode is unavailable; simulation and offline commands work |

`OpenLive` fails closed with an error on every platform when privileges, the
backend or the interface are missing; a test covers this. Live mode validates
everything before opening a backend: the source address must be assigned to
the interface, and both MACs must be unicast. `serve` refuses to run with
root or raw-socket capabilities unless `--allow-privileged` is given; raw
access belongs to `nyxr-packetd`.

## Capture limitations

- **Checksums:** replies whose IP or TCP checksum does not verify are never
  correlated. On Linux veth with TX checksum offload, locally generated
  SYN/ACKs are captured with partial checksums and look like silence. Disable
  offload on lab interfaces (`ethtool -K DEV tx off`), as the lab collectors
  do. A test pins this behavior.
- **Drops:** backend or capture-artifact drops leave the comparison
  unresolved. A drop counter that goes backwards flags every trial
  `capture-stats-reset` and leaves the run unresolved.
- **Timestamps** are userspace (software) clocks that include backend
  queueing. Precision and queue delay are reported as unknown, and RTT is
  descriptive only.
- Fragmented replies are not reassembled, and ICMP errors stay unresolved.
- Synthetic API runs validate software only; they are not live ground truth.

## Hardening and tests

- **Hostile input:** fuzz targets cover report replay, correlation,
  admission, sequence bounds, profiles, graphs, the audit chain, change
  scopes and the API run request (`make fuzz`, in CI). Every decoder is size
  bounded and strict (unknown fields refused).
- **Races:** cancel, finish, kill switch and retention eviction run
  concurrently under `make race` (in CI). A cancelled run leaves the
  controller usable; the kill switch is idempotent and permanent.
- **Resources:** one run at a time; at most 16 retained runs; 1 MiB request
  bodies; 24 MiB report replay; 1 MiB profiles; 64 KiB audit lines;
  rate-limited refusal entries.
