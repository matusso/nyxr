# HORIZON security review: 2026-10-23

Required by [#73](https://github.com/matusso/nyxr/issues/73) before any
HORIZON probe becomes default-active. **Result: no probe is default-active,
and none is enabled by this change.** Every finding below is fixed or
documented. This review records the state of the API, CLI and audit surface;
it is not a penetration test, and a live-transport API would need its own
review.

## Scope and method

The review read the code; it did not exploit anything. It covered
`internal/api` (HORIZON routes, token guard, body limit, Host allow-list, web
UI), `internal/horizon` (modes, admission, run service, controller, audit
trail, metrics), `cmd/nyxr` (`serve` HORIZON flags, CLI live mode, output
handling) and DSL admission. A separate reviewer from the implementer did the
reading, and the HORIZON, API and CLI test suites passed during the review,
including under `-race`. The [#72](https://github.com/matusso/nyxr/issues/72)
planner code had its own independent correctness review; its findings are
fixed in that change.

## Questions and answers

| Question | Answer |
| --- | --- |
| Can a request cause traffic outside operator policy, or bypass modes? | No. The body carries only `mode` and `experiment` (unknown fields refused); admission checks the enabled mode, that the experiment belongs to it, and the server-held policy, and the controller recompiles at the execution boundary. |
| Is every endpoint authenticated? | Yes: all routes are behind the bearer token (constant-time compare). `serve` refuses HORIZON without a token, and now so does the handler itself. JSON-only POST and no cookies rule out CSRF; a loopback Host allow-list blocks DNS rebinding. |
| Resource exhaustion? | One run at a time, bounded retention (now at most 16 runs), 1 MiB bodies and 96-bit random run IDs. Audit refusals are now rate-limited. |
| Races (cancel, finish, kill switch, eviction)? | None found; state changes happen under locks. The race detector runs in CI (`make race`). |
| Audit integrity? | Every traffic-starting path writes an entry first and fails closed. The chain's limits are documented (see below). |
| Default-active probes? | None. The API is synthetic-only and needs explicit flags; `reconstruct` is off by default; CLI live mode needs an explicit interface, source IP and next-hop MAC. |

## Findings and resolution

| # | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | medium | A failed `run.finish` audit write was silently discarded. | Counted in `nyxr_horizon_audit_failures_total`. A failed write now latches the trail, so no further run starts. |
| 2 | medium | Refusal entries were unbounded: a token holder could fill the disk. | At most 30 refusal entries per minute; the metric counts all of them, and the next entry states how many were skipped. |
| 3 | low | After a partial write the chain appended past the broken line; two processes could share a file. | The trail latches on failure, and an exclusive advisory lock is taken on Unix. |
| 4 | low | Undetectable tail truncation and the lack of an external anchor were not documented. | Documented in [operations](operations.md#audit-trail). |
| 5 | low | Audit error messages exposed the server's file path to clients. | Clients get a generic "audit trail unavailable". |
| 6 | low | Multi-probe sequences counted as `resolve`, weakening the "reconstruct is opt-in" rule. | Any arm with more than one probe is `reconstruct`. |
| 7 | low | Only `serve`, not `api.Handler`, enforced the token requirement. | The handler refuses HORIZON when no token is configured. |
| 8 | low | Worst-case retained memory was about 1 GiB (64 runs). | The cap is now 16 runs (about 200 MiB worst case), documented. |
| 9 | gap | CLI live runs had no audit option. | `resolve` and live `adapt` accept `--audit FILE`, with the same fail-closed rule. |
| – | low | A synchronous `resolve` refused at start left an `accepted` entry without an outcome. | It now writes a `refused` outcome. |

Each fix has a regression test (`internal/horizon/runs_test.go`,
`internal/api/horizon_test.go`, `cmd/nyxr/horizon_test.go`).

## Residual risks

- The audit chain is tamper-evident, not signed. An attacker with write
  access to the file can rewrite or truncate it undetectably unless entries
  are shipped elsewhere.
- One shared bearer token: the audit trail records the remote address and
  whether a token was used, not which person sent the request.
- Metrics and runs live in process memory and are lost on restart; only the
  audit trail persists.
- The web UI was checked for text-only rendering and its endpoints are
  covered by tests, but its pages were not visually verified in a browser.
