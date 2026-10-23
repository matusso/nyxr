# HORIZON cross-port ground truth — 2026-10-23

**Status: complete for issue #70. Go.** Across 30 registered studies on four
known topologies, cross-port classification was correct in 30/30 (exact
two-sided 95% interval 88.4–100%). Matched isolated probes were correct in
9/30 (14.7–49.4%). Every registered gate passes. This is one shared-kernel
Linux lab with SYN token-bucket limiters only; it supports no claim about other
mechanisms or deployed networks.

## Environment and protocol

- Same Docker VM and image as the [Phase 3 corpus](../2026-10-23-phase3-linux-arm64/RESULTS.md)
  (`sha256:811cab92…`, 18 CPUs, `7.0.14-linuxkit`), network-disconnected,
  private namespaces only, veth TX checksum offload disabled.
- Collector [`crossport.py`](../../live/crossport.py), protocol
  [`crossport-protocol.json`](../../live/crossport-protocol.json) (registered
  before collection), study experiments in [`lab/horizon/cross-port`](../../cross-port/).
  Each study gets a fresh topology. Ports: A = 8443, B = 443, unrelated = 9443
  (closed). The limiter is `iptables -m limit --limit 2/second --limit-burst 1`
  on SYNs, so one token every 500 ms and SYNs without a token are dropped.
- Each role: 12 randomized pairs, 100 ms windows, 600 ms washout, 10 packets/s.
  The time-separated role adds 1,500 ms between precondition and measurement.

| Topology | Ground truth | Limiter | Studies |
| --- | --- | --- | --- |
| independent | no-coupling | none | 6 IPv4 (5 roles) + 3 IPv6 (main, same-port) |
| per-port | per-port-state | separate buckets for 443 and 8443 on the endpoint | 6 IPv4 |
| shared-endpoint | shared-state | one bucket for 443+8443 on the endpoint | 6 IPv4 + 3 IPv6 |
| shared-path | shared-state | one bucket for 443+8443 in the FORWARD chain of a router in front of the endpoint | 6 IPv4 |

## Results

| Topology | Cross-port classification | Isolated classification | Candidates | Orthogonal signal | Elevated hypothesis |
| --- | --- | --- | ---: | --- | --- |
| independent | no-coupling 9/9 | no-coupling 9/9 | 0 | — | — |
| per-port | per-port-state 6/6 | no-coupling 6/6 | 0 | — | — |
| shared-endpoint | shared-state 9/9 | no-coupling 9/9 | 9 | cooldown 6/9 | rate-limiter, location endpoint-or-path-unresolved (6) |
| shared-path | shared-state 6/6 | no-coupling 6/6 | 6 | cooldown 6/6 | rate-limiter, location endpoint-or-path-unresolved (6) |

- Measurement effects were all-or-nothing in this lab. Under a shared limiter,
  main, reverse and same-port suppressed 12/12 pairs (p = 0.00048828125), while
  time-separated and null showed 0/12. Under a per-port limiter only same-port
  suppressed. The independent topology showed no suppression in any role.
  Every no-precondition control probe in every study was answered, which is
  why matched isolated probing cannot separate the topologies.
- **Go/no-go gate: go.** The cross-port lower bound (88.4%) exceeds the
  isolated upper bound (49.4%).
- **Zero candidate false positives**: no shared-state candidate in the 15
  independent or per-port studies.
- **No unsupported infrastructure hypothesis**: `rate-limiter` was elevated
  only in the 12 IPv4 shared studies that had the time-separated cooldown
  signal. The 3 IPv6 shared-endpoint studies ran only main and same-port, so
  their candidates kept every hypothesis `not-elevated`. `firewall-tracking`
  was never elevated (no TTL divergence).
- **Confounded location stays unresolved**: endpoint-hosted and path-hosted
  limiters produced identical candidates, and neither was assigned a location.
  Every reverse study was symmetric.

## Evidence graphs over these studies (#71)

`nyxr horizon graph --study main=…,same-port=…,reverse=…,time-separated=…,null=…`
over each topology's six IPv4 studies (evaluated 2026-10-23T18:00Z, TTL 24h):

| Topology | shared-state | rate-limiter | firewall-tracking | Detected changes |
| --- | --- | --- | --- | --- |
| independent | not-supported (6 runs) | not evaluated | not evaluated | none |
| per-port | not-supported (6) | not evaluated | not evaluated | none |
| shared-endpoint | supported (6), grade good | supported, location endpoint-or-path-unresolved | unresolved | none |
| shared-path | supported (6), grade good | supported, location endpoint-or-path-unresolved | unresolved | none |
| two endpoint + two path studies, same address | supported (2 current, 2 stale) | supported (2 current, 2 stale) | unresolved | reply TTL changed (64 → 63 after the router was inserted) |

The last row shows change detection on real data. Inserting the router
changed the reply TTL, and the earlier endpoint studies became stale instead
of being pooled with the later ones.

## Collection attempts

1. **Campaign 1** (`campaign-1/`, collector `be3162ad…`): completed all 24
   independent, per-port and shared-endpoint studies (102 role runs, 45.4
   minutes). Its first shared-path study then failed **before any traffic**.
   The routed topology had no IPv6 DNAT, but the readiness check still probed
   IPv6, so the listener readiness timed out. The remaining shared-path
   studies never started. That study's directory, logs and manifest are
   retained. `campaign-1/summary.json` is that campaign analyzed alone (24/30,
   with the six shared-path studies counted as errors).
2. **Campaign 2** (`campaign-2-shared-path/`, collector `a6220aa8…`):
   readiness now checks only the families a topology serves. It reran the
   six registered shared-path studies (30 role runs, 13.7 minutes). Its
   `summary.json` is the combined analysis.

The combined analysis (`crossport.py analyze --output campaign-1 --output
campaign-2`) replaces a planned study only if it failed setup with zero
traffic, and only with the same planned study from a later campaign. Every
attempt is listed under `attempts`. The exact campaign-1 collector was
reconstructed from the #70 commit plus the recorded offload change, and its
SHA-256 matches the campaign's `environment.json`. It is archived under
`collector-source/campaign-1/`.

## Files

[baseline-summary.json](baseline-summary.json) is the combined analysis.
[raw-corpus.tar.gz](raw-corpus.tar.gz) holds both campaigns: per-role
experiments, dry-run plans, sealed reports, independent PCAPs with drop logs,
resources, before/after truth (addresses, routes, iptables counters, offload
state), `study.json` from `horizon cross-port`, manifests and collector
sources. [raw-artifact-hashes.json](raw-artifact-hashes.json) hashes every
archived file. [SHA256SUMS](SHA256SUMS) covers this directory.
