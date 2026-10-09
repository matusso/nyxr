# NYXR HORIZON implementation plan

[GitHub project](https://github.com/users/matusso/projects/2), linked to
`matusso/nyxr`. Source: `docs/HORIZON_ROADMAP.md`. Initial local branch:
`codex/horizon-poc`. HZ-001 is the first slice; deeper tomography remains gated.

NEXT GEN [#75](https://github.com/matusso/nyxr/issues/75) defines the shared
[ownership and versioned adapter contract](../architecture/next-gen-horizon-contracts.md).
It reuses #61/#67/#68/#71/#72/#73 rather than duplicating their deliverables.
A coordination link blocks only its related integration or live-validation slice;
ordinary NEXT GEN delivery remains independent of HORIZON's research go/no-go result.

| Issue | Deliverable | Dependencies |
|---|---|---|
| [#61](https://github.com/matusso/nyxr/issues/61) | PoC integration map and inference assumptions | — |
| [#62](https://github.com/matusso/nyxr/issues/62) | Versioned restricted DSL, scope/budget admission, dry-run | #61 |
| [#63](https://github.com/matusso/nyxr/issues/63) | Paired runtime, correlation, raw evidence and cancellation | #62 |
| [#64](https://github.com/matusso/nyxr/issues/64) | Conservative SACK comparison and offline replay | #63 |
| [#65](https://github.com/matusso/nyxr/issues/65) | CLI, synthetic lab and build/test verification | #64 |
| [#66](https://github.com/matusso/nyxr/issues/66) | Phase 0: live topology corpus and measured baselines | #61 |
| [#67](https://github.com/matusso/nyxr/issues/67) | Phase 1: general DSL, policy profiles and resource properties | #62 |
| [#68](https://github.com/matusso/nyxr/issues/68) | Phase 2: richer correlation, clocks, ICMP/IPv6, bounded PCAPNG | #63, #67 |
| [#69](https://github.com/matusso/nyxr/issues/69) | Phase 3: environmental controls and calibrated HZ-001/HZ-002 | #65, #66, #68 |
| [#70](https://github.com/matusso/nyxr/issues/70) | Phase 4: HZ-003/HZ-004 cross-port state experiments | #69 |
| [#71](https://github.com/matusso/nyxr/issues/71) | Phase 5: calibrated hypotheses and evidence graph | #70 |
| [#72](https://github.com/matusso/nyxr/issues/72) | Phase 6: adaptive planning and behavior profiles | #71, #66 |
| [#73](https://github.com/matusso/nyxr/issues/73) | Phase 7: API/UI, observability and production hardening | #71 |
| [#74](https://github.com/matusso/nyxr/issues/74) | Phase 8: prior-art/invention-disclosure gate | #66, #70 |

Each issue has concrete acceptance criteria and dependency links. #61–#65
enter **In review** after local implementation and validation, remaining open
for review. #66–#74 stay **Todo**. This status does not imply code publication
or a validated live lab.

PoC acceptance: fail-closed independent scope/budgets; simulated effect/null/
loss/noise; packet-to-trial tracing; replay/tamper checks; build/full tests/vet,
targeted race/fuzz and OS portability builds; scoped operator documentation.

Live #66 requires Linux ground truth, independent capture, controlled netem
loss/jitter, accuracy/traffic/latency/resource baselines and repeated null trials.
#69 pre-registers false-positive limits. #70 must demonstrate discrimination
against matched isolated controls; stop expansion if it cannot. #71 must keep
confounded scenarios unresolved. #72 requires measured accuracy/traffic benefit
and honest full port coverage. #73 requires a security review before any default
active probes. #74 requires actual prior-art/experimental evidence and counsel,
not a patentability claim. Synthetic tests do not fulfill these research gates.
