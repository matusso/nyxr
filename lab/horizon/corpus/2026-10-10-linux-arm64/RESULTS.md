# HORIZON Linux live baseline — 2026-10-10

**Status: partial Phase 0 evidence. Issue #66 remains open.** Live Linux collection and noisy-network behavior were exercised; Windows/BSD fixtures, held-out validation, independence/stationarity and the registered statistical acceptance gates remain unmet. No OS, proxy, NAT or causal mechanism is inferred from these results.

## Environment and protocol

- Linux kernel: `Linux-7.0.14-linuxkit-aarch64-with-glibc2.41`; Docker engine 29.8.2, arm64. Runtime context recorded during the repeated campaign: 18 exposed CPUs, 8,317,267,968 bytes VM RAM; no additional container CPU/memory quota.
- Image: `sha256:ac7bc86e6101cd3630bd51aa37513303d93745643cd49161af7677a0b8f67ea5`. Package versions, build/binary hash and frozen collector/endpoint hashes are stored with each campaign. The binary build information is in [binary-buildinfo.txt](binary-buildinfo.txt).
- Network-disconnected Docker container; only private namespaces, private addresses and TCP/443. Scripts and binary were mounted read-only; results used a dedicated writable directory. No production/third-party traffic was sent.
- Primary metric: correlated SYN/ACK SACK permission. Alpha 0.05; randomized 12 paired trials, 800ms windows, 300ms washout, 3 packets/s, 48 runner packets/90s maximum. Order seeds 66000–66002. Netem random draws are not reproduced by these seeds.
- Clean and response-path `delay 20ms 5ms loss 5%` were separate conditions. SACK-enabled Linux/NAT, SACK-disabled endpoint/proxy frontend and DROP firewall truth were configured independently and retained before/after each run.
- Thresholds were registered in issue #66 before the live campaign: >=60 resolved complete null repetitions per stratum, zero false positives, no missing/invalid/unresolved planned runs, exact one-sided 95% upper bound <=5%; >=12 clean effect repetitions and >=90% expected effects over all planned runs. These gates are **not passed** by this exploratory corpus.

## Completed evidence

- 44 completed live HORIZON reports and 44 one-port scanner baselines: 2 clean preflight reports, 18 full-matrix reports and 24 repeated null/proxy reports. All completed HORIZON reports passed canonical offline replay and independent-capture TX matching. Backend and independent capture drop counters were zero.
- A prior setup attempt failed before traffic because Docker mounted `/proc/sys` read-only. Its manifest retains one started/failed and one unstarted planned run. It is archived separately as `setup-failure`; it is not counted as successful live evidence.
- Collector fixes handle private namespace-local procfs writes, the scanner observation-plus-summary stream, and bounded child shutdown on cancellation. Cancellation and resource/error retention were verified in an unprivileged Linux test container; all 10 accounting tests passed.
- [baseline-summary.json](baseline-summary.json) preserves every analyzed outcome and per-stratum denominator. [raw-corpus.tar.gz](raw-corpus.tar.gz) contains raw reports/stdout/stderr, independent PCAP/drop logs, plans, resources, topology/rule/qdisc/counter snapshots, environment files and frozen source provenance. The old frozen collectors are provenance snapshots; use the maintained collector for new runs.

## Full Linux matrix

One repetition per row. “Expected agreement” compares to the independently configured SACK outcome; unresolved is the expected firewall outcome. Every planned row remains in the denominator.

| Case | Family | Condition | HZ-001 outcome | Timeouts / 24 | Runner TX | Independent packets | Scanner state |
| --- | --- | --- | --- | ---: | ---: | ---: | --- |
| linux | IPv4 | clean | difference | 0 | 48 | 76 | open |
| linux | IPv4 | loss-jitter | difference | 0 | 48 | 77 | open |
| linux | IPv6 | clean | difference | 0 | 48 | 80 | open |
| linux | IPv6 | loss-jitter | unresolved | 2 | 44 | 72 | filtered |
| null | IPv4 | clean | no-difference | 0 | 48 | 76 | open |
| null | IPv4 | loss-jitter | unresolved | 1 | 46 | 75 | open |
| null | IPv6 | clean | no-difference | 0 | 48 | 80 | open |
| null | IPv6 | loss-jitter | unresolved | 2 | 46 | 83 | open |
| proxy | IPv4 | clean | no-difference | 0 | 48 | 76 | open |
| proxy | IPv4 | loss-jitter | no-difference | 0 | 48 | 75 | open |
| proxy | IPv6 | clean | no-difference | 0 | 48 | 79 | open |
| proxy | IPv6 | loss-jitter | unresolved | 1 | 46 | 77 | open |
| nat | IPv4 | clean | difference | 0 | 48 | 76 | open |
| nat | IPv4 | loss-jitter | unresolved | 2 | 45 | 77 | open |
| firewall | IPv4 | clean | unresolved | 24 | 24 | 24 | filtered |
| firewall | IPv4 | loss-jitter | unresolved | 24 | 24 | 24 | filtered |
| firewall | IPv6 | clean | unresolved | 24 | 24 | 24 | filtered |
| firewall | IPv6 | loss-jitter | unresolved | 24 | 24 | 24 | filtered |

Outcomes: 4 SACK differences, 5 no detectable differences, 9 unresolved. Expected-outcome agreement is 13/18 over all planned rows; all 9 clean rows agree. Four unresolved firewall rows match their known DROP truth; five additional unresolved rows expose attrition under loss/jitter.

The significant complete SACK-enabled runs have 12 treatment-only pairs, zero control-only pairs and exact p=0.00048828125. A missing-reply run remains unresolved even when its surviving pairs have p<0.05. The IPv6 Linux loss/jitter run missed two replies and the ordinary scanner reported `filtered` for the known-open listener. This is a published negative result, not evidence that the service closed. The discovery baseline classified 17/18 rows correctly.

## Repeated null/proxy baseline

Three repetitions per family/condition. Unresolved runs are retained, not silently removed or counted as successful null trials. False-positive bounds are per stratum; the small strata are not pooled to claim acceptance.

| Stratum | Planned | Resolved null | Unresolved | False positives | Zero-FP upper 95% |
| --- | ---: | ---: | ---: | ---: | ---: |
| Linux/null/v4/clean | 3 | 3 | 0 | 0 | 63.16% |
| Linux/null/v4/loss-jitter | 3 | 0 | 3 | 0 | unknown |
| Linux/null/v6/clean | 3 | 3 | 0 | 0 | 63.16% |
| Linux/null/v6/loss-jitter | 3 | 1 | 2 | 0 | 95.00% |
| Linux/proxy/v4/clean | 3 | 3 | 0 | 0 | 63.16% |
| Linux/proxy/v4/loss-jitter | 3 | 1 | 2 | 0 | 95.00% |
| Linux/proxy/v6/clean | 3 | 3 | 0 | 0 | 63.16% |
| Linux/proxy/v6/loss-jitter | 3 | 1 | 2 | 0 | 95.00% |

Total: 15 valid no-difference results, 9 unresolved results, zero observed false SACK differences; all 24 reports and both captures per report passed integrity/quality checks. The ordinary scanner classified 23/24 ports correctly; its miss was `proxy-v6-loss-jitter-002`. This is exploratory, not calibrated population accuracy. With 0/3 false positives in each clean stratum, the one-sided upper bound is 63.16%, far above the registered 5% ceiling. No null gate passed.

## Traffic, timing and resource baseline

Values below describe the 18-condition matrix. HORIZON performs 12 pairs; the scanner discovers one port. IPv4 discovery uses raw SYN; IPv6 discovery uses connect mode. Task and traffic budgets differ, so these measurements do not support a speedup comparison.

- HORIZON runner TX: 755 packets / 49,922 bytes, including cleanup. Independent total traffic: 1,175 packets / 79,050 bytes, including endpoint/kernel traffic.
- HORIZON wall time per run: 26.730–27.566s. Per-child user CPU: 0.029–0.055s; system CPU: 0.082–0.113s; peak RSS: 47,928 KiB. These include the namespace-exec wrapper.
- Linux clean reply RTT p50: 0.265ms IPv4 / 0.252ms IPv6. Under netem: 22.886ms / 23.516ms. These are userspace receive timings over received replies, not calibrated wire latency; timeout and unresolved counts remain separate.
- Matrix timeouts: 104 of 432 arms, including 96 expected firewall timeouts. Repeated null/proxy timeouts: 17 of 576 arms. No per-run runner packet cap was exceeded.

## Verify and replay

The lossless archive has 693 raw files. [raw-artifact-hashes.json](raw-artifact-hashes.json) hashes every file inside it; [SHA256SUMS](SHA256SUMS) hashes the delivered artifacts. SHA-256 is corruption detection, not authentication.

```sh
(cd lab/horizon/corpus/2026-10-10-linux-arm64 && shasum -a 256 -c SHA256SUMS)
mkdir -p /tmp/hz66-corpus
tar -xzf lab/horizon/corpus/2026-10-10-linux-arm64/raw-corpus.tar.gz -C /tmp/hz66-corpus
python3 lab/horizon/live/lab.py analyze --binary "$PWD/nyxr" --output /tmp/hz66-corpus/linux-matrix
python3 lab/horizon/live/lab.py analyze --binary "$PWD/nyxr" --output /tmp/hz66-corpus/null-repeats
```

For individual reports, `nyxr horizon replay report.json` opens no network transport. All 44 reports were checked after archival.

## Registered metadata clarification

The registered limitations include an imprecise statement that IPv6 uses a routed path. The measured IPv6 targets were directly attached Linux listeners or proxy frontends; no routed IPv6 backend/NAT measurement was performed. Routing snapshots alone do not validate that path. The immutable protocol files are retained as recorded; treat that wording as an erratum, not an additional validated fixture.

## Remaining gates

- Windows/BSD kernel ground truth, IPv4/IPv6 fixtures and held-out networks. A stopped local Windows VM was discovered with NAT networking; it was not booted/reconfigured and no isolated guest access was supplied. No BSD fixture was available.
- The full >=60-per-stratum null study and >=12 clean effect repetitions, with dependence/stationarity assessment. These are deliberately separate from the smoke/exploratory corpus.
- Broader mechanisms, ICMP/path-shift/OS inference, timestamp/checksum calibration and causal claims remain outside HZ-001. This corpus confirms scoped collection and conservative unresolved behavior, not unique identification of topology.

Issue #66 can mark live Linux/netem validation and pre-registration/negative-result publication complete, but should remain open for the unfulfilled corpus and statistical acceptance gates.
