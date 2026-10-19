# Routed Windows study with a SackOpts null attempt, 2026-10-19

The separately registered `horizon-windows-routed-controlled/v2` study placed the
native Windows 11 target behind one FreeBSD layer-3 hop and attempted a
controlled Windows SACK null through the `SackOpts` registry value. All 38
executed reports were valid full baselines. The SackOpts control was
**ineffective**: Windows still offered SACK in every treatment SYN-ACK after the
value was set and the VM restarted. The registered stopping rule therefore
left all 120 planned null reports unexecuted. No controlled Windows null
exists. The interrupted v1 registration is kept separately in the
[v1 corpus](../2026-10-19-windows-routed-v1-failed-arm64/RESULTS.md) and is not pooled.

| Phase / stratum | SackOpts | Planned | Valid | Invalid | Missing | Expected | Correct |
| --- | --- | ---: | ---: | ---: | ---: | --- | ---: |
| Native IPv4 clean | absent | 12 | 12 | 0 | 0 | SACK difference | 12 |
| Native IPv4 DROP | absent | 3 | 3 | 0 | 0 | Unresolved | 3 |
| Native IPv6 clean | absent | 12 | 12 | 0 | 0 | SACK difference | 12 |
| Native IPv6 DROP | absent | 3 | 3 | 0 | 0 | Unresolved | 3 |
| Feasibility IPv4 | 0 | 3 | 3 | 0 | 0 | No difference | 0 |
| Feasibility IPv6 | 0 | 3 | 3 | 0 | 0 | No difference | 0 |
| Null IPv4 / IPv6 | 0 | 60 / 60 | — | — | — | No difference | not executed (stopping rule) |
| Restore IPv4 / IPv6 | absent | 1 / 1 | 1 / 1 | 0 | 0 | SACK difference | 1 / 1 |

All 38 ordinary scanner checks matched the path: 32 open and six filtered
under DROP. IPv4 scanning used raw SYN; IPv6 used kernel connect.

## Registration and topology

The protocol (`windows-routed-protocol.json`, commit `0cab853`) was committed
before traffic. It froze seeds 70000–70510, the phase order and the feasibility
stopping rule. Runs kept the shared 12-pair, 800ms observation, 300ms washout,
3pps, 48-packet and 90s limits. Native clean runs used 12 randomized blocks;
three DROP checks followed.

The macOS source (`10.66.21.1`, `fd66:66:21::1`) and Windows target
(`10.66.22.2`, `fd66:66:22::2`) used distinct prefixes on the private Fusion
segment. Each side routed the other prefix through the FreeBSD 15.1-RELEASE-p4
ARM64 router (`vmx0`, IPFW only, no dummynet, ICMP redirects disabled). There
was no NAT. Router truth was read before and after every run: fixture
identity, condition, boot time, forwarding/redirect sysctls, the exact owned
rule set and the absence of dummynet. Windows truth recorded build 26200, the
SackOpts value, the boot time, the route to the source prefix through the
router, the scoped helper/control rules and the adapter MAC.

Routing was confirmed for every run. The router's scoped count rule advanced
by 25–29 forwarded SYN-ACKs per run: 1,038 in total.

## SackOpts control

`SackOpts = 0` was written at 13:02:32Z and Windows restarted at 13:02:50Z.
Both values were checked before and after every feasibility run. All six
feasibility reports had 12 complete pairs, 12 treatment SYN-ACKs carrying
SACK-permitted, none in control and p=0.00048828125. That is the same result
as with the value absent. On this Windows 11 build the registry value does not
disable SACK negotiation, so the stopping rule applied. The value was deleted at
13:16:40Z, Windows restarted at 13:16:52Z, and the restore runs again showed
SACK differences.

## DROP behaviour

The router denied only forwarded TCP443 SYN-ACKs. Both arms of a pair use the
same source port, so the second arm's SYN reached Windows while it still held
the first arm's half-open entry. Windows answered with an RST-ACK, which the
router forwarded (TTL 127): 12 of 24 arms per DROP run, with the other 12
timing out. Every DROP report had zero complete pairs and stayed unresolved.
This fixture filters SYN-ACKs; it is not a blackhole and not the Windows
firewall block of the 2026-10-13 study.

## Traffic, timing and resources

| Collection | Runner TX | Captured HORIZON | Wall time (s) | Peak RSS (KiB) |
| --- | ---: | ---: | --- | --- |
| Native IPv4 clean (12) | 576 / 32,832 B | 924 / 53,544 B | 27.226–27.247 | 29,904–30,400 |
| Native IPv4 DROP (3) | 72 / 4,320 B | 111 / 6,426 B | 26.467–26.471 | 29,808–30,000 |
| Native IPv6 clean (12) | 576 / 44,352 B | 864 / 67,392 B | 27.224–27.241 | 29,840–30,368 |
| Native IPv6 DROP (3) | 72 / 5,760 B | 111 / 8,646 B | 26.460–26.466 | 29,920–30,160 |
| Feasibility IPv4 (3) | 144 / 8,208 B | 231 / 13,386 B | 27.224–27.232 | 30,016–30,176 |
| Feasibility IPv6 (3) | 144 / 11,088 B | 216 / 16,848 B | 27.227–27.233 | 30,304–30,544 |
| Restore IPv4 / IPv6 (1 each) | 48 / 2,736 B; 48 / 3,696 B | 77 / 4,462 B; 72 / 5,616 B | 27.230; 27.235 | 30,224; 30,288 |

Captures on the shared segment include both forwarded legs, so they exceed
runner TX. Every runner transmission and scanner SYN was present in the
independent captures, with zero kernel/backend drops and no timeouts outside
DROP. Resources describe macOS source children, not Windows or router
CPU/RSS. Timings are descriptive, not calibrated wire latency or a speedup.

## Verification and archive

All 38 canonical reports replayed identically. The 729 raw files in
`raw-corpus.tar.gz` passed SHA-256 checks after extraction, and frozen-source
re-analysis of the extracted archive reproduced every stored summary and the
combined all-planned accounting. Archive SHA-256:
`2255c8160a481a719d7826db5a5438898249d4273bc93236ab0f230bc8fcdf9b`.

The archive includes plans, router and Windows before/after truth,
independent captures, raw reports, scanner results, resource accounting,
SackOpts change records, setup/teardown evidence, collection logs and the
frozen source. Two declared redactions were applied before hashing:
operator-local path prefixes became `/tmp/hz66` / `<repo>`, and
`environment.json` keeps only routes on the measurement interface. The
collector now records only those routes. Neither file is read by analysis.

Cleanup is verified. The helper and control rules were removed after each
collection, Windows routed addresses and routes were removed, SackOpts is
absent and IPv6 DHCP was left unchanged. Router teardown unloaded IPFW and
restored forwarding and redirect sysctls and the tunable.

## Limitations

- No Windows loss/jitter stratum: v1's dummynet shaping panicked the router.
- No controlled Windows null: the SackOpts control was ineffective. The Windows
  null gate cannot be evaluated with this fixture.
- Same Windows 11 and FreeBSD VMs as earlier studies; a fresh routed
  configuration, not physically independent held-out hardware.
- Numerical gates assume IID Bernoulli sampling, which cannot be established.
- Routed IPv4/IPv6 through one hop without NAT; NAT/proxy fixtures come from the
  Linux corpus.
