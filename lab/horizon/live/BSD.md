# Controlled FreeBSD baselines

## Expanded VNET study

The separate bsd-study-guest.sh, bsd-study-endpoint.c, bsd-study-protocol.json,
bsd-delay-profile.txt and bsd_study.py implement the larger study without
changing the exploratory registration or corpus. The bootstrap is specific to
the recorded Fusion lab; adapt its explicit private addresses for another lab.
It requires an operator-owned disposable VM with no existing jails or IPFW.

Two fresh VNET jails have separate TCP stacks, epair adapters and private IPv4/
IPv6 addresses. Runtime directories use read-only nullfs mounts; devfs uses
ruleset 4. No credentials or packages are installed. A temporary guest bridge
attaches the fixtures to the VM Ethernet interface. Static IPv4 addresses are
outside the recorded DHCP pool. No forwarding or default routes are added.

Before loading absent IPFW/dummynet modules, the bootstrap records and
temporarily sets the default-to-accept tunable and verifies the default-only
ruleset. Host rules are unchanged. Fresh VNET rules 60066/60067, set 30 and pipe
6066 affect only outgoing TCP443 SYN-ACKs to exact private source addresses.
The registered impairment uses an empirical uniform 15–25ms delay profile,
5% loss and a 100Mbit/s cap; DROP denies the same replies. This condition is
not claimed identical to Linux netem.

TCP443 connections carry no commands. Private IPv4 control TCP18067 bypasses
shaping and accepts only TRUTH, CLEAN0, CLEAN1, IMPAIR0, IMPAIR1, DROP1 and STOP.
No arbitrary command or remote shell interface exists. Native SACK/condition
controls reopen measurement listeners before each run; before/after snapshots
record native settings and rule/pipe counters. Helpers stop after six hours.

The frozen plan has 588 reports: twelve balanced randomized blocks provide 60
nulls and 12 effects per role/family/clean-or-impaired stratum, followed by three
DROP checks per role/family. Both roles are allocated before experimental
traffic, with no algorithm tuning from reserved outcomes. Two workers run
concurrently at at most 6pps combined, retaining separate captures and per-child
resources. An external 90s deadline stops/reaps failed children.

Prepare a JSON mapping development and reserved to verified target_v4,
target_v6, source_v4, source_v6, guest_interface and next_hop_mac. Role targets/
MACs must differ and source addresses must already be assigned:

    PYTHONDONTWRITEBYTECODE=1 python3 lab/horizon/live/bsd_study.py run \
      --binary /path/to/nyxr --output /tmp/new-bsd-vnet-study \
      --interface bridge101 --fixtures /path/to/verified-fixtures.json

Offline bsd_study.py analyze uses the same binary/output flags, identical
canonical replay, native/canonical SACK agreement and independent TX accounting.
All planned invalid, missing and unresolved outcomes remain in their separate
denominators. Strict complete-pair inference may fail under loss; the rule is
not relaxed to obtain success.

Numerical confidence/effect gates are conditional on IID sampling. Shared
kernel/VM/source resources prevent a claim of physically independent held-out
or population performance. Split-half RTT drift and lag-one correlation are
descriptive preregistered diagnostics; no flags cannot prove IID/stationarity.
Count thresholds alone cannot close the issue.

STOP restores each VNET's original SACK value and clears owned shaping rules.
The wrapper removes owned jails, mounts, bridge, epairs and newly loaded modules,
and restores the prior tunable. Retain host before/after snapshots, then remove
only the source's owned IPv6 alias and confirm endpoints are closed. A crash or
forced SIGKILL can bypass traps; inspect and clean only this study's resources.

## Exploratory clean fixture

`bsd-endpoint.c` supplies native TCP listeners and an independently controlled
SACK setting on an operator-owned FreeBSD lab VM. `bsd.py` measures those
listeners from an explicitly selected macOS Ethernet BPF interface. The fixture
is a FreeBSD endpoint test, not a FreeBSD Nyxr backend test.

The [2026-10-12 FreeBSD corpus](../corpus/2026-10-12-freebsd-arm64/RESULTS.md)
records 12 verified clean baselines and separately retains an expired setup.
All four family/state strata agree with native ground truth, with confirmed
SACK/listener/address cleanup. Three repeats per stratum do not pass the full
statistical gate.

The guest helper requires root and explicit interface/local/peer arguments. It
checks that its private IPv4 and ULA IPv6 addresses are assigned to the selected
adapter, binds only those addresses on TCP 443, and accepts application messages
only from its exact source peers. IPv6 is IPv6-only. Binding fails if another
listener already owns an address/port; existing listeners are not replaced.

The only accepted messages are `TRUTH`, `SACK0`, `SACK1` and `STOP`. There is no
guest command execution interface. SACK controls use native `sysctlbyname` on
`net.inet.tcp.sack.enable`; telemetry independently records the value and a
native TCP settings snapshot. The change affects the dedicated VM's TCP stack.
The helper restores its original value and closes both listeners on stop,
handled signals or its bounded deadline (60–1800 seconds). SIGKILL or a VM crash
can bypass restoration; do not forcibly kill the helper. If required, restore
only its printed original SACK value from the local root console.

Build and start in the authorized guest, substituting its verified addresses:

```sh
cc -O2 -Wall -Wextra -Werror -o /tmp/bsd-endpoint bsd-endpoint.c
/tmp/bsd-endpoint em0 192.168.254.131 192.168.254.1 \
  fd66:66:12::2 fd66:66:12::1 900
```

Both source and guest must have explicitly assigned IPv6 ULAs. If temporary
aliases are needed, refuse to replace an existing address, record the prior
interface/routes, wait for duplicate-address detection and remove only the
new aliases after the study. The helper does not create addresses, alter
firewall rules, add default gateways or install packages. Temporary `/64`
aliases create a connected prefix and do not validate routed IPv6 or NAT.

From the macOS source (BPF access is required):

```sh
python3 lab/horizon/live/bsd.py run --binary /tmp/nyxr-hz66-macos \
  --output /tmp/hz66-bsd-new-study --target-v4 192.168.254.131 \
  --source-v4 192.168.254.1 --target-v6 fd66:66:12::2 \
  --source-v6 fd66:66:12::1 --guest-interface em0 --interface bridge101 \
  --mac 00:0c:29:85:1a:62
```

`bsd-protocol.json` separately registers 12 clean runs: three repetitions in
each IPv4/IPv6 SACK-enabled/disabled stratum. Seeds 66300–66311 and every
planned outcome are frozen before collector traffic. Each experiment uses the
Linux study's 12 pairs, 800ms observation, 300ms washout, 3pps and 48-packet/90s
limits. SACK-enabled truth expects a treatment-only negotiation difference;
SACK-disabled truth expects no detectable difference. Before/after native
truth must agree with the registered setting and stable fixture/adapter identity.

Independent PCAPs use immediate capture. Analysis requires zero capture and
backend drops, every raw HORIZON TX frame, scanner SYN transmissions matching
the positive reported denominator, canonical replay, and the original planned
experiment. IPv4 scanner mode is raw SYN; IPv6 uses kernel connect. Capture
totals include endpoint/kernel traffic. Resources describe source children,
not guest CPU/RSS; Darwin RSS bytes are normalized to KiB. The scanner and
paired experiment solve different tasks and establish no speedup ratio.

Missing, failed, invalid, reverse and unresolved outcomes are preserved in each
all-planned denominator. Neither families nor SACK states are pooled. Three
resolved nulls with zero false positives give an exact one-sided 95% upper
bound of about 63.16%, which cannot pass the registered 5% ceiling. Controlled
null truth does not by itself satisfy the full sample-size, independence,
impairment, platform breadth or independently held-out acceptance gates.

The collector requests stop and retains restoration evidence. When an operator
wrapper adds temporary addresses, separately record native post-cleanup SACK,
listener and alias state plus a source interface snapshot after alias removal.
Native firewall snapshots can report an unavailable module; preserve that
status without enabling or disabling the firewall for the experiment.

Offline re-analysis opens no network transport:

```sh
python3 lab/horizon/live/bsd.py analyze --binary /path/to/nyxr \
  --output /tmp/hz66-bsd-new-study
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s lab/horizon/live
```
