# Exploratory Windows IPv4/IPv6 baseline

`windows-endpoint.ps1` and `windows.py` implement separate, bounded Windows
fixture. They require an operator-owned Windows VM and a macOS source on the
same explicitly selected private virtual Ethernet segment. This is not a
Windows Nyxr backend test. The [2026-10-11 Windows corpus](../corpus/2026-10-11-windows-arm64/RESULTS.md)
records three verified IPv4 runs and preserves the initial three runs whose
short scanner captures failed because of buffering. Neither campaign passes
the complete cross-platform or statistical gate. The separate
[IPv6 corpus](../corpus/2026-10-11-windows-ipv6-arm64/RESULTS.md) records three
verified IPv6 runs on the same endpoint with temporary ULA addresses and
confirmed cleanup.

The Windows helper binds its native TCP listener to one assigned private address
on port 443. It creates a uniquely named inbound firewall rule restricted to
that local address, port and the source's single address. It neither
disables the firewall nor changes global TCP features. `finally` removes its
rule and closes its listener. A deadline bounds the helper to 600 seconds by
default and at most six hours. Do not forcibly kill its console: bypassing `finally` can leave the
rule behind. If that happens, remove only the printed `nyxr-hz66-<UUID>` rule
with `Remove-NetFirewallRule -Name '<exact printed name>'` in an elevated
console.

Start the reviewed local script in elevated PowerShell, substituting the
addresses of the explicitly authorized VM/source:

```powershell
& .\windows-endpoint.ps1 -LocalAddress 192.168.254.130 -PeerAddress 192.168.254.1
```

From macOS (BPF device access is required):

```sh
python3 lab/horizon/live/windows.py run --binary /tmp/nyxr-hz66-macos \
  --output /tmp/hz66-windows-new-study --target 192.168.254.130 \
  --source 192.168.254.1 --interface bridge101 --mac 00:0c:29:7d:91:cb
```

IPv6 requires ULA addresses (`fc00::/7`) on that same authorized adapter.
Link-local, zone-qualified and public IPv6 targets are rejected. With existing
assigned ULAs, use the same commands with the IPv6 local/peer/source/target
addresses. When the Windows adapter has only link-local IPv6, the helper can
create one temporary ULA selected through its existing private IPv4 address:

```powershell
& .\windows-endpoint.ps1 -LocalAddress fd66:66:11::2 -PeerAddress fd66:66:11::1 `
  -AddTemporaryIPv6 -InterfaceIPv4 192.168.254.130
```

The selected ULA must not already exist. It is added only to ActiveStore, with
`SkipAsSource` to avoid automatic DNS registration, after recording addresses,
routes and IPv6 interface settings. Duplicate-address detection must complete.
Cleanup removes only that added address and restores the recorded DHCP state
(adding a static address can disable DHCP for its family). No default gateway
is added. Record and verify address removal and DHCP restoration after the
helper exits. The source must also have an explicitly assigned ULA; remove any
temporary source address afterward. A `/64` connected route does not establish
routed IPv6 or NAT coverage.

The IPv6 supplement is `horizon-windows-ipv6-exploratory/v1`, seeds 66200–66202,
with a separate three-run denominator. The immutable IPv4 protocol and its
archived results are unchanged. IPv6 uses the existing scanner's TCP connect
mode, since raw SYN scanning is IPv4-only. Its actual source SYNs are checked
against independent IPv6 PCAPs; capture totals include the kernel handshake
and teardown as well as the paired HORIZON raw traffic.

The output directory must not exist. Before collector traffic, a supplemental
protocol and all three planned runs are frozen. The IPv4 seeds are 66100–66102;
each run uses the Linux study's 12-pair/800ms-window/300ms-washout/3pps/
48-packet/90s limits. Native Windows SACK support is the pre-registered
**hypothesis**; the helper cannot independently disable/configure SACK and
cannot supply a known null control. Agreement is exploratory and cannot pass
the full cross-platform ground-truth gate. Three repeats cannot pass the
registered 12-repeat clean effect gate either.

The collector retrieves native OS build, adapter MAC, addresses/routes,
firewall state and TCP settings before/after each run through two fixed
messages (`TRUTH`, `STOP`). It has no guest command-execution interface. It
validates the endpoint identity and exact temporary firewall scope before
measurement. Telemetry requests occur outside independent measurement windows.

The scanner baseline uses one-port raw SYN. Independent classic Ethernet
PCAPs must retain every runner TX and zero capture drops. Immediate capture mode
is required for the short scanner workload; zero drops alone do not prove that
its buffered packets were written. Analysis also requires independently
captured SYN transmissions matching the scanner's TX denominator. Canonical replay,
failed/missing/unresolved outcomes, scanner classifications, traffic, reply
RTT, timeouts and child resources remain in the record. macOS `wait4` RSS bytes
are normalized to KiB. Those resources describe the macOS children, not the
Windows listener. The collector requests `STOP` at the end and records whether
its rule was removed; a cleanup failure remains explicit.

BSD, impairments, controlled Windows SACK nulls, independently held-out
fixtures and population confidence remain outstanding. Existing guest routes
are recorded; temporary IPv6 setup adds its connected prefix. Direct Ethernet
probes to a VM on a NAT
segment do not measure NAT traversal or imply network disconnection. The
macOS source kernel's own RSTs are retained, unlike the Linux source's
suppressed RSTs; compare the studies with that difference in mind.

## Separately registered Windows clean and blocked study

`windows-study-protocol.json` freezes 12 clean and three known-blocked reports
per address family, with distinct IPv4/IPv6 seeds and denominators. The clean
setting tests the previously observed native Windows SACK effect hypothesis.
It is not a controlled SACK-disabled null: the helper records the `SackOpts`
registry value if present but never changes it. The blocked setting adds a
temporary inbound firewall **block** only for the measurement peer and TCP
port 443. A separate peer-scoped TCP 8443 control port carries the fixed
`TRUTH`, `BLOCK`, `UNBLOCK`, and `STOP` messages so the collector can verify
native state while the measurement port is blocked. The blocked reports are
expected to remain unresolved and are never counted as resolved nulls.

Start the same reviewed helper in elevated PowerShell with `-StudyControl`
and a 1,200-second bound. Use the same explicit private addresses as above:

```powershell
& .\windows-endpoint.ps1 -LocalAddress 192.168.254.130 -PeerAddress 192.168.254.1 -StudyControl -Seconds 1200
```

From macOS, collect IPv4 using the separately registered collector:

```sh
python3 lab/horizon/live/windows_study.py run --binary /tmp/nyxr-hz66-macos \
  --output /tmp/hz66-windows-study-v4 --target 192.168.254.130 \
  --source 192.168.254.1 --interface bridge101 --mac 00:0c:29:7d:91:cb
```

For IPv6, add the temporary source ULA and use the helper's
`-AddTemporaryIPv6 -InterfaceIPv4` options as described above; collect to a
different output directory with the two ULA addresses. Remove the source ULA
after collection. Every run retains before/after native rule and TCP setting
records, independent PCAPs, scanner output, raw HORIZON reports and child
resource measurements. The collector requests `STOP` even after an error and
records cleanup failure explicitly. If a guest process is forcibly killed,
remove only rules with the printed fixture's exact `nyxr-hz66-` names, then
check for remaining temporary addresses.

The completed [IPv4](../corpus/2026-10-13-windows-study-ipv4-arm64/RESULTS.md)
and [IPv6](../corpus/2026-10-13-windows-study-ipv6-arm64/RESULTS.md) clean/block
studies each retain 12 valid clean differences and three valid unresolved
known blocks, with zero missing or invalid reports. The IPv6 fixture rules and
source temporary address were removed. The guest address cleanup check is
recorded separately from the collector's rule cleanup: the operator's read-only
post-exit check found the address absent, with IPv6 DHCP and router discovery
enabled as before setup.

Windows loss/jitter, a controlled Windows SACK null, independently held-out
coverage, stationarity and population acceptance remain separate #66 gates.

Offline re-analysis opens no network transport:

```sh
python3 lab/horizon/live/windows.py analyze --binary /tmp/nyxr-hz66-macos \
  --output /tmp/hz66-windows-new-study
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s lab/horizon/live
```

## Routed Windows study with a SackOpts null attempt

`windows-routed-protocol.json` registers `horizon-windows-routed-controlled/v2`.
The source (`10.66.21.1`, `fd66:66:21::1`) and the Windows target
(`10.66.22.2`, `fd66:66:22::2`) use distinct prefixes on the private Fusion
segment. Each side routes the other prefix through the FreeBSD VM
(`.3`/`::3` on both prefixes), so every measurement packet is forwarded at
layer 3. IPv4 and IPv6 run as separate collections, each with its own frozen
denominator; there is no NAT.

v1 (commit "Register routed Windows study with SackOpts null attempt (v1)")
also shaped forwarded SYN-ACKs with dummynet. The FreeBSD 15.1 ARM64 router
panicked (`vm_fault failed`, in `in_lltable_lookup` and `in_localip_fib`)
within a minute of loss/jitter shaping, on `em0` and again on `vmx0`. v1
stopped after 7 of 27 native IPv4 runs; its outcomes stay in their own
denominator. v2 drops the loss/jitter condition: there is no Windows
impairment stratum.

`bsd-router.sh setup <interface>` records the router state, loads IPFW (no
dummynet) with an accept default, adds the four router aliases, enables
forwarding, disables ICMP redirects and installs two count rules on forwarded
TCP443 SYN-ACKs to the source. Measurement runs reach it through an SSH forced
command (`command="/root/hz66-router.sh control",restrict`) that accepts only
`TRUTH`, `CLEAN` and `DROP`. `DROP` denies those same replies. Probes and the
fixed TCP8443 control channel are forwarded without rules. `teardown` removes
the rules, aliases and newly loaded module and restores the recorded sysctls
and tunable.

`windows-routed-setup.ps1` adds the Windows target addresses and routes in
ActiveStore, records the prior IPv6 DHCP state and removes exactly those
objects on `Teardown`. `SetSackOpts` creates
`Tcpip\Parameters\SackOpts = 0` and records the change time. `ClearSackOpts`
deletes it. A full restart follows each change, which also clears every
ActiveStore address, so `Setup` runs again afterwards. The unchanged helper
runs with `-StudyControl`, and its native truth also reports the boot time.
The collector checks every truth snapshot against the registered SackOpts
value, a boot later than the recorded change, the Windows route through the
router, and the router fixture, condition, rule scope, boot time and absence
of dummynet. It requires the router counters to increase for every run.

Results: the [v2 corpus](../corpus/2026-10-19-windows-routed-arm64/RESULTS.md)
has all native and restore reports correct. The SackOpts control was
ineffective on build 26200: feasibility still showed treatment-only SACK. The
null phase was therefore not executed. The
[v1 corpus](../corpus/2026-10-19-windows-routed-v1-failed-arm64/RESULTS.md)
retains the router panics.

The phases run in order. `native` (SackOpts absent): 12 clean effect-hypothesis
runs, then three known DROP checks. `feasibility` (SackOpts 0): three clean
runs. `null` runs only if all six feasibility reports are valid no-difference
outcomes and no SYN-ACK in either arm carries SACK-permitted: 60 clean nulls
per family. Otherwise the control is declared ineffective and its 120 reports
remain recorded as not executed under the stopping rule. `restore` (SackOpts
deleted again): one clean run per family.

```sh
python3 lab/horizon/live/windows_routed.py run --binary /path/to/nyxr \
  --output /tmp/routed-native-v4 --phase native --family 4 --interface bridge100 \
  --router 192.168.254.131 --router-key /path/to/forced-command-key \
  --router-known-hosts /path/to/known_hosts --router-mac <router MAC> \
  --target-mac <Windows MAC>
python3 lab/horizon/live/windows_routed.py combine --binary /path/to/nyxr \
  --output /tmp/routed-*
```

SackOpts phases also need `--sackopts-record` (the JSON written by the setup
script). `null` additionally needs `--feasibility` with both feasibility
outputs. The macOS source aliases and routes require root; remove them after
collection. The helper must run elevated and outlive the remote session; a
SYSTEM scheduled task works. If the router is unreachable the collector cannot
send `STOP`; end the task and remove only the printed fixture rules.
