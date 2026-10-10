# Exploratory Windows IPv4 baseline

`windows-endpoint.ps1` and `windows.py` implement a separate, bounded Windows
fixture. They require an operator-owned Windows VM and a macOS source on the
same explicitly selected private virtual Ethernet segment. This is not a
Windows Nyxr backend test. The [2026-10-11 Windows corpus](../corpus/2026-10-11-windows-arm64/RESULTS.md)
records three verified IPv4 runs and preserves the initial three runs whose
short scanner captures failed because of buffering. Neither campaign passes
the complete cross-platform or statistical gate.

The Windows helper binds its native TCP listener to one assigned IPv4 address
on port 443. It creates a uniquely named inbound firewall rule restricted to
that local address, port and the source's single IPv4 address. It neither
disables the firewall nor changes global TCP features. `finally` removes its
rule and closes its listener. A deadline bounds the helper to 600 seconds by
default. Do not forcibly kill its console: bypassing `finally` can leave the
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

The output directory must not exist. Before collector traffic, a supplemental
protocol and all three planned runs are frozen. The seeds are 66100–66102;
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

IPv6, BSD, impairments, controlled Windows SACK nulls, independently held-out
fixtures and population confidence remain outstanding. Existing guest routes
are recorded without modification. Direct Ethernet probes to a VM on a NAT
segment do not measure NAT traversal or imply network disconnection. The
macOS source kernel's own RSTs are retained, unlike the Linux source's
suppressed RSTs; compare the studies with that difference in mind.

Offline re-analysis opens no network transport:

```sh
python3 lab/horizon/live/windows.py analyze --binary /tmp/nyxr-hz66-macos \
  --output /tmp/hz66-windows-new-study
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s lab/horizon/live
```
