# Runtime packet gates

## Linux AF_PACKET

Run `sudo bash tests/lab/linux-netns.sh` on Linux with `iproute2`, Python 3,
Go, and optionally `iptables`. The script builds nyxr, creates two disposable
network namespaces and a veth pair, and verifies automatic ARP resolution,
raw SYN open/closed/filtered classification, and IPv4 ARP/IPv6 NDP discovery,
then runs a fixed 100-port closed scan. It prints the 100-probe
throughput and source-interface TX/RX packet and drop deltas across both scans.
The filtered case needs `iptables`.
No external target or permanent network setting is used. A container needs
`CAP_NET_ADMIN` and `CAP_NET_RAW` in addition to root.

## macOS BPF manual gate

Use an isolated Ethernet test network with a known responder at `TARGET_IP`,
an open TCP port `OPEN_PORT`, a closed TCP port `CLOSED_PORT`, and the responder
or gateway MAC `NEXT_HOP_MAC`. Run from the project root on the actual macOS
host, with `INTERFACE` set to its Ethernet interface:

```sh
go build -o /tmp/nyxr-smoke ./cmd/nyxr
sudo /tmp/nyxr-smoke sniff --interface "$INTERFACE" --count 1 --timeout 10s
sudo /tmp/nyxr-smoke scan --tcp-mode syn --interface "$INTERFACE" --next-hop-mac "$NEXT_HOP_MAC" --protocols tcp --ports "$OPEN_PORT,$CLOSED_PORT" --workers 1 --timeout 500ms --json "$TARGET_IP"
```

Generate a packet on the interface while `sniff` runs. Require a decoded
Ethernet/IP observation, then JSON states `open` and `closed` with one
transmitted packet each. Record OS version, interface, privileges, Npcap/BPF
version where relevant, emitted JSON, and NIC packet/drop counters. A BPF
open or timeout by itself does not pass this gate.

## Windows Npcap manual gate

Install Npcap with WinPcap API compatibility on a Windows host. In elevated
PowerShell, set `$adapter` to a `\Device\NPF_{GUID}` Ethernet adapter and
set `$sourceIP`, `$sourceMAC`, `$nextHopMAC`, `$targetIP`, `$openPort`, and
`$closedPort` to values from an isolated test network. Then run:

```powershell
go build -o "$env:TEMP\nyxr-smoke.exe" ./cmd/nyxr
& "$env:TEMP\nyxr-smoke.exe" sniff --interface $adapter --count 1 --timeout 10s
& "$env:TEMP\nyxr-smoke.exe" scan --tcp-mode syn --interface $adapter --source-ip $sourceIP --source-mac $sourceMAC --next-hop-mac $nextHopMAC --protocols tcp --ports "$openPort,$closedPort" --workers 1 --timeout 500ms --json $targetIP
```

Generate traffic while `sniff` runs. Require one decoded frame and `open` /
`closed` JSON observations. Save `Get-NetAdapterStatistics -Name <adapter
display name>` before and after, plus the adapter ID, Npcap version, Windows
build, and scan output. These gates must run on real hosts; cross-builds do
not establish live RX/TX behavior.
