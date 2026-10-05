# Runtime gates

Cross-builds and fixtures prove that code compiles and parses correctly. They
do not prove that a live backend sends and receives packets on a given
operating system. These gates do. Run them on real hosts, record the results,
and update the [Roadmap](../roadmap.md) when a gate passes.

| Gate | Platform | Automation |
| --- | --- | --- |
| [Linux AF_PACKET](#linux-af_packet) | Linux | Scripted, disposable network namespaces |
| [Linux AF_XDP](#linux-af_xdp) | Linux | Scripted, disposable network namespaces |
| [macOS BPF](#macos-bpf-manual-gate) | macOS | Manual, isolated test network |
| [Windows Npcap](#windows-npcap-manual-gate) | Windows | Manual, isolated test network |
| [UDP ICMP](#udp-icmp-manual-gate-macos-and-windows) | macOS, Windows | Manual, isolated test network |

## Linux AF_PACKET

Run `sudo bash tests/lab/linux-netns.sh` on Linux with `iproute2`, Python 3,
Go, and optionally `iptables`. The script builds nyxr, creates two disposable
network namespaces and a veth pair, and verifies automatic ARP resolution,
raw SYN open/closed/filtered classification, and IPv4 ARP/IPv6 NDP discovery,
plus UDP open/closed/filtered classification with an echo responder and a
closed port. The UDP gate checks that a raw ICMP listener opened in the source
namespace; packet fixtures separately check exact ICMP quote correlation.
It then runs a fixed 100-port closed scan. It records throughput, observed
reply loss, and source-veth TX/RX packet and drop deltas across that scan in
`tests/performance/latest-linux/`, alongside the command, environment and
per-probe results. Pass another directory as the script argument to save a
named run.
The filtered case needs `iptables`.
No external target or permanent network setting is used. A container needs
`CAP_NET_ADMIN` and `CAP_NET_RAW` in addition to root.

## Linux AF_XDP

On a privileged Linux host with the AF_PACKET gate's dependencies plus
`clang`, `bpftool`, GCC and BPF capabilities, run the same namespace lab with
`NYXR_LAB_XDP=1`. It attaches the Nyxr XDP program to the disposable source
veth, repeats the open/closed/filtered SYN classification and fixed 100-port
load scan through AF_XDP, records the per-probe results and veth counters, and
detaches the program during cleanup. The program attaches only to the
disposable source veth; its pins are removed during cleanup. Require all
classifications to match AF_PACKET and zero observed reply loss before
recording a performance comparison. A Linux cross-build alone does not pass
this gate. In a container where `ip netns exec` hides `/sys/fs/bpf`, mount
bpffs outside `/sys` and set `NYXR_LAB_BPFFS` to that mountpoint. Set
`NYXR_LAB_SKIP_NDP=1` only when verifying AF_XDP in an environment that lacks
working IPv6 neighbor discovery; record that the NDP gate was skipped.

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

## UDP ICMP manual gate (macOS and Windows)

On an isolated network, provide a UDP echo responder on one port, leave a
second port closed, and firewall-drop a third. Run `nyxr scan --profile custom
--protocols udp --ports OPEN,CLOSED,FILTERED --send-hex 010203 --workers 1
--timeout 500ms --json TARGET` with raw-socket privileges. Require `open`,
`closed`, and `open|filtered` respectively, and confirm the silent result does
not say `raw ICMP unavailable`. Repeat with IPv6. Save the JSON results and
the firewall rule used; synthetic tests cover exact quote checksums and
cross-probe rejection independently of socket-error delivery.
