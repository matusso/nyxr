# HORIZON laboratory

`hz-001.yaml` is the unprivileged synthetic fixture. See
`docs/horizon/README.md` for commands, analysis and limitations.

## Optional live Linux topology

Requires root on an isolated lab host with `ip`, `tc`, Python and `tcpdump`.
Do not reuse existing interfaces/namespaces with these names. The procedure
is prepared for validation; **it was not run on the macOS development host**.
Live ground-truth acceptance remains GitHub issue #66.

```sh
sudo ip netns add hz-target
sudo ip link add hz-host type veth peer name hz-peer
sudo ip link set hz-peer netns hz-target
sudo ip link set hz-host address 02:00:00:00:00:01
sudo ip addr add 10.77.0.1/24 dev hz-host
sudo ip link set hz-host up
sudo ip netns exec hz-target ip link set hz-peer address 02:00:00:00:00:02
sudo ip netns exec hz-target ip addr add 10.77.0.2/24 dev hz-peer
sudo ip netns exec hz-target ip link set hz-peer up
sudo ip netns exec hz-target ip link set lo up

# Separate terminals, intentionally within the lab:
sudo ip netns exec hz-target python3 -m http.server 443 --bind 10.77.0.2
sudo tcpdump -i hz-host -s 0 -w horizon-ground-truth.pcap 'host 10.77.0.2 and tcp port 443'
sudo ./nyxr-packetd --socket /tmp/nyxr-horizon.sock --interface hz-host
```

Copy `hz-001.yaml` to `lab-local.yaml`; use target `10.77.0.2`, both receive
windows at least 800 ms, washout 300 ms and duration 90 s. Keep the 48-packet
cap and 3 packets/s. Follow the operator guide with an explicit `/32` allowlist.

Repeat with new evidence files under controlled response-path loss/jitter:

```sh
sudo ip netns exec hz-target tc qdisc add dev hz-peer root netem delay 20ms 5ms loss 5%
# Repeat HZ-001, preserve capture/evidence, then remove the injected impairment:
sudo ip netns exec hz-target tc qdisc del dev hz-peer root
```

Record kernel version, TCP SACK settings, topology, seeds, raw trial/capture
evidence and drop counters. Repeat null controls and isolated baseline probes
before claiming real false-positive rates. The sender kernel may independently
send RSTs, which are outside the runner's budgeted cleanup count.

Stop Python, packetd and tcpdump before removing the lab resources:

```sh
sudo ip link del hz-host
sudo ip netns del hz-target
```

Correlated Ethernet frames are currently stored inline in versioned JSON.
PCAPNG indexing, broad ground-truth coverage and detailed retransmission/ICMP
models remain roadmap work.
