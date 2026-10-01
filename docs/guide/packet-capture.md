# Packet capture and analysis

nyxr can record the packets behind a scan as pcapng evidence, summarize any
capture into hosts and ports, and browse captures packet by packet in the
terminal.

- [Capture scan evidence](#capture-scan-evidence)
- [Summarize a capture](#summarize-a-capture)
- [Browse packets in the terminal](#browse-packets-in-the-terminal)
- [Sniff an interface](#sniff-an-interface)

## Capture scan evidence

```sh
sudo nyxr scan --profile deep --interface eth0 --pcapng scan.pcapng 192.0.2.10
```

`--pcapng FILE` (with `--interface`) opens a separate capture handle and records
every frame to or from a target, including router ICMP errors that quote a
probe.

- **No impact on scan speed.** A reader goroutine copies matching frames into
  a bounded queue, and a separate writer goroutine encodes and writes them. Scan
  receive workers never wait on the file.
- **Annotated frames.** Each frame carries direction flags, a packet ID and a
  one-line summary as a pcapng comment.
- **Linked to results.** At the end of the scan, `packet-evidence` records link
  each target, transport and port to its packet IDs. ICMP errors with a
  complete quoted UDP header are indexed under the UDP flow they refer to.
- **Nothing lost silently.** Queue overflow, the size budget
  (`--pcapng-max-mb`, default 1024) and backend drops are counted in the scan
  summary.

Timestamps are taken when user space receives the frame.

Through the API, `pcapng` must be a bare `*.pcapng` file name; the server
places it in its `--evidence-dir`, and the web UI offers it for download.

## Summarize a capture

`nyxr decode` reads pcap and pcapng files (Ethernet link type) and prints the
hosts and ports that the replies prove open:

```sh
nyxr decode capture.pcapng
```

```text
phase0.pcap
  packets    10 frames • 8 decoded • 2 skipped
  protocols  icmp 2 • icmp6 1 • tcp 3 • udp 2
  hosts      2 responding
  ports      2 open • 1 filtered

192.0.2.1  1 open
    PORT     STATE  SERVICE  REASON
    443/tcp  open   https    syn-ack

192.0.2.2  1 filtered
    PORT       STATE     SERVICE  REASON
    50000/tcp  filtered  -        icmp-unreach
```

| Flag | Effect |
| --- | --- |
| `--all` | Also list closed ports (RST to a SYN, ICMP port unreachable) and filtered ports |
| `--packets` | List every decoded packet |
| `--json` | One JSON object per decoded packet |
| `--tui` | Open the interactive browser |

Open evidence comes from SYN/ACKs and UDP responses.

## Browse packets in the terminal

```sh
nyxr decode --tui capture.pcapng
```

![nyxr decode --tui showing a packet list, decoded layers and a hex dump](../images/decode-tui.png)

The browser has three panes:

1. **Packet list** with time, addresses, protocol, length and a summary.
2. **Layers** of the selected packet: Frame, Ethernet, VLAN, ARP, IPv4/IPv6,
   TCP with its options, UDP, ICMP/ICMPv6 (including the quoted header of
   errors), NDP and DNS. Every field shows its value and a short note on what
   it means: a TTL hints at the sender's OS and hop distance, TCP flags say
   whether a reply means open or closed, an ICMP code tells closed from
   filtered.
3. **Hex dump**, with the bytes of the selected field highlighted.

On nyxr's own pcapng files the browser also shows each frame's direction,
evidence packet ID and comment.

| Key | Action |
| --- | --- |
| `/` | Filter by words that must all match: address, port, protocol, flag. `!word` excludes |
| `Tab` | Switch panes |
| `Enter` | Fold or unfold a layer |
| `n` / `p` | Next or previous packet |
| `x` | Toggle the hex dump |
| `?` | List every key |
| `q` | Quit |

`--no-color` or `NO_COLOR` keeps the browser monochrome, with reverse video for
the selection.

## Sniff an interface

`nyxr sniff` captures live frames and prints them decoded:

```sh
sudo nyxr sniff --interface eth0 --count 100 --timeout 30s
```

| Flag | Default | Effect |
| --- | --- | --- |
| `--interface` | | Ethernet interface to capture on |
| `--count` | 100 | Stop after this many decoded packets |
| `--timeout` | 10s | Stop after this long |

It needs the same privileges as [raw packet scanning](raw-packets.md#platform-requirements).
To watch live traffic in the browser instead, use the
[packets page](web-ui-and-api.md#live-packets-and-frame-editing) of the web UI.
