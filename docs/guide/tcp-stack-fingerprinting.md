# TCP/IP stack fingerprinting

Use `--fingerprint` with raw IPv4 or IPv6 SYN scanning to collect header evidence
alongside service identification:

```sh
sudo nyxr scan --tcp-mode syn --interface eth0 --protocols tcp \
  --ports 22,80,443 --fingerprint --service --json 192.0.2.10
```

API and YAML requests use `fingerprint: true` with `tcp_mode: syn`.
[Raw SYN privileges and interface settings](raw-packets.md) apply, including
support through `nyxr-packetd`. Connect scans and `ot-safe` retain their existing
application/device fingerprinting; they do not expose TCP header evidence.
IPv6 targets need no extra options; see [IPv6 raw SYN](raw-packets.md#ipv6-raw-syn).

## Collection

The fixed `nyxr-syn-v1` probe offers MSS 1460, SACK, timestamps and window
scale 7, and requests ECN with ECE+CWR. Its timestamp carries the sequence
token. ECE without CWR in a SYN/ACK records negotiated ECN, following
[RFC 3168](https://www.rfc-editor.org/rfc/rfc3168.html).
Ordinary discovery keeps its original option-free SYN.

IPv6 targets get the `nyxr-syn6-v1` probe: the same options, order, ECN
request and token, with MSS 1440 (a 1500-byte link minus the 40-byte IPv6
header) and hop limit 64. IPv6 has no DF bit or IP ID, so nyxr sends neither.

Replies must pass discovery's target, address, port and HMAC-derived ACK
token checks. Nyxr retains at most eight SYN/ACK or RST/ACK samples per probe
within the original `--timeout`. It sends one SYN per port, with no extra
fingerprint probes. Results wait until that deadline; cancellation preserves
validated replies already collected and sets `collection_complete` to false.
Silent ports and ICMP errors carry no TCP stack claim. RST without ACK cannot
validate the SYN token and is ignored.

Samples preserve window, observed TTL (IPv6 hop limit) and estimated initial
TTL, `ip_version`, IPv4 DF/IP ID, raw options and ordering, MSS, window scale, SACK, timestamp value/echo,
all eight TCP flag bits, sequence/ACK, ECN and receive time. Receive times are
batch arrival estimates, not hardware timestamps. Multiple samples from one
probe describe IP ID behavior as zero, constant, increasing (with wraparound),
varying, or insufficient samples. IPv6 samples omit the `df` and `ip_id`
fields entirely and report IP ID behavior as `not-applicable`; they are never
filled with zero or guessed values. Repeat intervals are labelled
`duplicate-or-retransmitted-syn-ack`: capture duplicates cannot prove real
retransmission. Resets retain observed ACK/window/options behavior.

Unknown and semantically malformed options remain evidence. Structurally
truncated and fragmented packets are rejected by the decoder. The existing
16,384 outstanding-probe limit, bounded queues and eight-sample limit bound
memory. `truncated` means further validated samples were not retained.

## Native classification and combined evidence

Rules combine option ordering, estimated initial TTL, and validated
MSS/SACK/window scaling. Current hypotheses are Linux (70%), Windows (65%),
and the intentionally ambiguous BSD/macOS family (60%). Confidence is an
engineering estimate, not a calibrated probability or OS version detection.
TTL alone, generic MSS replies and resets never identify an OS. IPv6 replies
use the same rules with hop limit in place of TTL; the family-level rules have
not been calibrated separately for IPv6. Mixed
signatures and truncated collections remain unknown. The Linux ordering rule
is consistent with the option writer in the
[Linux TCP implementation](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_output.c).
Rules are Nyxr-native; no third-party fingerprint database is imported.

`nx_tcp_v1_…` (IPv4) and `nx_tcp6_v1_…` (IPv6) signatures hash response
type, IP version, estimated initial TTL, DF (IPv4 only), window, flags and
options. The prefix and `probe_profile` keep the two families apart, because
the probes differ (MSS) and replies cannot be compared across them. They exclude hop distance, IP ID,
sequence/ACK, receive times and timestamp counters. Unknown option bytes
remain part of the signature, allowing unknown stacks to retain comparable
observations.

Device synthesis combines a stack hypothesis with matched protocol evidence
and existing signals. `device.os_family` and `device.os_confidence` stay
separate from device-class confidence. Different stack families across ports,
or disagreement with an explicit application OS claim, produce
`device.os_conflict`. HTTP headers and TLS certificates never upgrade an OS
hypothesis into a confirmed OS.

Stored asset profiles retain `os_family` claims at their stack confidence.
One consistent family supplies the profile OS only when no application OS
claim exists. Detailed application OS claims take precedence; conflicting
families remain in the claims list. TCP signatures never merge assets.

JSON, history and API port results retain the full `tcp_stack` object. Text
output adds a family/confidence or an unknown signature. The web UI's
**TCP/IP stack evidence** disclosure shows samples, reasons and behavior.
Enable [pcapng capture](packet-capture.md) separately for full packet bytes.

## Limits and validation

SYN cookies, tuning, option negotiation and intermediaries can change headers.
A hypothesis describes the responding stack; it cannot prove the OS behind a
proxy. Kernel versions, specific embedded stacks, printer models, intermediary
roles (load balancer, firewall, NAT or VPN gateway), cross-flow IP ID analysis
and exhaustive retransmission schedules need more native rules and controlled
probes. Host TCP stacks often reset unsolicited SYN/ACKs, so no repeat may be
observable. Short timeouts do not prove retransmission is unsupported.

Fixtures cover IPv4 and IPv6 checksums, owned option bytes, IPv6 extension
headers and ICMPv6 quotes, known/unknown rules, malformed
options, token/tuple rejection, sample bounds, repeats, resets, cancellation,
conflicts, storage and pipeline propagation. Live fingerprint validation and
confidence calibration on representative devices remain open; backend runtime
gates alone do not establish fingerprint accuracy. The Linux namespace gate
checks that live IPv6 replies carry `nyxr-syn6-v1` evidence without DF or IP
ID; it does not validate any family hypothesis.
