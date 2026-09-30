# Deterministic Ethernet captures

`phase0.pcap` contains ten classic Ethernet PCAP records in fixed order:
IPv4 TCP, IPv4 UDP, IPv6 TCP, IPv6 UDP, ICMPv4, ICMPv6, VLAN-tagged IPv4 TCP,
ICMPv4 destination-unreachable with a quoted TCP header, a three-byte frame,
and a truncated IPv4 TCP frame. Addresses are documentation ranges; no live
capture or private traffic is included.

Regenerate from the repository root with `go run ./tests/pcaps/generate`.
`internal/packet/fixtures_test.go` checks every record, including rejection of
the malformed frames, and seeds the packet decoder and PCAP reader fuzzers.
