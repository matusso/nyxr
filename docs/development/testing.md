# Testing

nyxr is tested in layers, from pure unit tests that run anywhere to privileged
lab gates that need real interfaces. A feature is only described as working on
a platform once the matching layer has passed there.

| Layer | Runs | Command |
| --- | --- | --- |
| Unit and loopback tests | Everywhere, unprivileged; in CI | `make check` |
| Packet fixtures | Everywhere; in CI | part of `make check` |
| Fuzzing | Short campaigns in CI; longer locally | `make fuzz` |
| Benchmarks | Locally, on a recorded environment | `make benchmark` |
| Runtime gates | Privileged hosts with real or virtual interfaces | [Runtime gates](runtime-gates.md) |

## Unit and loopback tests

```sh
make check   # go test ./... and go vet ./...
```

The suite covers target and port parsing, packet decoding, pcap and pcapng
reading, probe definitions and matchers, service parsers, storage migrations
and queries, and the API. Loopback tests run real TCP and UDP exchanges,
including UDP retries and late responses. One test runs the same scan through
`nyxr scan` and the API and requires identical observations apart from IDs and
timings.

Fake UDP and SYN responders inject latency, loss, duplicate replies, ICMP rate
limiting and protocol mismatches, so classification can be tested without a
network.

## Packet fixtures

`tests/pcaps/phase0.pcap` contains ten classic Ethernet PCAP records in fixed
order:

1. IPv4 TCP
2. IPv4 UDP
3. IPv6 TCP
4. IPv6 UDP
5. ICMPv4
6. ICMPv6
7. VLAN-tagged IPv4 TCP
8. ICMPv4 destination unreachable with a quoted TCP header
9. A three-byte frame
10. A truncated IPv4 TCP frame

Addresses are documentation ranges; the file contains no live capture or
private traffic. `internal/packet/fixtures_test.go` checks every record,
including rejection of the two malformed frames, and seeds the packet decoder
and PCAP reader fuzzers.

Regenerate the file from the repository root:

```sh
go run ./tests/pcaps/generate
```

Protocol probes (UDP matchers, BACnet, Modbus, EtherNet/IP, database
handshakes) have their own byte-level fixtures next to their tests.

## Fuzzing

```sh
make fuzz
```

| Target | Package |
| --- | --- |
| `FuzzDecoder` | `internal/packet` |
| `FuzzTCPStackOptions` | `internal/stack` (native option parsing and classification) |
| `FuzzPCAPReader` | `internal/packet` |
| `FuzzDefinitionAndMatcher` | `internal/probe` |
| `FuzzResponseParsers` | `internal/service` |
| `FuzzParse` | `internal/nmapdb` |

`make fuzz` runs each target for five seconds. For a longer campaign, run one
target directly:

```sh
go test -run '^$' -fuzz '^FuzzDecoder$' -fuzztime=10m ./internal/packet
```

## Benchmarks and runtime gates

- [Performance](performance.md) describes the benchmark workload and the
  recorded baseline.
- [Runtime gates](runtime-gates.md) describes the privileged Linux namespace
  lab and the manual macOS and Windows gates.
