# Performance

nyxr publishes performance figures only with the workload, environment and raw
output that produced them. This page describes the benchmark harness and the
recorded baseline.

## Run the benchmark

```sh
make benchmark                                   # writes tests/performance/latest/
bash tests/performance/baseline.sh <directory>   # or choose the output directory
go tool pprof -top <directory>/cpu.pprof         # sampled CPU work
```

The script records the exact Go version and host details, runs three
one-second samples of each benchmark with `-benchmem`, and profiles the scan
workload.

| Benchmark | Workload |
| --- | --- |
| `BenchmarkDecodeTCP` | Decode one IPv4 TCP frame with a reused decoder |
| `BenchmarkDecodeFixture` | Decode the mixed [fixture](testing.md#packet-fixtures) frames with a reused decoder |
| Synthetic SYN scan | 100 IPv4 SYN probes against a fake responder, four decoder workers, 3 ms timeout, every tenth reply dropped |

## Recorded baseline

macOS arm64, 2026-09-30, Go 1.27.1 on an Apple M5 Max. Recorded with
`bash tests/performance/baseline.sh tests/performance/baseline-2026-09-30-macos-arm64`.

| Measurement | Result |
| --- | --- |
| TCP decode | 41.75–42.24 ns/op, 0 allocs/op |
| Mixed fixture decode | 46.57–50.67 ns/op, 0 allocs/op |
| Synthetic SYN scan | 3,678–3,759 probes/s at exactly 10% injected response loss |
| Synthetic scan allocations | 3.22 MB and 924–931 allocations per 100-probe run |
| CPU profile | 480 ms of CPU sampled over 3.81 s wall time |

Runtime waits dominate the profile because lost probes consume their full 3 ms
timeout.

Source files: [benchmarks](../../tests/performance/baseline-2026-09-30-macos-arm64/benchmarks.txt),
[environment](../../tests/performance/baseline-2026-09-30-macos-arm64/environment.txt),
[CPU profile](../../tests/performance/baseline-2026-09-30-macos-arm64/cpu.pprof).

### What these numbers do not show

- This baseline predates the asynchronous SYN engine.
- These are decoder and fake-responder figures. They do not measure NIC
  transmit or receive rate, or kernel drops.
- No packets-per-second claim for live scanning is established yet.

## Linux workload with interface counters

On a privileged Linux host, the namespace lab adds a live AF_PACKET workload:

```sh
sudo bash tests/lab/linux-netns.sh tests/performance/latest-linux
```

After its classification and discovery checks, the script scans 100 closed
ports with raw SYN, four workers and a 100 ms timeout. It saves the command,
environment, per-probe results, throughput, observed reply loss, and the
source veth's TX/RX packet and drop counter deltas. These are virtual Ethernet
counters, not physical adapter measurements.

This Linux result has not been recorded yet. Until it is, do not treat
synthetic loss or a missing counter as a measured NIC drop rate. See
[Runtime gates](runtime-gates.md) for this and the macOS and Windows gates.

## Optimization order

Optimize in this order, measuring before and after each step: parser reuse and
buffer ownership; packet templates; AF_PACKET batching; sharded RX/TX;
correlation and queue profiling. Evaluate AF_XDP or PF_RING only if measured
AF_PACKET results show a bottleneck these steps cannot remove. Publish the
workload, hardware, packet loss and CPU alongside any packets-per-second figure.
