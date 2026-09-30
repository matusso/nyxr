# Phase 0 performance baseline

Run `make benchmark` from the repository root. It saves the exact Go version,
host details, three benchmark samples, and a CPU profile in
`tests/performance/latest/`. Set a different output path with
`bash tests/performance/baseline.sh <directory>`. The fixed synthetic scan
uses 100 IPv4 SYN probes, four workers, a 3 ms timeout, and drops every tenth
reply. `BenchmarkDecodeTCP` and `BenchmarkDecodeFixture` reuse one decoder.
Run `go tool pprof -top <directory>/cpu.pprof` for sampled CPU work.

The recorded run used `bash tests/performance/baseline.sh
tests/performance/baseline-2026-09-30-macos-arm64`. The script runs three
one-second samples of each decoder benchmark and the fixed synthetic scan
with `-benchmem`; it profiles the scan. The linked environment and raw Go
output are the source for the figures below.

Recorded baseline: [macOS arm64, 2026-09-30](baseline-2026-09-30-macos-arm64/benchmarks.txt)
with [environment](baseline-2026-09-30-macos-arm64/environment.txt) and
[CPU profile](baseline-2026-09-30-macos-arm64/cpu.pprof). Go 1.27.1 on an
Apple M5 Max yielded 41.75–42.24 ns per TCP decode (0 allocs/op),
46.57–50.67 ns per mixed fixture decode (0 allocs/op), and 3,678–3,759
synthetic SYN probes/s at exactly 10% injected response loss. The 100-probe
campaign allocated 3.22 MB and 924–931 allocations per run. The profile
sampled 480 ms of CPU over 3.81 s wall time; runtime waits dominated because
lost probes consume their full 3 ms timeout.

These are decoder and fake-responder numbers; they do not measure NIC TX/RX
rate or kernel drops. On a privileged Linux host, run
`sudo bash tests/lab/linux-netns.sh tests/performance/latest-linux`. After
classification and discovery checks, the script runs a fixed 100 closed-port
AF_PACKET SYN workload with four workers and a 100 ms timeout. It saves the
command, environment, per-probe results, throughput, observed reply loss, and
source-veth TX/RX packet and drop counter deltas for that workload. These are
virtual Ethernet interface counters, not physical adapter measurements. The
Linux result remains unrecorded until this gate runs; do not treat synthetic
loss or a missing counter result as a measured NIC drop rate. The macOS and
Windows live gates are in
[the lab instructions](../lab/README.md).
