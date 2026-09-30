# Phase 0 performance baseline

Run `make benchmark` from the repository root. It saves the exact Go version,
host details, three benchmark samples, and a CPU profile in
`tests/performance/latest/`. Set a different output path with
`bash tests/performance/baseline.sh <directory>`. The fixed synthetic scan
uses 100 IPv4 SYN probes, four workers, a 3 ms timeout, and drops every tenth
reply. `BenchmarkDecodeTCP` and `BenchmarkDecodeFixture` reuse one decoder.
Run `go tool pprof -top <directory>/cpu.pprof` for sampled CPU work.

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
rate or kernel drops. On Linux, `sudo bash tests/lab/linux-netns.sh` provides
the fixed 103-probe live AF_PACKET workload and prints veth packet/drop
counters before and after. The live NIC baseline remains unrecorded until that
gate runs on a privileged Linux host. The macOS and Windows live gates are in
[the lab instructions](../lab/README.md).
