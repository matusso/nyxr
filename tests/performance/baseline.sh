#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
out=${1:-tests/performance/latest}
mkdir -p "$out"
{
  date -u '+UTC %Y-%m-%dT%H:%M:%SZ'
  go version
  go env GOOS GOARCH GOMAXPROCS CGO_ENABLED
  uname -a
  if command -v sysctl >/dev/null; then sysctl -n machdep.cpu.brand_string 2>/dev/null || true; fi
  if [[ -r /proc/cpuinfo ]]; then rg -m 1 'model name' /proc/cpuinfo || true; fi
} >"$out/environment.txt"
go test -run '^$' -bench 'Benchmark(DecodeTCP|DecodeFixture)$' \
  -benchmem -benchtime=1s -count=3 ./internal/packet | tee "$out/benchmarks.txt"
go test -run '^$' -bench '^BenchmarkSYNFakeResponder$' \
  -benchmem -benchtime=1s -count=3 -cpuprofile="$out/cpu.pprof" \
  ./internal/scan | tee -a "$out/benchmarks.txt"
echo "Saved environment, benchmark results, and CPU profile in $out"
echo "Run sudo bash tests/lab/linux-netns.sh on Linux for real NIC packet/drop counters."
