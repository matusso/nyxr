package scan

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/tests/lab"
)

// Fixed 100-probe campaign: every tenth reply is lost. This is an engine
// baseline, not a claim about physical NIC throughput or kernel drops.
func BenchmarkSYNFakeResponder(b *testing.B) {
	ports := make([]uint16, 100)
	for i := range ports {
		ports[i] = uint16(20000 + i)
	}
	cfg := config.Config{Targets: []netip.Addr{netip.MustParseAddr("198.51.100.20")}, Ports: ports,
		TCP: true, TCPMode: "syn", Timeout: 3 * time.Millisecond, Workers: 4,
		NextHopMAC: net.HardwareAddr{6, 5, 4, 3, 2, 1}}
	b.ReportAllocs()
	start := time.Now()
	var sent, lost int
	for i := 0; i < b.N; i++ {
		fake := lab.NewSYNResponder("open", lab.Behavior{DropEvery: 10})
		var observations int
		err := runSYNWithIO(context.Background(), cfg, func(o Observation) error { observations++; return nil }, fake,
			net.HardwareAddr{1, 2, 3, 4, 5, 6}, netip.MustParseAddr("192.0.2.10"))
		if err != nil || observations != 100 {
			b.Fatalf("observations %d, error %v", observations, err)
		}
		_, n := fake.Counts()
		sent += n
		lost += int(fake.Stats().Dropped)
	}
	b.ReportMetric(float64(b.N*100)/time.Since(start).Seconds(), "probes/s")
	b.ReportMetric(float64(lost)/float64(sent)*100, "simulated-loss-%")
}
