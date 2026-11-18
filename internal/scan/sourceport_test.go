package scan

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/probe"
)

// A gateway that only answers peers on one source port is found by the probe
// that declares that port, after an earlier probe used an ephemeral socket.
func TestUDPProbeSourcePort(t *testing.T) {
	free, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	sport := uint16(free.LocalAddr().(*net.UDPAddr).Port)
	_ = free.Close()

	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	sources := make(chan int, 4)
	go func() {
		var buf [64]byte
		for {
			_, from, err := server.ReadFromUDP(buf[:])
			if err != nil {
				return
			}
			sources <- from.Port
			if from.Port == int(sport) {
				_, _ = server.WriteToUDP([]byte("ok"), from)
			}
		}
	}()
	probes := []probe.Probe{
		{Name: "ephemeral", Matcher: "any", Payload: []byte("a")},
		{Name: "pinned", Matcher: "any", Payload: []byte("b"), SourcePort: sport},
	}
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"},
		200*time.Millisecond, probes, 0, []byte("test-secret"), newProbeLimiter(0))
	if got.State != "open" || got.Probe != "pinned" {
		t.Fatalf("pinned source port not used: %+v", got)
	}
	if first, second := <-sources, <-sources; first == int(sport) || second != int(sport) {
		t.Fatalf("source ports %d then %d, want ephemeral then %d", first, second, sport)
	}
}
