package scan

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/probe"
	"github.com/matusso/nyxr/tests/lab"
)

func TestUDPResponderFaults(t *testing.T) {
	for _, tc := range []struct {
		name       string
		behavior   lab.Behavior
		retries    int
		want       string
		confidence int
		sent       int
	}{
		{"latency-duplicates", lab.Behavior{Latency: 2 * time.Millisecond, Duplicates: 1}, 0, "open", 100, 2},
		{"first-lost", lab.Behavior{DropFirst: 1}, 1, "open", 100, 1},
		{"protocol-mismatch", lab.Behavior{ProtocolMismatch: true}, 0, "open", 75, 1},
		{"all-lost", lab.Behavior{DropEvery: 1}, 1, "open|filtered", 30, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, err := lab.NewUDPResponder(tc.behavior)
			if err != nil {
				t.Skipf("loopback unavailable: %v", err)
			}
			p := probe.Probe{Name: "dns", Payload: make([]byte, 12), Matcher: "dns", Retries: tc.retries}
			got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: server.Port(), transport: "udp"}, 20*time.Millisecond, []probe.Probe{p}, 0, []byte("lab-secret"), newProbeLimiter(0))
			// The probe returns on the first reply; close first so the
			// responder finishes its duplicate burst before counting.
			server.Close()
			if got.State != tc.want || got.Confidence != tc.confidence {
				t.Fatalf("observation %+v", got)
			}
			_, sent := server.Counts()
			if sent != tc.sent {
				t.Fatalf("sent %d replies, want %d", sent, tc.sent)
			}
		})
	}
}

func TestSYNResponderFaults(t *testing.T) {
	for _, tc := range []struct {
		name, mode, state string
		behavior          lab.Behavior
		targets           int
		// Cases that need a reply get a generous timeout: the reply crosses
		// several goroutines and loaded CI runners can exceed a few ms.
		// Cases that expect a timeout keep it short.
		timeout time.Duration
	}{
		{"open-duplicate", "open", "open", lab.Behavior{Duplicates: 1}, 1, 2 * time.Second},
		{"closed", "closed", "closed", lab.Behavior{Latency: time.Millisecond}, 1, 2 * time.Second},
		{"mismatch", "open", "filtered", lab.Behavior{ProtocolMismatch: true}, 1, 15 * time.Millisecond},
		{"lost", "open", "filtered", lab.Behavior{DropEvery: 1}, 1, 15 * time.Millisecond},
		{"icmp-limited", "icmp", "filtered", lab.Behavior{ICMPLimit: 1}, 2, 500 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := lab.NewSYNResponder(tc.mode, tc.behavior)
			targets := make([]netip.Addr, tc.targets)
			for i := range targets {
				targets[i] = netip.MustParseAddr("198.51.100.20")
			}
			cfg := config.Config{Targets: targets, Ports: []uint16{443}, TCP: true, TCPMode: "syn", Timeout: tc.timeout, Workers: 1, NextHopMAC: net.HardwareAddr{6, 5, 4, 3, 2, 1}}
			var got []Observation
			err := runSYNWithIO(context.Background(), cfg, func(o Observation) error { got = append(got, o); return nil }, fake, net.HardwareAddr{1, 2, 3, 4, 5, 6}, netip.MustParseAddr("192.0.2.10"))
			if err != nil || len(got) != tc.targets {
				t.Fatalf("observations %+v, error %v", got, err)
			}
			if got[0].State != tc.state {
				t.Fatalf("first observation %+v", got[0])
			}
			if tc.name == "icmp-limited" && (got[0].Confidence != 95 || got[1].Confidence != 60) {
				t.Fatalf("rate-limited ICMP: %+v", got)
			}
		})
	}
}
