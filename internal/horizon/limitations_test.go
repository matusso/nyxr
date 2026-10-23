package horizon

import (
	"context"
	"testing"

	"github.com/matusso/nyxr/internal/packetio"
)

// Documented capture limitations (docs/horizon/operations.md) as tests, so a
// behavior change is a deliberate decision rather than a silent drift.

// A reply whose TCP checksum does not verify is never correlated. On Linux
// veth with TX checksum offload, locally generated SYN/ACKs carry partial
// checksums in the capture and therefore look like silence (no-response).
func TestUnverifiableChecksumReplyIsNotCorrelated(t *testing.T) {
	t.Parallel()
	for _, ipv6 := range []bool{false, true} {
		sent := fixtureProbe(t, ipv6)
		reply := fixtureReply(t, sent, false)
		if _, ok := correlateRich(reply, sent); !ok {
			t.Fatal("valid fixture reply not correlated")
		}
		ipHeader := 20
		if ipv6 {
			ipHeader = 40
		}
		partial := append([]byte(nil), reply...)
		sum := 14 + ipHeader + 16 // TCP checksum field
		partial[sum], partial[sum+1] = 0, 0x1c
		if _, ok := correlateRich(partial, sent); ok {
			t.Fatalf("ipv6=%v: reply with an unverifiable checksum was correlated", ipv6)
		}
	}
}

// resettingIO reports a capture drop counter that goes backwards, as some
// backends do when their statistics restart.
type resettingIO struct {
	packetio.PacketIO
	calls int
}

func (r *resettingIO) Stats() packetio.Stats {
	r.calls++
	if r.calls == 1 {
		return packetio.Stats{Dropped: 100}
	}
	return packetio.Stats{}
}

func TestCaptureStatisticsResetLeavesRunUnresolved(t *testing.T) {
	t.Parallel()
	sim, _ := NewSimulator("sack")
	defer sim.Close()
	e := loadExperiment(t, "../../lab/horizon/hz-001.yaml")
	r, err := Run(context.Background(), e, testPolicy(), testLink(), &resettingIO{PacketIO: sim})
	if err != nil {
		t.Fatal(err)
	}
	for _, trial := range r.Trials {
		if !hasFlag(trial.QualityFlags, "capture-stats-reset") {
			t.Fatal("trial missing capture-stats-reset")
		}
	}
	if r.Comparison.Status != "unresolved" {
		t.Fatalf("drop accounting unknown but comparison %s", r.Comparison.Status)
	}
	roundTrip(t, r)
}
