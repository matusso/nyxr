package device

import (
	"net/netip"
	"testing"

	"github.com/matusso/nyxr/internal/observe"
)

func TestIndependentDeviceSignals(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.7")
	c := New()
	c.Add(observe.Observation{Kind: observe.KindPort, Target: addr, Transport: "tcp", Port: 502, State: "open"})
	if got := c.Results(); len(got) != 0 {
		t.Fatalf("port-only claim: %+v", got)
	}
	c.Add(observe.Observation{Kind: observe.KindService, Target: addr, Transport: "tcp", Port: 502,
		Service: "modbus", Fingerprint: observe.FingerprintMatched, Reason: "validated identity"})
	if got := c.Results(); len(got) != 0 {
		t.Fatalf("same-port claim: %+v", got)
	}
	c.Add(observe.Observation{Kind: observe.KindPort, Target: addr, Transport: "tcp", Port: 44818, State: "open"})
	got := c.Results()
	if len(got) != 1 || got[0].Attributes["device.class"] != "industrial device" || len(got[0].Signals) != 2 || got[0].Confidence >= 90 {
		t.Fatalf("weak corroboration: %+v", got)
	}
	c.Add(observe.Observation{Kind: observe.KindService, Target: addr, Transport: "tcp", Port: 44818,
		Service: "ethernetip", Fingerprint: observe.FingerprintMatched, Reason: "validated identity"})
	got = c.Results()
	if len(got) != 1 || got[0].Confidence != 90 {
		t.Fatalf("two protocol identities: %+v", got)
	}
}
