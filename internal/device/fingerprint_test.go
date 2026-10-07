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

func TestStackAndApplicationEvidenceRemainSeparate(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.7")
	c := New()
	port := observe.Observation{Kind: observe.KindPort, Target: addr, Transport: "tcp", Port: 443, State: "open",
		TCPStack: &observe.TCPStack{Status: observe.FingerprintMatched, Signature: "native", Candidates: []observe.StackCandidate{{Family: "Linux", Confidence: 70}}}}
	c.Add(port)
	if len(c.Results()) != 0 {
		t.Fatal("stack alone invented a device class")
	}
	c.Add(observe.Observation{Kind: observe.KindService, Target: addr, Transport: "tcp", Port: 443, State: "open", Service: "http", Fingerprint: observe.FingerprintMatched})
	got := c.Results()
	if len(got) != 1 || got[0].Attributes["device.os_family"] != "Linux" || got[0].Attributes["device.os_confidence"] != "70" || got[0].Confidence != 65 {
		t.Fatalf("combined evidence inflated OS certainty: %+v", got)
	}
	c.Add(observe.Observation{Kind: observe.KindService, Target: addr, Transport: "tcp", Port: 445, Service: "smb", Fingerprint: observe.FingerprintMatched, Attributes: map[string]string{"smb.os_version": "10.0"}})
	got = c.Results()
	if got[0].Attributes["device.os_family"] != "" || got[0].Attributes["device.os_conflict"] == "" {
		t.Fatalf("conflicting OS evidence lost: %+v", got)
	}
	c = New()
	c.Add(port)
	port.Port = 80
	port.TCPStack = &observe.TCPStack{Status: observe.FingerprintMatched, Candidates: []observe.StackCandidate{{Family: "Windows", Confidence: 65}}}
	c.Add(port)
	c.Add(observe.Observation{Kind: observe.KindService, Target: addr, Transport: "tcp", Port: 443, Service: "http", Fingerprint: observe.FingerprintMatched})
	got = c.Results()
	if got[0].Attributes["device.os_family"] != "" || got[0].Attributes["device.os_conflict"] == "" {
		t.Fatalf("cross-port conflict lost: %+v", got)
	}
}

func TestAmbiguousBSDFamilyAcceptsApplicationAliases(t *testing.T) {
	for _, name := range []string{"FreeBSD", "OpenBSD", "Apple Mac OS X", "macOS", "Darwin"} {
		if !compatibleOS(name, "BSD/macOS") {
			t.Fatalf("compatible family rejected: %s", name)
		}
	}
	if compatibleOS("Microsoft Windows", "BSD/macOS") {
		t.Fatal("conflicting family accepted")
	}
}
