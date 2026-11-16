package config

import (
	"net/netip"
	"slices"
	"testing"
)

func TestScopeTargetsAndPortsRoundTrip(t *testing.T) {
	cfg := Config{Targets: []netip.Addr{netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("192.0.2.5"),
		netip.MustParseAddr("192.0.2.6"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("198.51.100.1")}}
	got := cfg.ScopeTargets()
	if want := []string{"192.0.2.5-192.0.2.7", "198.51.100.1", "2001:db8::1"}; !slices.Equal(got, want) {
		t.Fatalf("targets: %v", got)
	}
	scope, err := ParseScope(got)
	if err != nil || !scope.Contains(netip.MustParseAddr("192.0.2.6")) || scope.Contains(netip.MustParseAddr("192.0.2.8")) {
		t.Fatalf("scope: %v", err)
	}
	ports := []uint16{443, 80, 8002, 8000, 8001, 80}
	text := FormatPorts(ports)
	back, err := ParsePorts(text)
	if text != "80,443,8000-8002" || err != nil || len(back) != 5 {
		t.Fatalf("ports: %q %v %v", text, back, err)
	}
}
