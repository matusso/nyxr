//go:build darwin

package scan

import (
	"net/netip"
	"strings"
	"testing"
)

func TestDarwinRouteSnapshot(t *testing.T) {
	text := `Routing tables
Internet:
Destination Gateway Flags Netif Expire
default 192.168.1.1 UGScg en0
default link#24 UCSIg utun5
100.64/10 link#24 UCS utun5
192.168.1 link#15 UCS en0
192.168.1.1 02:00:00:00:00:01 UHLWI en0
`
	routes, err := parseDarwinRoutes(strings.NewReader(text))
	if err != nil || len(routes) != 5 {
		t.Fatalf("routes=%v err=%v", routes, err)
	}
	for _, tc := range []struct {
		value string
		bits  int
	}{{"192.168.1", 24}, {"100.64/10", 10}, {"192.168.1.1", 32}} {
		p, ok := darwinDestination(tc.value)
		if !ok || p.Bits() != tc.bits {
			t.Fatalf("%s: %v %v", tc.value, p, ok)
		}
	}
	if !routes[3].prefix.Contains(netip.MustParseAddr("192.168.1.200")) || routes[3].hop.IsValid() {
		t.Fatalf("on-link route: %+v", routes[3])
	}
}

func TestDarwinEgressPrefersUnscopedRoutes(t *testing.T) {
	text := `Destination Gateway Flags Netif Expire
default 172.16.1.112 UGScg utun9
default 192.168.1.1 UGScIg en0
default link#31 UCSIg utun10
100.64/10 link#31 UCS utun10
192.168.1 link#16 UCS en0
192.168.1.1/32 link#16 UCS en0
10.9.0/24 link#16 UCSI en0
`
	routes, err := parseDarwinRoutes(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]string{
		"1.1.1.1": "utun9", "192.168.1.20": "en0", "100.100.1.1": "utun10", "10.9.0.5": "utun9",
	} {
		if got, err := darwinEgress(routes, netip.MustParseAddr(target)); err != nil || got != want {
			t.Fatalf("%s: got %q err=%v, want %s", target, got, err, want)
		}
	}
}
