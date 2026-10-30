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

func TestDarwinIPv6RouteSnapshot(t *testing.T) {
	table := `Routing tables

Internet6:
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::1%en0                             UGcg                  en0
default                                 fe80::%utun0                            UGcIg               utun0
::1                                     ::1                                     UHL                   lo0
2001:db8:1::/64                         link#15                                 UC                    en0
2001:db8:1::10                          a4:83:e7:0:0:1                          UHLWI                 en0
2001:db8:7::/48                         2001:db8:1::fe                          UGc                   en0
fe80::%en0/64                           link#15                                 UCI                   en0
ff00::/8                                link#15                                 UmCI                  en0
`
	routes, err := parseDarwinRoutes6(strings.NewReader(table))
	if err != nil || len(routes) != 5 {
		t.Fatalf("routes: %+v %v", routes, err)
	}
	next := darwinNextHop(routes, "en0", "IPv6")
	for target, want := range map[string]string{
		"2001:db8:1::20": "2001:db8:1::20",
		"2001:db8:1::10": "2001:db8:1::10",
		"2001:db8:7::5":  "2001:db8:1::fe",
		"2001:db8:9::1":  "fe80::1",
	} {
		hop, err := next(netip.MustParseAddr(target))
		if err != nil || hop != netip.MustParseAddr(want) || hop.Zone() != "" {
			t.Fatalf("%s via %v %v", target, hop, err)
		}
	}
	if egress, err := darwinEgress(routes, netip.MustParseAddr("2001:db8:9::1")); err != nil || egress != "en0" {
		t.Fatalf("egress %q %v", egress, err)
	}
	only, err := parseDarwinRoutes6(strings.NewReader("fe80::%en0/64 link#15 UCI en0\n"))
	if err != nil || len(only) != 0 {
		t.Fatalf("link-local-only table: %+v %v", only, err)
	}
	if _, err := darwinNextHop(only, "en0", "IPv6")(netip.MustParseAddr("2001:db8::1")); err == nil {
		t.Fatal("routed a global target through an empty table")
	}
}
