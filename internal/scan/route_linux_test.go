//go:build linux

package scan

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseIPv4Routes(t *testing.T) {
	input := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"eth0 00000000 0102000A 0003 0 0 100 00000000 0 0 0\n" +
		"eth0 0002000A 00000000 0001 0 0 10 00FFFFFF 0 0 0\n"
	routes, err := parseIPv4Routes(strings.NewReader(input), "eth0")
	if err != nil || len(routes) != 2 || routes[1].bits != 24 || routes[0].gateway.String() != "10.0.2.1" {
		t.Fatalf("routes: %+v, %v", routes, err)
	}
}

func TestParseIPv4RoutesAllDevices(t *testing.T) {
	input := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"wlan0 00000000 0101A8C0 0003 0 0 600 00000000 0 0 0\n" +
		"eth0 00000000 0102000A 0003 0 0 100 00000000 0 0 0\n" +
		"wlan0 0001A8C0 00000000 0001 0 0 600 00FFFFFF 0 0 0\n"
	routes, err := parseIPv4Routes(strings.NewReader(input), "")
	if err != nil || len(routes) != 3 || routes[0].device != "wlan0" || routes[1].device != "eth0" {
		t.Fatalf("routes: %+v, %v", routes, err)
	}
}

func TestParseIPv6Routes(t *testing.T) {
	table := strings.Join([]string{
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0",
		"20010db8000100000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0",
		"20010db8000900000000000000000000 30 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00200201 lo",
		"fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0",
		"ff000000000000000000000000000000 08 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0",
		"20010db8000200000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth1",
	}, "\n")
	routes, err := parseIPv6Routes(strings.NewReader(table), "eth0")
	if err != nil || len(routes) != 3 {
		t.Fatalf("routes: %+v %v", routes, err)
	}
	gateway := netip.MustParseAddr("fe80::1")
	for target, want := range map[string]netip.Addr{
		"2001:db8:1::20": netip.MustParseAddr("2001:db8:1::20"),
		"2001:db8:5::1":  gateway,
	} {
		route, ok := bestIPv6Route(routes, netip.MustParseAddr(target))
		hop := route.gateway
		if !hop.IsValid() {
			hop = netip.MustParseAddr(target)
		}
		if !ok || hop != want {
			t.Fatalf("%s via %v", target, route)
		}
	}
	all, err := parseIPv6Routes(strings.NewReader(table), "")
	if err != nil || len(all) != 4 {
		t.Fatalf("reject route kept or device filter wrong: %+v", all)
	}
	if empty, err := parseIPv6Routes(strings.NewReader(""), "eth0"); err != nil || len(empty) != 0 {
		t.Fatalf("empty table: %v %v", empty, err)
	}
}
