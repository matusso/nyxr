//go:build linux

package scan

import (
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
