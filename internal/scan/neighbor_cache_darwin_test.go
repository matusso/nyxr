//go:build darwin

package scan

import (
	"net/netip"
	"testing"
)

func TestParseDarwinARP(t *testing.T) {
	hop := netip.MustParseAddr("192.168.1.1")
	for _, tc := range []struct {
		name, line, device string
		want               bool
	}{
		{"valid", "? (192.168.1.1) at 02:2a:6f:f6:62:9d on en0 ifscope [ethernet]", "en0", true},
		{"wrong interface", "? (192.168.1.1) at 02:2a:6f:f6:62:9d on en1 ifscope [ethernet]", "en0", false},
		{"wrong IP", "? (192.168.1.2) at 02:2a:6f:f6:62:9d on en0 ifscope [ethernet]", "en0", false},
		{"incomplete", "? (192.168.1.1) at (incomplete) on en0 ifscope [ethernet]", "en0", false},
		{"broadcast", "? (192.168.1.1) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]", "en0", false},
		{"zero", "? (192.168.1.1) at 00:00:00:00:00:00 on en0 ifscope [ethernet]", "en0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDarwinARP(tc.line, tc.device, hop)
			if (len(got) == 6) != tc.want {
				t.Fatalf("MAC = %v, want valid=%t", got, tc.want)
			}
		})
	}
}
