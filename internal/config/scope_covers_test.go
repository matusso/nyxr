package config

import (
	"net/netip"
	"testing"
)

func TestScopeCovers(t *testing.T) {
	s, err := ParseScope([]string{"10.0.0.0/25", "10.0.0.128-10.0.0.200", "2001:db8::/64"})
	if err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr
	for _, c := range []struct {
		first, last string
		want        bool
	}{
		{"10.0.0.1", "10.0.0.200", true},
		{"10.0.0.0", "10.0.0.201", false},
		{"10.0.0.5", "10.0.0.5", true},
		{"10.0.1.0", "10.0.1.0", false},
		{"2001:db8::1", "2001:db8::ffff", true},
		{"2001:db8:0:1::", "2001:db8:0:1::", false},
		{"10.0.0.9", "10.0.0.1", false},
	} {
		if got := s.Covers(a(c.first), a(c.last)); got != c.want {
			t.Errorf("Covers(%s, %s) = %v, want %v", c.first, c.last, got, c.want)
		}
	}
	if (Scope{}).Covers(a("10.0.0.1"), a("10.0.0.1")) {
		t.Error("empty scope must cover nothing")
	}
}
