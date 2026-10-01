package config

import (
	"net/netip"
	"strings"
	"testing"
)

func TestScopeMatchesIPCIDRAndRanges(t *testing.T) {
	s, err := ParseScope([]string{"10.0.0.0/24, 192.168.1.10-192.168.1.20", "172.16.0.5-9", "2001:db8::/64", "198.51.100.7"})
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]bool{
		"10.0.0.0": true, "10.0.0.255": true, "10.0.1.0": false,
		"192.168.1.10": true, "192.168.1.20": true, "192.168.1.21": false,
		"172.16.0.5": true, "172.16.0.9": true, "172.16.0.10": false,
		"2001:db8::1": true, "2001:db8:0:1::1": false,
		"198.51.100.7": true, "198.51.100.8": false, "::ffff:10.0.0.9": true,
	} {
		if got := s.Contains(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Contains(%s) = %v, want %v", addr, got, want)
		}
	}
	if empty, _ := ParseScope(nil); !empty.Empty() || !empty.Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("empty scope must match everything")
	}
	for _, bad := range []string{"host.example", "10.0.0.9-10.0.0.1", "10.0.0.1-2001:db8::1", "10.0.0.0/33"} {
		if _, err := ParseScope([]string{bad}); err == nil {
			t.Errorf("ParseScope(%q) accepted", bad)
		}
	}
}

func knownSource(ports ...KnownPort) KnownPortSource {
	return func() ([]KnownPort, error) { return ports, nil }
}

func kp(addr, transport string, port uint16) KnownPort {
	return KnownPort{Address: netip.MustParseAddr(addr), Transport: transport, Port: port}
}

func TestKnownOpenRescansOnlyStoredOpenPorts(t *testing.T) {
	source := knownSource(kp("10.0.0.1", "tcp", 22), kp("10.0.0.1", "tcp", 443), kp("10.0.0.2", "tcp", 80),
		kp("10.0.0.2", "udp", 161), kp("10.9.0.1", "tcp", 3306))
	r, err := Request{KnownOpen: true, Targets: []string{"10.0.0.0/24"}}.Resolve(ResolveOptions{Remote: true, KnownOpen: source})
	if err != nil {
		t.Fatal(err)
	}
	c := r.Config
	if c.Profile != KnownProfile || !r.Service.Enabled || !c.TCP || !c.UDP {
		t.Fatalf("profile %q service %v tcp %v udp %v", c.Profile, r.Service.Enabled, c.TCP, c.UDP)
	}
	if len(c.Targets) != 2 || c.Targets[0].String() != "10.0.0.1" || c.Targets[1].String() != "10.0.0.2" {
		t.Fatalf("targets outside the scope or missing: %v", c.Targets)
	}
	if got := summarizePorts(c.Ports); got != "22,80,161,443" {
		t.Fatalf("ports %s", got)
	}
	a1, a2 := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	if !c.Includes(a1, "tcp", 22) || c.Includes(a1, "tcp", 80) || c.Includes(a1, "udp", 22) || !c.Includes(a2, "udp", 161) || c.Includes(a2, "tcp", 161) {
		t.Fatal("restriction must hold exactly the stored pairs")
	}
	if p := r.Plan(); p.Tasks != 4 || !p.KnownOpen {
		t.Fatalf("plan tasks %d known %v, want 4 restricted tasks", p.Tasks, p.KnownOpen)
	}
}

func TestKnownOpenRefusals(t *testing.T) {
	source := knownSource(kp("10.0.0.1", "tcp", 22))
	off := false
	for name, tc := range map[string]struct {
		req  Request
		opts ResolveOptions
		want string
	}{
		"no database":  {Request{KnownOpen: true}, ResolveOptions{}, "database"},
		"empty scope":  {Request{KnownOpen: true, Targets: []string{"192.0.2.0/24"}}, ResolveOptions{KnownOpen: source}, "no open ports"},
		"ports given":  {Request{KnownOpen: true, Ports: "80"}, ResolveOptions{KnownOpen: source}, "drop ports"},
		"research":     {Request{KnownOpen: true, Profile: "research"}, ResolveOptions{KnownOpen: source}, "research"},
		"hostname":     {Request{KnownOpen: true, Targets: []string{"db.example"}}, ResolveOptions{KnownOpen: source}, "not an IP"},
		"service kept": {Request{KnownOpen: true, Service: &off}, ResolveOptions{KnownOpen: source}, ""},
	} {
		r, err := tc.req.Resolve(tc.opts)
		if tc.want == "" {
			if err != nil || r.Service.Enabled {
				t.Errorf("%s: err %v, service %v (explicit service=false must be kept)", name, err, r.Service.Enabled)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
	}
}
