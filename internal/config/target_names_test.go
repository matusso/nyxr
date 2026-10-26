package config

import (
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func stubLookup(t *testing.T, hosts map[string][]string) {
	t.Helper()
	previous := lookupIP
	lookupIP = func(name string) ([]net.IP, error) {
		var out []net.IP
		for _, a := range hosts[strings.TrimSuffix(strings.ToLower(name), ".")] {
			out = append(out, net.ParseIP(a))
		}
		if len(out) == 0 {
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		}
		return out, nil
	}
	t.Cleanup(func() { lookupIP = previous })
}

func TestBuildKeepsHostnamesForResolvedTargets(t *testing.T) {
	stubLookup(t, map[string][]string{
		"app.example.test":   {"192.0.2.10"},
		"other.example.test": {"192.0.2.10", "192.0.2.11"},
	})
	cfg, err := Build(Options{Targets: []string{"App.Example.Test.,other.example.test,192.0.2.12"}, Ports: "443", AllowTargets: []string{"192.0.2.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Targets) != 3 {
		t.Fatalf("targets = %v", cfg.Targets)
	}
	if got := cfg.TargetNames[netip.MustParseAddr("192.0.2.10")]; !slices.Equal(got, []string{"app.example.test", "other.example.test"}) {
		t.Fatalf("names keep input order, lower case and no trailing dot: %v", got)
	}
	if got := cfg.TargetNames[netip.MustParseAddr("192.0.2.12")]; got != nil {
		t.Fatalf("a literal address has no name: %v", got)
	}
}

func TestHostnameTargetsStayBoundToAuthorizedAddresses(t *testing.T) {
	stubLookup(t, map[string][]string{"app.example.test": {"192.0.2.10", "198.51.100.7"}})
	_, err := Build(Options{Targets: []string{"app.example.test"}, Ports: "443", AllowTargets: []string{"192.0.2.0/24"}})
	if err == nil || !strings.Contains(err.Error(), "198.51.100.7 is outside --allow-targets") {
		t.Fatalf("every resolved address must be authorized: %v", err)
	}
}

func TestTargetNamesAreBounded(t *testing.T) {
	hosts := map[string][]string{}
	var targets []string
	for i := range 6 {
		name := "n" + string(rune('a'+i)) + ".example.test"
		hosts[name] = []string{"192.0.2.10"}
		targets = append(targets, name)
	}
	stubLookup(t, hosts)
	_, names, err := ParseTargetsNamed(targets)
	if err != nil {
		t.Fatal(err)
	}
	if got := names[netip.MustParseAddr("192.0.2.10")]; len(got) != 4 || got[0] != "na.example.test" {
		t.Fatalf("names per address must be bounded: %v", got)
	}
}
