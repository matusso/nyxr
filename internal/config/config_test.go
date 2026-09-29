package config

import (
	"testing"
)

func TestParsePorts(t *testing.T) {
	ports, err := ParsePorts("443,80-82,80")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{80, 81, 82, 443}
	if len(ports) != len(want) {
		t.Fatalf("got %v", ports)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("got %v", ports)
		}
	}
	for _, bad := range []string{"0", "65536", "99-80", "1-x", ""} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestParseTargets(t *testing.T) {
	targets, err := ParseTargets([]string{"192.0.2.1-192.0.2.2", "192.0.2.0/30", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 4 {
		t.Fatalf("got %v", targets)
	}
	if targets[0].String() != "192.0.2.0" || targets[3].String() != "192.0.2.3" {
		t.Fatalf("got %v", targets)
	}
	if _, err := ParseTargets([]string{"192.0.0.0/15"}); err == nil {
		t.Fatal("accepted oversized range")
	}
}
