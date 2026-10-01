package config

import (
	"net/netip"
	"testing"
)

func TestLargeSYNTargetsStayCompact(t *testing.T) {
	stream, err := ParseTargetStream([]string{"10.1.0.0/16", "10.2.0.0/16", "10.1.0.1"})
	if err != nil || stream.Count() != 131072 || len(stream.ranges) != 1 {
		t.Fatalf("stream=%+v err=%v", stream, err)
	}
	var first, last netip.Addr
	var count int
	stream.Each(func(addr netip.Addr) bool {
		if count == 0 {
			first = addr
		}
		last = addr
		count++
		return true
	})
	if count != stream.Count() || first.String() != "10.1.0.0" || last.String() != "10.2.255.255" {
		t.Fatalf("count=%d first=%s last=%s", count, first, last)
	}
}

func TestLargeSYNBuildAndAllowlist(t *testing.T) {
	opts := Options{Targets: []string{"10.1.0.0/16", "10.2.0.0/16"}, TCPMode: "syn", Interface: "en0", NextHopMAC: "02:00:00:00:00:01"}
	cfg, err := Build(opts)
	if err != nil || cfg.TargetCount() != 131072 || len(cfg.Targets) != 0 || cfg.Plan().Targets != 131072 {
		t.Fatalf("config=%+v err=%v", cfg, err)
	}
	cfg.AllowTargets = []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("10.2.0.0/16")}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("allowed stream: %v", err)
	}
	cfg.AllowTargets = []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("10.2.0.0/17")}
	if err := cfg.Validate(); err == nil {
		t.Fatal("partial allowlist accepted")
	}
}
