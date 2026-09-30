package config

import (
	"strings"
	"testing"
)

func intp(v int) *int { return &v }

func TestBuildDefaultProfile(t *testing.T) {
	cfg, err := Build(Options{Targets: []string{"192.0.2.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile != "discovery" || !cfg.TCP || cfg.UDP || cfg.ICMP {
		t.Fatalf("unexpected protocols: %+v", cfg)
	}
	if len(cfg.Ports) != 3 || cfg.Rate != 100 || cfg.Workers != 64 {
		t.Fatalf("unexpected defaults: ports=%v rate=%d workers=%d", cfg.Ports, cfg.Rate, cfg.Workers)
	}
}

func TestBuildOverridesProfile(t *testing.T) {
	cfg, err := Build(Options{
		Targets:   []string{"192.0.2.1"},
		Profile:   "udp-deep",
		Rate:      intp(7),
		Workers:   intp(3),
		Protocols: "udp",
		Ports:     "53",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Rate != 7 || cfg.Workers != 3 {
		t.Fatalf("overrides not applied: rate=%d workers=%d", cfg.Rate, cfg.Workers)
	}
	if cfg.UDPRetries != 1 {
		t.Fatalf("udp-deep should default retries to 1, got %d", cfg.UDPRetries)
	}
	if len(cfg.Ports) != 1 || cfg.Ports[0] != 53 {
		t.Fatalf("port override not applied: %v", cfg.Ports)
	}
}

func TestBuildUnknownProfile(t *testing.T) {
	_, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "nope"})
	if err == nil || !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("expected unknown profile error, got %v", err)
	}
}

func TestBuildPlannedProfileRejected(t *testing.T) {
	for _, name := range []string{"deep", "service", "iot", "web", "database", "full", "research"} {
		_, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: name})
		if err == nil || !strings.Contains(err.Error(), "planned") {
			t.Fatalf("profile %q should be rejected as planned, got %v", name, err)
		}
	}
}

func TestBuildCustomProfileRequiresFields(t *testing.T) {
	// custom contributes no defaults, so protocols must be supplied.
	if _, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "custom"}); err == nil {
		t.Fatal("custom without protocols should fail")
	}
	// ports required for tcp/udp.
	if _, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "custom", Protocols: "tcp", Timeout: "1s"}); err == nil {
		t.Fatal("custom tcp without ports should fail")
	}
	// icmp-only custom needs no ports.
	cfg, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "custom", Protocols: "icmp", Timeout: "1s"})
	if err != nil {
		t.Fatalf("icmp-only custom should build: %v", err)
	}
	if !cfg.ICMP || cfg.TCP || len(cfg.Ports) != 0 {
		t.Fatalf("unexpected icmp-only config: %+v", cfg)
	}
}

func TestBuildOTSafeEnforcement(t *testing.T) {
	base := Options{Targets: []string{"192.0.2.1"}, Profile: "ot-safe"}
	if _, err := Build(base); err != nil {
		t.Fatalf("default ot-safe should build: %v", err)
	}
	// UDP is refused.
	if _, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "ot-safe", Protocols: "udp", Ports: "53"}); err == nil {
		t.Fatal("ot-safe must reject udp")
	}
	// Unlimited rate (0) must be refused, not silently allowed.
	if _, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "ot-safe", Rate: intp(0)}); err == nil {
		t.Fatal("ot-safe must reject unlimited rate")
	}
	// Rate above the cap is refused.
	if _, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "ot-safe", Rate: intp(50)}); err == nil {
		t.Fatal("ot-safe must reject rate above cap")
	}
	// Too many workers refused.
	if _, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "ot-safe", Workers: intp(64)}); err == nil {
		t.Fatal("ot-safe must reject worker count above cap")
	}
	// Short timeout refused.
	if _, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "ot-safe", Timeout: "500ms"}); err == nil {
		t.Fatal("ot-safe must reject sub-3s timeout")
	}
	// Custom payloads refused even on a udp attempt.
	if _, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "ot-safe", Payload: PayloadSource{SendHex: "01"}}); err == nil {
		t.Fatal("ot-safe must reject custom payloads")
	}
}

func TestBuildCustomPayload(t *testing.T) {
	cfg, err := Build(Options{
		Targets: []string{"192.0.2.1"}, Profile: "udp",
		Payload: PayloadSource{SendHex: "01ff"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.UDPProbes) != 1 || cfg.UDPProbes[0].Name != "custom-hex" {
		t.Fatalf("unexpected probes: %+v", cfg.UDPProbes)
	}
	if len(cfg.UDPProbes[0].Payload) != 2 {
		t.Fatalf("payload not decoded: %v", cfg.UDPProbes[0].Payload)
	}
}

func TestBuildPayloadRequiresUDP(t *testing.T) {
	if _, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "tcp", Payload: PayloadSource{SendHex: "01"}}); err == nil {
		t.Fatal("custom payload without udp should fail")
	}
}

func TestBuildPayloadOneSource(t *testing.T) {
	_, err := Build(Options{
		Targets: []string{"192.0.2.1"}, Profile: "udp",
		Payload: PayloadSource{SendHex: "01", SendBase64: "AQ=="},
	})
	if err == nil || !strings.Contains(err.Error(), "one custom UDP payload") {
		t.Fatalf("expected single-source error, got %v", err)
	}
}

func TestResolvePorts(t *testing.T) {
	all, err := ResolvePorts("all")
	if err != nil || len(all) != 65535 {
		t.Fatalf("all ports: len=%d err=%v", len(all), err)
	}
	top, err := ResolvePorts("top-100")
	if err != nil || len(top) == 0 {
		t.Fatalf("top-100: len=%d err=%v", len(top), err)
	}
	for i := 1; i < len(top); i++ {
		if top[i] <= top[i-1] {
			t.Fatalf("top100 not sorted/unique at %d: %v", i, top)
		}
	}
	if _, err := ResolvePorts("22,443"); err != nil {
		t.Fatalf("numeric list should still work: %v", err)
	}
}
