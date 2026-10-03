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
	if cfg.Profile != "tcp-basic" || !cfg.TCP || cfg.UDP || cfg.ICMP {
		t.Fatalf("unexpected protocols: %+v", cfg)
	}
	if top, _ := ResolvePorts("top100"); len(cfg.Ports) != len(top) || cfg.Rate != 300 || cfg.Workers != 128 {
		t.Fatalf("unexpected defaults: ports=%v rate=%d workers=%d", cfg.Ports, cfg.Rate, cfg.Workers)
	}
}

func TestBuildOverridesProfile(t *testing.T) {
	cfg, err := Build(Options{
		Targets:   []string{"192.0.2.1"},
		Profile:   "udp-full",
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
		t.Fatalf("udp-full should default retries to 1, got %d", cfg.UDPRetries)
	}
	if cfg.UDPMode != UDPFull {
		t.Fatalf("udp-full should exhaust the catalog, got %q", cfg.UDPMode)
	}
	if len(cfg.Ports) != 1 || cfg.Ports[0] != 53 {
		t.Fatalf("port override not applied: %v", cfg.Ports)
	}
}

func TestBuildUDPProfileModes(t *testing.T) {
	for _, tc := range []struct {
		profile string
		mode    UDPMode
	}{
		{"udp-basic", UDPBasic},
		{"udp-common", UDPCommon},
		{"udp-full", UDPFull},
	} {
		cfg, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: tc.profile, Ports: "40000"})
		if err != nil || cfg.UDPMode != tc.mode || cfg.Plan().UDPMode != tc.mode {
			t.Fatalf("%s: mode=%q, plan=%q, err=%v", tc.profile, cfg.UDPMode, cfg.Plan().UDPMode, err)
		}
	}
	if _, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "udp-basic",
		Payload: PayloadSource{SendHex: "01"}}); err == nil {
		t.Fatal("udp-basic accepted a custom payload")
	}
}

func TestBuildDeepScanSplitsTCPAndUDPPorts(t *testing.T) {
	cfg, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "deep-scan"})
	if err != nil {
		t.Fatal(err)
	}
	udp, _ := ResolvePorts("udp")
	if !cfg.TCP || !cfg.UDP || len(cfg.PortsFor("tcp")) != 65535 || len(cfg.PortsFor("udp")) != len(udp) {
		t.Fatalf("full: tcp=%d udp=%d ports", len(cfg.PortsFor("tcp")), len(cfg.PortsFor("udp")))
	}
	if plan := cfg.Plan(); plan.Tasks != 65535+len(udp) || plan.UDPPorts != len(udp) {
		t.Fatalf("full plan: %+v", plan)
	}
	// An explicit port list applies to both transports.
	cfg, err = Build(Options{Targets: []string{"192.0.2.1"}, Profile: "deep-scan", Ports: "53,80"})
	if err != nil || cfg.UDPPorts != nil || len(cfg.PortsFor("udp")) != 2 || cfg.Plan().Tasks != 4 {
		t.Fatalf("full with --ports: %+v %v", cfg.Plan(), err)
	}
	// Narrowing full to UDP keeps the UDP list.
	cfg, err = Build(Options{Targets: []string{"192.0.2.1"}, Profile: "deep-scan", Protocols: "udp"})
	if err != nil || len(cfg.Ports) != len(udp) || cfg.UDPPorts != nil {
		t.Fatalf("full udp-only: ports=%d err=%v", len(cfg.Ports), err)
	}
}

func TestBuildRemovedProfilePointsToReplacement(t *testing.T) {
	_, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "deep"})
	if err == nil || !strings.Contains(err.Error(), `use "tcp-common"`) {
		t.Fatalf("removed profile error: %v", err)
	}
	// "full" was renamed to "deep-scan"; the old name must point at it.
	_, err = Build(Options{Targets: []string{"192.0.2.1"}, Profile: "full"})
	if err == nil || !strings.Contains(err.Error(), `use "deep-scan"`) {
		t.Fatalf("renamed profile error: %v", err)
	}
}

func TestBuildUnknownProfile(t *testing.T) {
	_, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "nope"})
	if err == nil || !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("expected unknown profile error, got %v", err)
	}
}

func TestBuildDatabaseProfile(t *testing.T) {
	cfg, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "database"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TCP || cfg.UDP || len(cfg.Ports) < 40 {
		t.Fatalf("database profile must scan the TCP catalog: %+v", cfg)
	}
	for _, want := range []uint16{1433, 3306, 5432, 6379, 7687, 9042, 9200, 11211, 27017} {
		found := false
		for _, p := range cfg.Ports {
			found = found || p == want
		}
		if !found {
			t.Fatalf("database profile missing %d", want)
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
	base := Options{Targets: []string{"192.0.2.1"}, AllowTargets: []string{"192.0.2.0/24"}, Profile: "ot-safe"}
	if _, err := Build(base); err != nil {
		t.Fatalf("default ot-safe should build: %v", err)
	}
	if _, err := Build(Options{Targets: base.Targets, Profile: "ot-safe"}); err == nil {
		t.Fatal("ot-safe must require an allowlist")
	}
	if _, err := Build(Options{Targets: base.Targets, AllowTargets: []string{"192.0.3.0/24"}, Profile: "ot-safe"}); err == nil {
		t.Fatal("ot-safe must reject targets outside the allowlist")
	}
	if _, err := Build(Options{Targets: base.Targets, AllowTargets: base.AllowTargets, Profile: "ot-safe", Ports: "22"}); err == nil {
		t.Fatal("ot-safe must reject unapproved ports")
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
		Targets: []string{"192.0.2.1"}, Profile: "udp-common",
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
	if _, err := Build(Options{Targets: []string{"192.0.2.1"}, Profile: "tcp-basic", Payload: PayloadSource{SendHex: "01"}}); err == nil {
		t.Fatal("custom payload without udp should fail")
	}
}

func TestBuildNmapUDPRequiresUDPAndNoCustomPayload(t *testing.T) {
	for _, o := range []Options{
		{Targets: []string{"192.0.2.1"}, Profile: "tcp-basic", NmapUDPProbes: "unused"},
		{Targets: []string{"192.0.2.1"}, Profile: "udp-common", NmapUDPProbes: "unused", Payload: PayloadSource{SendHex: "01"}},
	} {
		if _, err := Build(o); err == nil || !strings.Contains(err.Error(), "Nmap UDP probes require UDP") {
			t.Fatalf("invalid Nmap UDP options accepted: %v", err)
		}
	}
}

func TestBuildPayloadOneSource(t *testing.T) {
	_, err := Build(Options{
		Targets: []string{"192.0.2.1"}, Profile: "udp-common",
		Payload: PayloadSource{SendHex: "01", SendBase64: "AQ=="},
	})
	if err == nil || !strings.Contains(err.Error(), "one custom UDP payload") {
		t.Fatalf("expected single-source error, got %v", err)
	}
}

func TestBuildRawSYNRequirements(t *testing.T) {
	base := Options{Targets: []string{"192.0.2.1"}, TCPMode: "syn", Interface: "eth0", NextHopMAC: "02:11:22:33:44:55"}
	cfg, err := Build(base)
	if err != nil || cfg.TCPMode != "syn" || cfg.Plan().NextHopMAC != base.NextHopMAC {
		t.Fatalf("SYN configuration: %+v, %v", cfg, err)
	}
	automatic := base
	automatic.NextHopMAC = ""
	if _, err := Build(automatic); err != nil {
		t.Fatalf("automatic next-hop configuration: %v", err)
	}
	for _, tc := range []Options{
		{Targets: base.Targets, TCPMode: "syn"},
		{Targets: base.Targets, TCPMode: "syn", Interface: "eth0", NextHopMAC: "ff:ff:ff:ff:ff:ff"},
		{Targets: []string{"2001:db8::1"}, TCPMode: "syn", Interface: "eth0", NextHopMAC: base.NextHopMAC},
		{Targets: base.Targets, Profile: "ot-safe", TCPMode: "syn", Interface: "eth0", NextHopMAC: base.NextHopMAC},
	} {
		if _, err := Build(tc); err == nil {
			t.Fatalf("accepted unsafe SYN configuration: %+v", tc)
		}
	}
}

func TestBuildNeighborDiscovery(t *testing.T) {
	for _, tc := range []struct{ protocol, target string }{
		{"arp", "192.0.2.10"}, {"ndp", "2001:db8:1::10"},
	} {
		cfg, err := Build(Options{Targets: []string{tc.target}, Profile: "custom", Protocols: tc.protocol,
			Interface: "eth0", Timeout: "1s"})
		if err != nil || cfg.Plan().Tasks != 1 || len(cfg.Ports) != 0 {
			t.Fatalf("%s plan: %+v, %v", tc.protocol, cfg, err)
		}
	}
	for _, tc := range []Options{
		{Targets: []string{"192.0.2.10"}, Profile: "custom", Protocols: "arp", Timeout: "1s"},
		{Targets: []string{"2001:db8::10"}, Profile: "custom", Protocols: "arp", Interface: "eth0", Timeout: "1s"},
		{Targets: []string{"192.0.2.10"}, Profile: "ot-safe", Protocols: "arp", Interface: "eth0"},
	} {
		if _, err := Build(tc); err == nil {
			t.Fatalf("accepted invalid neighbor discovery: %+v", tc)
		}
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
	var prev []uint16
	for _, tc := range []struct {
		name string
		want int
	}{{"TOP-1000", 1000}, {"top2000", 2000}, {"top5000", 5000}, {"top8387", 8387}} {
		ports, err := ResolvePorts(tc.name)
		if err != nil || len(ports) != tc.want {
			t.Fatalf("%s: len=%d err=%v", tc.name, len(ports), err)
		}
		in := make(map[uint16]bool, len(ports))
		for _, p := range ports {
			in[p] = true
		}
		for _, p := range prev {
			if !in[p] {
				t.Fatalf("%s is missing port %d from the smaller set", tc.name, p)
			}
		}
		prev = ports
	}
	if _, err := ResolvePorts("22,443"); err != nil {
		t.Fatalf("numeric list should still work: %v", err)
	}
}
