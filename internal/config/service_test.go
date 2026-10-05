package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProtocolDefinitionsResolveAndPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")
	if err := os.WriteFile(path, []byte("schema: nyxr/protocol/v1\nprotocol: custom\ntransport: tcp\nports: [5432]\nsteps:\n  - send: {text: PING}\n  - receive: {max_bytes: 4}\n  - expect: {prefix: PONG}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	on := true
	r := Request{Targets: []string{"192.0.2.1"}, Profile: "tcp-basic", Service: &on, ProtocolDefinitions: "custom.yaml"}
	resolved, err := r.Resolve(ResolveOptions{BaseDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.Service.Definitions) != 1 || resolved.Service.Definitions[0].Name != "custom" || resolved.Service.Plan().ProtocolDefinitions[0] != path {
		t.Fatalf("definition not loaded or planned: %+v", resolved.Service)
	}
	if _, err := r.Resolve(ResolveOptions{Remote: true}); err == nil || !strings.Contains(err.Error(), "remote requests") {
		t.Fatalf("remote file access allowed: %v", err)
	}
	r.Profile, r.AllowTargets = "ot-safe", []string{"192.0.2.1"}
	if _, err := r.Resolve(ResolveOptions{BaseDir: dir}); err == nil || !strings.Contains(err.Error(), "does not allow custom") {
		t.Fatalf("ot-safe accepted custom definition: %v", err)
	}
}

func build(t *testing.T, o Options) Config {
	t.Helper()
	o.Targets = []string{"192.0.2.1"}
	cfg, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestServiceProfilesEnableStage(t *testing.T) {
	for name, fallback := range map[string]string{"tcp-common": "tls,http", "tcp-full": "tls,http,database", "web": "tls,http", "deep-scan": "tls,http,database", "windows": "tls,http", "filesystem": "tls,http", "database": "database"} {
		s, err := BuildService(build(t, Options{Profile: name}), ServiceOptions{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !s.Enabled || strings.Join(s.Fallback, ",") != fallback || s.Workers < 1 || s.Timeout <= 0 {
			t.Fatalf("%s: unexpected stage %+v", name, s)
		}
	}
	db, err := BuildService(build(t, Options{Profile: "database"}), ServiceOptions{})
	if err != nil || strings.Join(db.Probes, ",") != "database" {
		t.Fatalf("database identity stage: %+v %v", db, err)
	}
	ot, err := BuildService(build(t, Options{Profile: "ot-safe", AllowTargets: []string{"192.0.2.1"}}), ServiceOptions{})
	if err != nil || !ot.Enabled || strings.Join(ot.Probes, ",") != "modbus,ethernetip" {
		t.Fatalf("ot-safe identity stage: %+v %v", ot, err)
	}
	s, err := BuildService(build(t, Options{Profile: "tcp-basic"}), ServiceOptions{})
	if err != nil || s.Enabled || s.Plan() != nil {
		t.Fatalf("tcp profile must stay discovery-only: %+v %v", s, err)
	}
}

func TestServiceOverrides(t *testing.T) {
	on, off, workers := true, false, 3
	s, err := BuildService(build(t, Options{Profile: "tcp-basic"}), ServiceOptions{Enable: &on, Probes: "http, tls,http", Fallback: "none", Timeout: "750ms", Workers: &workers})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(s.Probes, ",") != "http,tls" || s.Fallback != nil || s.Timeout != 750*time.Millisecond || s.Workers != 3 || s.Rate != 50 {
		t.Fatalf("overrides not applied: %+v", s)
	}
	if s, err := BuildService(build(t, Options{Profile: "tcp-common"}), ServiceOptions{Enable: &off}); err != nil || s.Enabled {
		t.Fatalf("explicit disable ignored: %+v %v", s, err)
	}
	plan := s.Plan()
	if plan == nil || plan.Timeout != "750ms" {
		t.Fatalf("plan: %+v", plan)
	}
}

func TestServiceRejections(t *testing.T) {
	on := true
	for name, tc := range map[string]struct {
		opts Options
		svc  ServiceOptions
		want string
	}{
		"ot-safe":         {Options{Profile: "ot-safe", AllowTargets: []string{"192.0.2.1"}}, ServiceOptions{Probes: "http"}, "does not allow service probe"},
		"udp only":        {Options{Profile: "udp-common"}, ServiceOptions{Enable: &on}, "require the TCP protocol"},
		"unknown probe":   {Options{Profile: "tcp-common"}, ServiceOptions{Probes: "telnet"}, "unknown service probe"},
		"option w/o flag": {Options{Profile: "tcp-basic"}, ServiceOptions{Probes: "http"}, "require --service"},
		"bad timeout":     {Options{Profile: "tcp-common"}, ServiceOptions{Timeout: "soon"}, "service timeout"},
		"empty name":      {Options{Profile: "tcp-common"}, ServiceOptions{Probes: "http,,tls"}, "empty service probe"},
	} {
		_, err := BuildService(build(t, tc.opts), tc.svc)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: want %q, got %v", name, tc.want, err)
		}
	}
}

func TestServiceNmapProbes(t *testing.T) {
	// Supplying the file enables the nmap probe and records the path.
	s, err := BuildService(build(t, Options{Profile: "tcp-common"}), ServiceOptions{NmapProbes: "/tmp/nmap-service-probes"})
	if err != nil {
		t.Fatal(err)
	}
	if s.NmapProbesFile != "/tmp/nmap-service-probes" {
		t.Fatalf("nmap file not recorded: %+v", s)
	}
	found := false
	for _, p := range s.Probes {
		if p == "nmap" {
			found = true
		}
	}
	if !found {
		t.Fatalf("nmap probe not added: %+v", s.Probes)
	}
	if plan := s.Plan(); plan == nil || plan.NmapProbes != "/tmp/nmap-service-probes" {
		t.Fatalf("plan missing nmap file: %+v", plan)
	}

	// Naming the probe without a file is an error.
	if _, err := BuildService(build(t, Options{Profile: "tcp-common"}), ServiceOptions{Probes: "banner,nmap"}); err == nil ||
		!strings.Contains(err.Error(), "requires --nmap-service-probes") {
		t.Fatalf("nmap without a file should fail, got %v", err)
	}

	// The file is a service override, so it needs the stage enabled.
	if _, err := BuildService(build(t, Options{Profile: "tcp-basic"}), ServiceOptions{NmapProbes: "/tmp/x"}); err == nil ||
		!strings.Contains(err.Error(), "require --service") {
		t.Fatalf("nmap file without a service stage should fail, got %v", err)
	}

	// ot-safe never allows the nmap probe.
	if _, err := BuildService(build(t, Options{Profile: "ot-safe", AllowTargets: []string{"192.0.2.1"}}),
		ServiceOptions{NmapProbes: "/tmp/x"}); err == nil {
		t.Fatal("ot-safe must reject the nmap probe")
	}
}

func TestNmapServiceProbesRemoteRejected(t *testing.T) {
	r := Request{Targets: []string{"192.0.2.1"}, Profile: "tcp-common", NmapServiceProbes: "/etc/nmap-service-probes"}
	if _, err := r.Resolve(ResolveOptions{Remote: true}); err == nil ||
		!strings.Contains(err.Error(), "local path") {
		t.Fatalf("remote request must reject nmap_service_probes, got %v", err)
	}
	// The same request resolves locally.
	if _, err := r.Resolve(ResolveOptions{}); err != nil {
		t.Fatalf("local resolve should succeed: %v", err)
	}
}

func TestOTServicePolicyCannotBeBypassed(t *testing.T) {
	cfg := build(t, Options{Profile: "ot-safe", AllowTargets: []string{"192.0.2.1"}})
	for _, svc := range []Service{
		{Enabled: true, Probes: []string{"http"}, Timeout: 3 * time.Second, Workers: 4, Rate: 5},
		{Enabled: true, Probes: []string{"modbus"}, Timeout: 3 * time.Second, Workers: 4, Rate: 0},
		{Enabled: true, Probes: []string{"modbus"}, Timeout: 3 * time.Second, Workers: 4, Rate: 5, Fallback: []string{"http"}},
	} {
		if err := svc.ValidateFor(cfg); err == nil {
			t.Fatalf("accepted unsafe direct service config: %+v", svc)
		}
	}
}
