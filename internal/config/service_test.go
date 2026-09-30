package config

import (
	"strings"
	"testing"
	"time"
)

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
	for name, fallback := range map[string]string{"service": "http", "deep": "tls,http", "web": "tls,http", "full": "tls,http"} {
		s, err := BuildService(build(t, Options{Profile: name}), ServiceOptions{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !s.Enabled || strings.Join(s.Fallback, ",") != fallback || s.Workers < 1 || s.Timeout <= 0 {
			t.Fatalf("%s: unexpected stage %+v", name, s)
		}
	}
	s, err := BuildService(build(t, Options{Profile: "tcp"}), ServiceOptions{})
	if err != nil || s.Enabled || s.Plan() != nil {
		t.Fatalf("tcp profile must stay discovery-only: %+v %v", s, err)
	}
}

func TestServiceOverrides(t *testing.T) {
	on, off, workers := true, false, 3
	s, err := BuildService(build(t, Options{Profile: "tcp"}), ServiceOptions{Enable: &on, Probes: "http, tls,http", Fallback: "none", Timeout: "750ms", Workers: &workers})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(s.Probes, ",") != "http,tls" || s.Fallback != nil || s.Timeout != 750*time.Millisecond || s.Workers != 3 || s.Rate != 50 {
		t.Fatalf("overrides not applied: %+v", s)
	}
	if s, err := BuildService(build(t, Options{Profile: "deep"}), ServiceOptions{Enable: &off}); err != nil || s.Enabled {
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
		"ot-safe":         {Options{Profile: "ot-safe"}, ServiceOptions{Enable: &on}, "does not allow deep service probes"},
		"udp only":        {Options{Profile: "udp"}, ServiceOptions{Enable: &on}, "require the TCP protocol"},
		"unknown probe":   {Options{Profile: "service"}, ServiceOptions{Probes: "smb"}, "unknown service probe"},
		"option w/o flag": {Options{Profile: "tcp"}, ServiceOptions{Probes: "http"}, "require --service"},
		"bad timeout":     {Options{Profile: "service"}, ServiceOptions{Timeout: "soon"}, "service timeout"},
		"empty name":      {Options{Profile: "service"}, ServiceOptions{Probes: "http,,tls"}, "empty service probe"},
	} {
		_, err := BuildService(build(t, tc.opts), tc.svc)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: want %q, got %v", name, tc.want, err)
		}
	}
}
