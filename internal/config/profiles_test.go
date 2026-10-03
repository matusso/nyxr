package config

import "testing"

func TestProfilesCatalog(t *testing.T) {
	names := map[string]bool{}
	available := 0
	for _, p := range Profiles() {
		if p.Name == "" || p.Description == "" {
			t.Fatalf("profile missing name/description: %+v", p)
		}
		if names[p.Name] {
			t.Fatalf("duplicate profile %q", p.Name)
		}
		names[p.Name] = true
		switch p.Availability {
		case StatusAvailable:
			available++
		case StatusPlanned:
			if p.Requires == "" {
				t.Fatalf("planned profile %q must state a prerequisite", p.Name)
			}
		default:
			t.Fatalf("profile %q has invalid availability %q", p.Name, p.Availability)
		}
	}
	for _, want := range []string{"tcp-basic", "tcp-common", "tcp-full", "udp-basic", "udp-common", "udp-full", "deep-scan", "windows", "filesystem", "web", "database", "iot", "ot-safe", "research", "custom"} {
		if !names[want] {
			t.Fatalf("profile %q is not registered", want)
		}
	}
	if available < 5 {
		t.Fatalf("expected several available profiles, got %d", available)
	}
	for old, replacement := range renamedProfiles {
		if names[old] || !names[replacement] {
			t.Fatalf("renamed profile %q -> %q is inconsistent with the catalog", old, replacement)
		}
	}
	if _, ok := LookupProfile("does-not-exist"); ok {
		t.Fatal("LookupProfile should not find a missing profile")
	}
}

func TestPlan(t *testing.T) {
	cfg, err := Build(Options{Targets: []string{"192.0.2.0/30"}, Profile: "tcp-basic", Ports: "80,443"})
	if err != nil {
		t.Fatal(err)
	}
	plan := cfg.Plan()
	if plan.Targets != 4 || plan.Ports != 2 {
		t.Fatalf("unexpected plan counts: %+v", plan)
	}
	// 4 targets x 2 ports x tcp = 8 tasks.
	if plan.Tasks != 8 {
		t.Fatalf("expected 8 tasks, got %d", plan.Tasks)
	}
	if len(plan.Protocols) != 1 || plan.Protocols[0] != "tcp" {
		t.Fatalf("unexpected protocols: %v", plan.Protocols)
	}
	if plan.PortSummary != "80,443" {
		t.Fatalf("unexpected port summary: %q", plan.PortSummary)
	}
}
