package config

import (
	"strings"
	"testing"
)

func researchOptions() Options {
	return Options{Profile: "research", Targets: []string{"192.0.2.10"}, AllowTargets: []string{"192.0.2.0/24"}, Interface: "eth0",
		Research: ResearchOptions{Kind: "tcp", TCPFlags: "xmas"}}
}

func TestResearchPolicy(t *testing.T) {
	o := researchOptions()
	cfg, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Research.TCPFlags != 0x29 || cfg.Rate != 5 || cfg.Workers != 1 || cfg.Plan().Tasks != 1 {
		t.Fatalf("bad research defaults: %+v %+v", cfg, cfg.Plan())
	}
	trueValue := true
	if _, err := BuildService(cfg, ServiceOptions{Enable: &trueValue}); err == nil {
		t.Fatal("research permitted deep service sends")
	}
	for _, mutate := range []func(*Options){
		func(o *Options) { o.AllowTargets = nil },
		func(o *Options) { o.Targets = []string{"198.51.100.1"} },
		func(o *Options) { x := 6; o.Rate = &x },
		func(o *Options) { x := 2; o.Workers = &x },
		func(o *Options) { o.Interface = "" },
		func(o *Options) { o.Research.FragmentSize = 7 },
		func(o *Options) { o.Research.Kind = "ip"; o.Research.IPProtocol = "not-a-number" },
	} {
		copy := o
		mutate(&copy)
		if _, err := Build(copy); err == nil {
			t.Fatalf("accepted unsafe research options: %+v", copy)
		}
	}
	o.Profile = "tcp"
	if _, err := Build(o); err == nil || !strings.Contains(err.Error(), "research") {
		t.Fatalf("ordinary profile accepted research controls: %v", err)
	}
}

func TestResearchProtocolKinds(t *testing.T) {
	for _, kind := range []string{"tcp", "udp", "icmp", "sctp", "ip"} {
		o := researchOptions()
		o.Research = ResearchOptions{Kind: kind}
		if kind == "ip" {
			o.Research.IPProtocol = "50"
		}
		cfg, err := Build(o)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if cfg.Plan().Tasks != 1 || cfg.Research.Kind != kind {
			t.Fatalf("%s: %+v", kind, cfg.Plan())
		}
	}
}

func TestRemoteResearchRejected(t *testing.T) {
	r := Request{Profile: "research"}
	if _, err := r.Resolve(ResolveOptions{Remote: true}); err == nil {
		t.Fatal("remote research request accepted")
	}
}
