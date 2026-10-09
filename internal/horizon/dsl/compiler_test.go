package dsl

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/horizon/model"
)

func example(t *testing.T) model.Experiment {
	t.Helper()
	b, err := os.ReadFile("../../../lab/horizon/hz-001.yaml")
	if err != nil {
		t.Fatal(err)
	}
	e, err := Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func policy() model.Policy {
	return model.Policy{AllowTargets: []string{"192.0.2.0/24"}, AllowPorts: []uint16{443}}
}

func TestDeterministicCompilation(t *testing.T) {
	e := example(t)
	a, err := Compile(e, policy())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Compile(e, policy())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) || len(a.Trials) != 24 || a.MaxPackets != 48 || a.Hash == "" {
		t.Fatalf("non-deterministic or incorrect plan: %+v", a)
	}
	encoded, _ := json.Marshal(e)
	fromJSON, err := Parse(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Compile(fromJSON, policy())
	if err != nil || !reflect.DeepEqual(a, c) {
		t.Fatalf("JSON/YAML mismatch: %v", err)
	}
	for i := 0; i < len(a.Trials); i += 2 {
		if a.Trials[i].Pair != i/2 || a.Trials[i+1].Pair != i/2 || a.Trials[i].Arm == a.Trials[i+1].Arm {
			t.Fatal("not paired")
		}
	}
	changed := e
	changed.Spec.Execution.Seed++
	c, err = Compile(changed, policy())
	if err != nil || a.Hash == c.Hash || reflect.DeepEqual(a.Trials, c.Trials) {
		t.Fatal("seed not included in identity/order")
	}
}

func TestAdmissionRejectsUnsafeExperiments(t *testing.T) {
	cases := map[string]func(*model.Experiment, *model.Policy){
		"version":                  func(e *model.Experiment, p *model.Policy) { e.APIVersion = "v9" },
		"empty scope":              func(e *model.Experiment, p *model.Policy) { p.AllowTargets = nil },
		"whitespace scope":         func(e *model.Experiment, p *model.Policy) { p.AllowTargets = []string{" , "} },
		"out of scope":             func(e *model.Experiment, p *model.Policy) { p.AllowTargets = []string{"198.51.100.0/24"} },
		"bad scope":                func(e *model.Experiment, p *model.Policy) { p.AllowTargets = []string{"example.com"} },
		"empty port authorization": func(e *model.Experiment, p *model.Policy) { p.AllowPorts = nil },
		"unauthorized port":        func(e *model.Experiment, p *model.Policy) { p.AllowPorts = []uint16{80} },
		"multiple targets": func(e *model.Experiment, p *model.Policy) {
			e.Spec.Scope.Targets = append(e.Spec.Scope.Targets, "192.0.2.11")
		},
		"dns": func(e *model.Experiment, p *model.Policy) { e.Spec.Scope.Targets[0] = "example.com" },
		"multicast": func(e *model.Experiment, p *model.Policy) {
			e.Spec.Scope.Targets[0] = "224.0.0.1"
			p.AllowTargets = []string{"0.0.0.0/0"}
		},
		"mapped ipv6": func(e *model.Experiment, p *model.Policy) { e.Spec.Scope.Targets[0] = "::ffff:192.0.2.10" },
		"unspecified": func(e *model.Experiment, p *model.Policy) { e.Spec.Scope.Targets[0] = "0.0.0.0" },
		"broadcast": func(e *model.Experiment, p *model.Policy) {
			e.Spec.Scope.Targets[0] = "255.255.255.255"
			p.AllowTargets = []string{"0.0.0.0/0"}
		},
		"bad flags": func(e *model.Experiment, p *model.Policy) { e.Spec.Treatment.Steps[0].Send.Flags = []string{"FIN"} },
		"extra send": func(e *model.Experiment, p *model.Policy) {
			e.Spec.Control.Steps = append(e.Spec.Control.Steps, e.Spec.Control.Steps[0])
		},
		"mixed step": func(e *model.Experiment, p *model.Policy) {
			e.Spec.Control.Steps[0].Observe = &model.Observe{WindowMS: 100}
		},
		"bad profile":           func(e *model.Experiment, p *model.Policy) { e.Spec.Treatment.Steps[0].Send.OptionsProfile = "ecn" },
		"wrong port":            func(e *model.Experiment, p *model.Policy) { e.Spec.Treatment.Steps[0].Send.DstPort = 80 },
		"changed timeout":       func(e *model.Experiment, p *model.Policy) { e.Spec.Treatment.Steps[1].Observe.WindowMS = 101 },
		"negative timeout":      func(e *model.Experiment, p *model.Policy) { e.Spec.Control.Steps[1].Observe.WindowMS = -1 },
		"packet cleanup budget": func(e *model.Experiment, p *model.Policy) { e.Spec.Limits.MaxPackets = 24 },
		"unlimited rate":        func(e *model.Experiment, p *model.Policy) { e.Spec.Limits.PacketsPerSecond = 0 },
		"excess rate":           func(e *model.Experiment, p *model.Policy) { e.Spec.Limits.PacketsPerSecond = 100 },
		"duration":              func(e *model.Experiment, p *model.Policy) { e.Spec.Limits.MaxDurationSeconds = 1 },
		"unbounded repetitions": func(e *model.Experiment, p *model.Policy) { e.Spec.Execution.Replicates = 1000000000 },
		"unrandomized":          func(e *model.Experiment, p *model.Policy) { e.Spec.Execution.RandomizedOrder = false },
		"negative washout":      func(e *model.Experiment, p *model.Policy) { e.Spec.Execution.WashoutMS = -1 },
		"parallel":              func(e *model.Experiment, p *model.Policy) { e.Spec.Limits.MaxConcurrentFlows = 2 },
		"capture":               func(e *model.Experiment, p *model.Policy) { e.Spec.Capture.MaxBytes = 1 << 30 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			e := example(t)
			p := policy()
			change(&e, &p)
			if _, err := Compile(e, p); err == nil {
				t.Fatal("unsafe experiment admitted")
			}
		})
	}
}

func TestStrictParsing(t *testing.T) {
	b, _ := os.ReadFile("../../../lab/horizon/hz-001.yaml")
	for name, data := range map[string]string{
		"unknown root":   string(b) + "unknown: true\n",
		"unknown packet": strings.Replace(string(b), "protocol: tcp", "protocol: tcp\n          badChecksum: true", 1),
		"duplicate":      string(b) + "kind: Other\n",
		"extra document": string(b) + "---\nkind: Experiment\n",
		"anchor":         strings.Replace(string(b), "targets: [", "targets: &target [", 1),
		"alias":          "apiVersion: &v test\nkind: *v\n",
		"oversize":       strings.Repeat(" ", MaxDocumentBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(data)); err == nil {
				t.Fatal("invalid document accepted")
			}
		})
	}
}

func FuzzAdmission(f *testing.F) {
	b, err := os.ReadFile("../../../lab/horizon/hz-001.yaml")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte("spec: {limits: {maxPackets: -1}}"))
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := Parse(bytes.NewReader(b))
		if err != nil {
			return
		}
		p, err := Compile(e, policy())
		if err != nil {
			return
		}
		if p.MaxPackets > e.Spec.Limits.MaxPackets || len(p.Trials) != 2*e.Spec.Execution.Replicates || p.MaxDurationMS > int64(e.Spec.Limits.MaxDurationSeconds)*1000 {
			t.Fatal("admitted plan bypassed budgets")
		}
	})
}
