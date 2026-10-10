package dsl

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

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

func TestStrictWireTypes(t *testing.T) {
	b, err := os.ReadFile("../../../lab/horizon/hz-001.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"fractional replicates": strings.Replace(string(b), "replicates: 12", "replicates: 12.9", 1),
		"fractional port":       strings.Replace(string(b), "tcpPorts: [443]", "tcpPorts: [443.9]", 1),
		"fractional rate":       strings.Replace(string(b), "packetsPerSecond: 3", "packetsPerSecond: 3.9", 1),
		"quoted integer":        strings.Replace(string(b), "maxPackets: 48", "maxPackets: \"48\"", 1),
		"numeric name":          strings.Replace(string(b), "name: hz-001-sack-permission", "name: 123", 1),
		"null seed":             strings.Replace(string(b), "seed: 42", "seed: null", 1),
		"null washout":          strings.Replace(string(b), "washoutMs: 50", "washoutMs: null", 1),
		"null extra step field": strings.Replace(string(b), "- observe: {windowMs: 100}", "- observe: {windowMs: 100}\n        send: null", 1),
		"missing required":      strings.Replace(string(b), "    randomizedOrder: true\n", "", 1),
		"explicit scalar tag":   strings.Replace(string(b), "seed: 42", "seed: !custom 42", 1),
		"non-string field":      strings.Replace(string(b), "seed: 42", "42: 42", 1),
		"empty":                 "",
		"null root":             "null",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(data)); err == nil {
				t.Fatal("invalid wire type accepted")
			}
		})
	}
	encoded, err := json.Marshal(example(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{
		strings.Replace(string(encoded), `"replicates":12`, `"replicates":12.9`, 1),
		strings.Replace(string(encoded), `"seed":42`, `"seed":null`, 1),
		strings.Replace(string(encoded), `"name":"hz-001-sack-permission"`, `"name":123`, 1),
	} {
		if _, err := Parse(strings.NewReader(data)); err == nil {
			t.Fatal("invalid JSON wire type accepted")
		}
	}
}

func TestNormalizedExperimentIdentity(t *testing.T) {
	b, err := os.ReadFile("../../../lab/horizon/hz-001.yaml")
	if err != nil {
		t.Fatal(err)
	}
	explicit := strings.Replace(string(b), "seed: 42", "seed: 0", 1)
	explicit = strings.Replace(explicit, "washoutMs: 50", "washoutMs: 0", 1)
	omitted := strings.Replace(explicit, "    seed: 0\n", "", 1)
	omitted = strings.Replace(omitted, "    washoutMs: 0\n", "", 1)
	var plans []model.Plan
	for _, data := range []string{explicit, omitted} {
		e, err := Parse(strings.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		p, err := Compile(e, policy())
		if err != nil {
			t.Fatal(err)
		}
		plans = append(plans, p)
	}
	if !reflect.DeepEqual(plans[0], plans[1]) {
		t.Fatal("omitted defaults changed experiment identity or trial order")
	}
	p := policy()
	p.AllowTargets = []string{"2001:db8::/32"}
	e := example(t)
	e.Spec.Scope.Targets = []string{"2001:0db8:0000:0000:0000:0000:0000:0010"}
	a, err := Compile(e, p)
	if err != nil {
		t.Fatal(err)
	}
	e.Spec.Scope.Targets = []string{"2001:db8::10"}
	c, err := Compile(e, p)
	if err != nil || !reflect.DeepEqual(a, c) {
		t.Fatalf("equivalent IPv6 spellings changed the normalized plan: %v", err)
	}
}

func TestCompileBoundsIncludeCleanup(t *testing.T) {
	for _, replicates := range []int{2, 50} {
		for _, rate := range []int{1, 10} {
			e := example(t)
			e.Spec.Execution.Replicates = replicates
			e.Spec.Execution.WashoutMS = 5000
			e.Spec.Control.Steps[1].Observe.WindowMS = 5000
			e.Spec.Treatment.Steps[1].Observe.WindowMS = 5000
			e.Spec.Limits.MaxPackets = 4 * replicates
			e.Spec.Limits.PacketsPerSecond = rate
			// Both SYNs and both potential RSTs reserve rate-gate time.
			bound := time.Duration(2*replicates)*(10*time.Second+2*time.Second/time.Duration(rate)) + 2*time.Second
			e.Spec.Limits.MaxDurationSeconds = int((bound + time.Second - 1) / time.Second)
			p, err := Compile(e, policy())
			if err != nil || p.MaxDurationMS != bound.Milliseconds() || p.MaxPackets != 4*replicates {
				t.Fatalf("incorrect cleanup reservation: %+v %v", p, err)
			}
			e.Spec.Limits.MaxDurationSeconds--
			if _, err := Compile(e, policy()); err == nil {
				t.Fatal("duration below cleanup reservation admitted")
			}
			e.Spec.Limits.MaxDurationSeconds++
			e.Spec.Limits.MaxPackets--
			if _, err := Compile(e, policy()); err == nil {
				t.Fatal("packet budget below cleanup reservation admitted")
			}
		}
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
