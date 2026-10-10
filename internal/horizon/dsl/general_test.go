package dsl

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"reflect"
	"testing"

	"github.com/matusso/nyxr/internal/horizon/model"
)

func generalExample(t testing.TB) model.Experiment {
	t.Helper()
	b, err := os.ReadFile("../../../lab/horizon/sequence-v1alpha2.yaml")
	if err != nil {
		t.Fatal(err)
	}
	e, err := Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func generalPolicy() model.Policy {
	return model.Policy{Profile: "lab", AllowTargets: []string{"192.0.2.0/24"}, AllowPorts: []uint16{443, 8443}, Permissions: []string{"cross-port"}}
}
func TestGeneralPlanAndWireCompatibility(t *testing.T) {
	e := generalExample(t)
	p, err := Compile(e, generalPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if p.MaxPackets != 24 || len(p.Trials) != 12 || p.MaxMemoryBytes != 2097152 || p.MaxReceiveFrames != 12*4097 || p.MaxEvidenceFrames != 12*19 || p.MaxConcurrentFlows != 1 {
		t.Fatalf("bounds: %+v", p)
	}
	for i, probe := range p.Trials {
		if probe.Probe != i%3 || probe.Cleanup == "" || probe.OptionsHex == "" || probe.Send == nil {
			t.Fatal("exact probe plan missing")
		}
		port := uint16(443)
		if probe.Probe == 2 {
			port = 8443
		}
		if probe.Send.DstPort != port || (probe.Probe > 0 && probe.WaitBeforeMS != 5) {
			t.Fatal("expansion changed ports/waits")
		}
	}
	b, _ := json.Marshal(e)
	parsed, err := Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	again, err := Compile(parsed, generalPolicy())
	if err != nil || !reflect.DeepEqual(p, again) {
		t.Fatal("JSON/YAML or deterministic identity changed", err)
	}
	legacy := example(t)
	old, err := Compile(legacy, policy())
	if err != nil || old.Hash != "0a31ee4dd0e9cbe49df5807d083b9ae5d5f59eef477d193632457c9d4964d424" {
		t.Fatal("v1alpha1 identity changed", err, old.Hash)
	}
	legacy.Spec.Control.Steps = append(legacy.Spec.Control.Steps, model.Step{Wait: &model.Wait{DurationMS: 0}})
	if _, err := Compile(legacy, policy()); err == nil {
		t.Fatal("v1alpha1 acquired general primitives")
	}
}
func TestGeneralAdmission(t *testing.T) {
	cases := map[string]func(*model.Experiment, *model.Policy){
		"no profile":          func(e *model.Experiment, p *model.Policy) { p.Profile = "" },
		"unknown profile":     func(e *model.Experiment, p *model.Policy) { p.Profile = "unknown" },
		"no permission":       func(e *model.Experiment, p *model.Policy) { p.Permissions = nil },
		"self authorization":  func(e *model.Experiment, p *model.Policy) { p.AllowPorts = []uint16{443} },
		"unknown permission":  func(e *model.Experiment, p *model.Policy) { p.Permissions = append(p.Permissions, "disruptive") },
		"fragile cross port":  func(e *model.Experiment, p *model.Policy) { p.Profile = "fragile" },
		"ot cross port":       func(e *model.Experiment, p *model.Policy) { p.Profile = "ot-restricted" },
		"missing declaration": func(e *model.Experiment, p *model.Policy) { e.Spec.CrossPort = false },
		"duplicate port":      func(e *model.Experiment, p *model.Policy) { e.Spec.Scope.TCPPorts[1] = 443 },
		"zero port":           func(e *model.Experiment, p *model.Policy) { e.Spec.Scope.TCPPorts[1] = 0 },
		"disruptive reset":    func(e *model.Experiment, p *model.Policy) { e.Spec.Control.Steps[1].Send.Flags = []string{"RST"} },
		"unknown payload":     func(e *model.Experiment, p *model.Policy) { e.Spec.Control.Steps[1].Send.OptionsProfile = "malformed" },
		"mixed primitive":     func(e *model.Experiment, p *model.Policy) { e.Spec.Control.Steps[0].Wait = &model.Wait{DurationMS: 10} },
		"repeat overflow":     func(e *model.Experiment, p *model.Policy) { e.Spec.Control.Steps[0].Repeat.Count = math.MaxInt },
		"zero repeat":         func(e *model.Experiment, p *model.Policy) { e.Spec.Control.Steps[0].Repeat.Count = 0 },
		"unbounded expansion": func(e *model.Experiment, p *model.Policy) {
			e.Spec.Control.Steps[0].Repeat.Count = 16
			e.Spec.Control.Steps[0].Repeat.Steps = []model.Step{e.Spec.Treatment.Steps[0]}
		},
		"observe without send": func(e *model.Experiment, p *model.Policy) {
			e.Spec.Control.Steps = []model.Step{{Observe: &model.Observe{WindowMS: 10}}}
		},
		"changed window":       func(e *model.Experiment, p *model.Policy) { e.Spec.Control.Steps[2].Observe.WindowMS = 11 },
		"changed port":         func(e *model.Experiment, p *model.Policy) { e.Spec.Control.Steps[1].Send.DstPort = 443 },
		"insufficient packets": func(e *model.Experiment, p *model.Policy) { e.Spec.Limits.MaxPackets-- },
		"deadline":             func(e *model.Experiment, p *model.Policy) { e.Spec.Limits.MaxDurationSeconds = 1 },
		"memory":               func(e *model.Experiment, p *model.Policy) { e.Spec.Limits.MaxMemoryBytes-- },
		"receive":              func(e *model.Experiment, p *model.Policy) { e.Spec.Limits.MaxReceiveFrames = 0 },
		"capture":              func(e *model.Experiment, p *model.Policy) { e.Spec.Capture.MaxBytes = math.MaxInt },
		"concurrency":          func(e *model.Experiment, p *model.Policy) { e.Spec.Limits.MaxConcurrentFlows = 2 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			e, p := generalExample(t), generalPolicy()
			change(&e, &p)
			if _, err := Compile(e, p); err == nil {
				t.Fatal("unsafe plan admitted")
			}
		})
	}
}
func TestProfileCeilings(t *testing.T) {
	for _, prof := range Profiles() {
		t.Run(prof.Name, func(t *testing.T) {
			e, p := example(t), policy()
			p.Profile = prof.Name
			e.Spec.Execution.Replicates = 2
			e.Spec.Limits.MaxPackets = 8
			e.Spec.Limits.PacketsPerSecond = prof.PacketsPerSecond
			e.Spec.Capture.MaxBytes = prof.MaxCaptureBytes
			e.Spec.Limits.MaxDurationSeconds = 30
			if _, err := Compile(e, p); err != nil {
				t.Fatal(err)
			}
			e.Spec.Limits.MaxPackets = prof.MaxPackets + 1
			if _, err := Compile(e, p); err == nil {
				t.Fatal("packet ceiling bypassed")
			}
			e.Spec.Limits.MaxPackets = 8
			e.Spec.Limits.PacketsPerSecond = prof.PacketsPerSecond + 1
			if _, err := Compile(e, p); err == nil {
				t.Fatal("rate ceiling bypassed")
			}
			e.Spec.Limits.PacketsPerSecond = prof.PacketsPerSecond
			e.Spec.Capture.MaxBytes = prof.MaxCaptureBytes + 1
			if _, err := Compile(e, p); err == nil {
				t.Fatal("capture ceiling bypassed")
			}
		})
	}
}
func FuzzSequenceBounds(f *testing.F) {
	f.Add(2, 2, 10, 4096, 2097152, 1, 20, 1048576, 0)
	f.Add(1, 2, 1, 1, 1052672, 1, 30, 4096, 4)
	f.Add(math.MaxInt, math.MaxInt, math.MaxInt, math.MaxInt, math.MaxInt, math.MaxInt, math.MaxInt, math.MaxInt, 8)
	f.Fuzz(func(t *testing.T, count, reps, rate, receive, memory, concurrency, duration, capture, depth int) {
		e, p := generalExample(t), generalPolicy()
		e.Spec.Control.Steps[0].Repeat.Count = count
		e.Spec.Treatment.Steps[0].Repeat.Count = count
		// Bound construction itself for arbitrary fuzz input, including overflow.
		if depth < 0 || depth > 8 {
			return
		}
		for i := 0; i < depth; i++ {
			e.Spec.Control.Steps = []model.Step{{Repeat: &model.Repeat{Count: 1, Steps: e.Spec.Control.Steps}}}
			e.Spec.Treatment.Steps = []model.Step{{Repeat: &model.Repeat{Count: 1, Steps: e.Spec.Treatment.Steps}}}
		}
		e.Spec.Execution.Replicates = reps
		e.Spec.Limits.MaxPackets = 200
		e.Spec.Limits.PacketsPerSecond = rate
		e.Spec.Limits.MaxReceiveFrames = receive
		e.Spec.Limits.MaxMemoryBytes = memory
		e.Spec.Limits.MaxConcurrentFlows = concurrency
		e.Spec.Limits.MaxDurationSeconds = duration
		e.Spec.Capture.MaxBytes = capture
		plan, err := Compile(e, p)
		if err != nil {
			return
		}
		if plan.MaxPackets > e.Spec.Limits.MaxPackets || len(plan.Trials)*2 != plan.MaxPackets || plan.MaxDurationMS > int64(duration)*1000 || plan.MaxMemoryBytes > memory || plan.MaxMemoryBytes < capture || plan.MaxReceiveFrames != len(plan.Trials)*(receive+1) || plan.MaxConcurrentFlows != 1 || plan.MaxEvidenceFrames > 1900 {
			t.Fatal("resource invariant bypassed")
		}
	})
}

func TestNestedWireDepthMatchesAdmission(t *testing.T) {
	e := generalExample(t)
	for i := 0; i < MaxRepeatDepth-1; i++ {
		e.Spec.Control.Steps = []model.Step{{Repeat: &model.Repeat{Count: 1, Steps: e.Spec.Control.Steps}}}
		e.Spec.Treatment.Steps = []model.Step{{Repeat: &model.Repeat{Count: 1, Steps: e.Spec.Treatment.Steps}}}
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal("document parser rejected allowed nesting", err)
	}
	if _, err := Compile(parsed, generalPolicy()); err != nil {
		t.Fatal(err)
	}
	e.Spec.Control.Steps = []model.Step{{Repeat: &model.Repeat{Count: 1, Steps: e.Spec.Control.Steps}}}
	if _, err := Compile(e, generalPolicy()); err == nil {
		t.Fatal("excess repeat depth admitted")
	}
}
