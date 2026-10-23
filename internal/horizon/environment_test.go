package horizon

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/horizon/model"
)

func loadExperiment(t *testing.T, path string) model.Experiment {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	e, err := dsl.Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func phase3Policy() model.Policy {
	return model.Policy{Profile: "lab", AllowTargets: []string{"192.0.2.0/24"}, AllowPorts: []uint16{443}}
}

func TestEnvironmentControlsExecuteAndReplay(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ file, scenario, conclusion string }{
		{"hz-002.yaml", "stable", "A/A control: no detectable SACK difference between identical arms"},
		{"hz-002.yaml", "sack", "A/A control: no detectable SACK difference between identical arms"},
		{"hz-001-environment.yaml", "sack", "SACK permission response differs between paired arms; causal explanation unresolved"},
		{"hz-001-environment.yaml", "stable", "no detectable difference in SACK permission"},
	} {
		t.Run(tc.file+"/"+tc.scenario, func(t *testing.T) {
			t.Parallel()
			environmentRun(t, tc.file, tc.scenario, tc.conclusion)
		})
	}
}

func environmentRun(t *testing.T, file, scenario, conclusion string) {
	t.Helper()
	e := loadExperiment(t, "../../lab/horizon/"+file)
	e.Spec.Execution.WashoutMS = 0
	e.Spec.Control.Steps[1].Observe.WindowMS = 10
	e.Spec.Treatment.Steps[1].Observe.WindowMS = 10
	sim, _ := NewSimulator(scenario)
	r, err := Run(context.Background(), e, phase3Policy(), testLink(), sim)
	sim.Close()
	if err != nil || !r.Completed || r.Environment == nil || r.Comparison.Conclusion != conclusion {
		t.Fatalf("%s/%s: %+v %v", file, scenario, r.Comparison, err)
	}
	env := r.Environment
	if env.Responses.References != 3 || env.Responses.ReferencesAnswered != 3 || len(env.GatingFlags) != 0 || env.Latency.PairedSamples != 12 || env.Latency.PairedLowerNS == nil {
		t.Fatalf("%s/%s environment: %+v", file, scenario, env)
	}
	want := []string{"ambient-load", "path-routing", "remote-state-reuse", "sequence-and-ip-id-tokens"}
	if len(env.Confounders) != len(want) {
		t.Fatal("confounders", env.Confounders)
	}
	for i := range want {
		if env.Confounders[i] != want[i] {
			t.Fatal("confounders", env.Confounders)
		}
	}
	if r.PacketsTX != 54 {
		t.Fatal("reference probes must share the packet budget", r.PacketsTX)
	}
	replayed := roundTrip(t, r)
	if replayed.Report.Environment.Carryover.PValue != env.Carryover.PValue {
		t.Fatal("replay changed the assessment")
	}
	tampered := r
	changed := *r.Environment
	changed.GatingFlags = []string{}
	changed.Responses.ReferencesAnswered = 2
	tampered.Environment = &changed
	sealed, _ := Seal(tampered)
	if _, err := Replay(bytes.NewReader(mustJSON(t, sealed))); err == nil {
		t.Fatal("tampered environment accepted after reseal")
	}
}

func TestEnvironmentGatesComparison(t *testing.T) {
	t.Parallel()
	e := loadExperiment(t, "../../lab/horizon/hz-001-environment.yaml")
	p, err := dsl.Compile(e, phase3Policy())
	if err != nil {
		t.Fatal(err)
	}
	r := model.Report{APIVersion: p.APIVersion, Experiment: p.Experiment, Completed: true}
	for i, planned := range p.Trials {
		options := []byte{2, 4, 5, 180}
		if planned.Arm == "treatment" {
			options = append(options, 4, 2, 0, 0)
		}
		f := model.Features{ResponseClass: "syn-ack", TCPOptions: options, RTTNS: int64(1e6 + i)}
		flags := []string{}
		if planned.Arm == "reference" && planned.Pair == 11 {
			f, flags = model.Features{ResponseClass: "no-response"}, []string{"timeout"}
		}
		r.Trials = append(r.Trials, model.Trial{Probe: planned.Probe, Pair: planned.Pair, Arm: planned.Arm, Features: f, QualityFlags: flags})
	}
	if c := Compare(r); c.Status != "inferred" {
		t.Fatal("legacy comparison without environment", c)
	}
	r.Environment = Assess(r)
	c := Compare(r)
	if c.Status != "unresolved" || c.Conclusion != "environmental quality gate: reference-loss" || c.TreatmentOnlySACK != 12 {
		t.Fatal("reference loss did not gate inference", c)
	}
}

func TestPhase3Admission(t *testing.T) {
	t.Parallel()
	e := loadExperiment(t, "../../lab/horizon/hz-002.yaml")
	plan, err := dsl.Compile(e, phase3Policy())
	if err != nil || len(plan.Trials) != 27 || plan.MaxPackets != 54 {
		t.Fatal("A/A plan", len(plan.Trials), plan.MaxPackets, err)
	}
	references := 0
	for _, trial := range plan.Trials {
		if trial.Arm == "reference" {
			references++
			if trial.Probe != dsl.ReferenceProbe || trial.Send.OptionsProfile != "baseline" || (trial.Pair+1)%4 != 0 {
				t.Fatal("reference probe placement", trial)
			}
		}
	}
	if references != 3 {
		t.Fatal("reference count", references)
	}
	for name, mutate := range map[string]func(*model.Experiment){
		"aa-sack":       func(e *model.Experiment) { e.Spec.Treatment.Steps[0].Send.OptionsProfile = "sack-permitted" },
		"aa-window":     func(e *model.Experiment) { e.Spec.Treatment.Steps[1].Observe.WindowMS = 200 },
		"confounder":    func(e *model.Experiment) { e.Spec.Confounders = []string{"magic"} },
		"duplicate":     func(e *model.Experiment) { e.Spec.Confounders = []string{"path-routing", "path-routing"} },
		"reference-big": func(e *model.Experiment) { e.Spec.Execution.ReferenceEvery = 13 },
		"reference-neg": func(e *model.Experiment) { e.Spec.Execution.ReferenceEvery = -1 },
		"budget":        func(e *model.Experiment) { e.Spec.Limits.MaxPackets = 48 },
	} {
		bad := loadExperiment(t, "../../lab/horizon/hz-002.yaml")
		mutate(&bad)
		if _, err := dsl.Compile(bad, phase3Policy()); err == nil {
			t.Fatal(name, "accepted")
		}
	}
	legacy := testExperiment(t)
	legacy.Spec.Confounders = []string{"ambient-load"}
	if _, err := dsl.Compile(legacy, testPolicy()); err == nil {
		t.Fatal("v1alpha1 accepted a v1alpha2 field")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStabilityIgnoresSACKAndPadding(t *testing.T) {
	t.Parallel()
	linux, windows := []byte{2, 4, 5, 180, 4, 2}, []byte{2, 4, 5, 180, 1, 1, 4, 2}
	if !bytes.Equal(withoutSACK(linux), []byte{2, 4, 5, 180}) || !bytes.Equal(withoutSACK(windows), []byte{2, 4, 5, 180}) {
		t.Fatal("SACK or padding retained")
	}
	if bytes.Equal(withoutSACK([]byte{2, 4, 5, 180, 3, 3, 8}), []byte{2, 4, 5, 180}) {
		t.Fatal("window scale change hidden")
	}
}
