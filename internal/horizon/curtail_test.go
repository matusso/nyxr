package horizon

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/horizon/model"
)

func TestCurtailDecisionIsExact(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		control, treatment, remaining int
		want                          string
	}{
		{10, 0, 2, "significant"},    // 10 vs 2 at worst: p = 0.039
		{9, 0, 3, ""},                // 9 vs 3 at worst: p = 0.146
		{0, 0, 4, "not-significant"}, // at most 4 discordant pairs: p >= 0.125
		{0, 0, 5, "not-significant"}, // 5 discordant pairs reach only p = 0.0625
		{0, 0, 6, ""},                // 6 discordant pairs reach p = 0.031
		{0, 0, 0, "not-significant"},
		{6, 0, 0, "significant"},
		{3, 3, 1, "not-significant"},
	} {
		if got := CurtailDecision(tc.control, tc.treatment, tc.remaining); got != tc.want {
			t.Errorf("%+v: got %q", tc, got)
		}
	}
	// Exactness: whenever a decision is returned, every completion agrees.
	for c := 0; c <= 12; c++ {
		for d := 0; c+d <= 12; d++ {
			for r := 0; c+d+r <= 14; r++ {
				decision := CurtailDecision(c, d, r)
				if decision == "" {
					continue
				}
				for x := 0; x <= r; x++ {
					for y := 0; x+y <= r; y++ {
						if (signTest(c+x, d+y) <= 0.05) != (decision == "significant") {
							t.Fatalf("(%d,%d,%d) decided %s but completion (%d,%d) disagrees", c, d, r, decision, x, y)
						}
					}
				}
			}
		}
	}
}

func curtailedRole(t *testing.T, scenario string) model.Report {
	t.Helper()
	e := fastRole(t, RoleMain)
	e.Spec.Execution.Replicates, e.Spec.Execution.StopRule = 12, "curtail"
	e.Spec.Limits.MaxPackets, e.Spec.Limits.MaxDurationSeconds = 200, 120
	if _, err := dsl.Compile(e, crossPortPolicy()); err != nil {
		t.Fatal(err)
	}
	sim, _ := NewSimulator(scenario)
	defer sim.Close()
	r, err := Run(context.Background(), e, crossPortPolicy(), testLink(), sim)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The synthetic limiter is time-based, so under load a pair can escape
// suppression: assert the curtailment invariants, not one exact pair count.
func TestCurtailedRunsStopEarlyAndReplay(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		scenario, decision string
		minPairs           int // earliest pair at which this decision can be exact
		significant        bool
	}{
		{"shared-limit", "significant", 10, true},
		{"stable", "not-significant", MinCurtailPairs, false},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			t.Parallel()
			r := curtailedRole(t, tc.scenario)
			c := r.Curtailment
			if c == nil || c.Pairs < tc.minPairs || c.Pairs >= r.Experiment.Spec.Execution.Replicates || c.Decision != tc.decision || !r.Completed {
				t.Fatalf("curtailment %+v completed %v", c, r.Completed)
			}
			if r.Comparison.Status != "inferred" || (r.Comparison.PValue <= 0.05) != tc.significant || r.Comparison.CompletePairs != c.Pairs {
				t.Fatalf("comparison %+v", r.Comparison)
			}
			roundTrip(t, r) // replay also proves the stop was the first decisive pair
			effect, err := roleEffect(RoleMain, r)
			if err != nil || effect.Significant != tc.significant || effect.CompletePairs != c.Pairs {
				t.Fatalf("effect %+v %v", effect, err)
			}
		})
	}
}

func TestReplayRejectsUnsupportedCurtailment(t *testing.T) {
	t.Parallel()
	r := curtailedRole(t, "shared-limit")
	// Drop the last pair and claim the stop came one pair earlier.
	tampered := r
	tampered.Curtailment = &model.Curtailment{Rule: CurtailRule, Pairs: r.Curtailment.Pairs - 1, Decision: "significant"}
	var kept []model.Trial
	for _, trial := range r.Trials {
		if trial.Pair < tampered.Curtailment.Pairs {
			kept = append(kept, trial)
		}
	}
	tampered.Trials = kept
	if err := verifyCurtailment(tampered); err == nil {
		t.Fatal("unsupported curtailment accepted")
	}
	// A curtail-rule run that kept going past the first decisive pair.
	late := r
	late.Curtailment = &model.Curtailment{Rule: CurtailRule, Pairs: r.Curtailment.Pairs + 1, Decision: "significant"}
	if err := verifyCurtailment(late); err == nil {
		t.Fatal("late curtailment accepted")
	}
	envelope, err := Seal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(envelope)
	if _, err := Replay(bytes.NewReader(b)); err == nil {
		t.Fatal("replay accepted tampered curtailment")
	}
}

func TestStopRuleRequiresPrecondition(t *testing.T) {
	t.Parallel()
	e := loadExperiment(t, "../../lab/horizon/hz-002.yaml")
	e.Spec.Execution.StopRule = "curtail"
	if _, err := dsl.Compile(e, model.Policy{Profile: "lab", AllowTargets: e.Spec.Scope.Targets, AllowPorts: e.Spec.Scope.TCPPorts}); err == nil {
		t.Fatal("curtailment admitted for a non-precondition experiment")
	}
}

func TestRetroCurtailMatchesLiveCurtailment(t *testing.T) {
	t.Parallel()
	for _, scenario := range []string{"shared-limit", "stable"} {
		e := fastRole(t, RoleMain)
		e.Spec.Execution.Replicates = 12
		e.Spec.Limits.MaxPackets, e.Spec.Limits.MaxDurationSeconds = 200, 120
		sim, _ := NewSimulator(scenario)
		full, err := Run(context.Background(), e, crossPortPolicy(), testLink(), sim)
		sim.Close()
		if err != nil {
			t.Fatal(err)
		}
		// Retro curtailment obeys the same rule a live run is replayed under.
		retro := RetroCurtail(full)
		if retro.Curtailment == nil || verifyCurtailment(retro) != nil || retro.PacketsTX >= full.PacketsTX || retro.Comparison.CompletePairs != retro.Curtailment.Pairs {
			t.Fatalf("%s: retro %+v %+v", scenario, retro.Curtailment, retro.Comparison)
		}
		// Exactness: the curtailed decision equals the full run's decision.
		if (retro.Comparison.PValue <= 0.05) != (full.Comparison.PValue <= 0.05) || retro.Comparison.Status != full.Comparison.Status {
			t.Fatalf("%s: curtailed decision differs from the full run", scenario)
		}
		// An independent live curtailed run reaches the same decision.
		if live := curtailedRole(t, scenario); live.Curtailment == nil || live.Curtailment.Decision != retro.Curtailment.Decision {
			t.Fatalf("%s: live %+v, retro %+v", scenario, live.Curtailment, retro.Curtailment)
		}
	}
}

func TestCurtailedReportWithCaptureResetReplaysUnresolved(t *testing.T) {
	t.Parallel()
	r := curtailedRole(t, "shared-limit")
	for i := range r.Trials {
		r.Trials[i].QualityFlags = append(slices.Clone(r.Trials[i].QualityFlags), "capture-stats-reset")
	}
	r.Environment = Assess(r)
	r.Comparison = Compare(r)
	if err := verifyCurtailment(r); err != nil {
		t.Fatalf("post-run flag broke curtailment verification: %v", err)
	}
	if r.Comparison.Status != "unresolved" {
		t.Fatalf("capture reset must leave the comparison unresolved: %+v", r.Comparison)
	}
}
