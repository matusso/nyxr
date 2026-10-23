package horizon

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/horizon/model"
)

func crossPortPolicy() model.Policy {
	return model.Policy{Profile: "lab", Permissions: []string{"cross-port"}, AllowTargets: []string{"192.0.2.0/24"}, AllowPorts: []uint16{443, 8443, 9443}}
}

// fastRole shortens a study experiment for unit tests: 8 pairs, 20 ms
// windows and 300 ms washout, keeping the matched-wait structure.
func fastRole(t *testing.T, role string) model.Experiment {
	t.Helper()
	e := loadExperiment(t, "../../lab/horizon/cross-port/"+role+".yaml")
	e.Spec.Execution.Replicates, e.Spec.Execution.WashoutMS = 8, 300
	extra := 0
	for _, s := range e.Spec.Treatment.Steps {
		if s.Observe != nil {
			s.Observe.WindowMS = 20
		}
		if s.Wait != nil {
			s.Wait.DurationMS = 300
			extra = 300
		}
	}
	e.Spec.Control.Steps[0].Wait.DurationMS = 20 + extra
	e.Spec.Control.Steps[2].Observe.WindowMS = 20
	if _, err := dsl.Compile(e, crossPortPolicy()); err != nil {
		t.Fatal(role, err)
	}
	return e
}

func runStudy(t *testing.T, scenario string, roles ...string) model.CrossPortStudy {
	t.Helper()
	type result struct {
		role   string
		report model.Report
	}
	results := make(chan result, len(roles))
	for _, role := range roles {
		go func() {
			sim, _ := NewSimulator(scenario)
			defer sim.Close()
			r, err := Run(context.Background(), fastRole(t, role), crossPortPolicy(), testLink(), sim)
			if err != nil {
				t.Error(role, err)
			}
			results <- result{role, r}
		}()
	}
	reports := map[string]model.Report{}
	for range roles {
		r := <-results
		roundTrip(t, r.report)
		reports[r.role] = r.report
	}
	s, err := AnalyzeCrossPort(reports)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCrossPortStudiesDiscriminateSyntheticLimiters(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		scenario, class string
		roles           []string
	}{
		{"shared-limit", "shared-state", []string{RoleMain, RoleSamePort, RoleTimeSeparated, RoleReverse, RoleNull}},
		{"port-limit", "per-port-state", []string{RoleMain, RoleSamePort}},
		{"stable", "no-coupling", []string{RoleMain, RoleSamePort}},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			t.Parallel()
			s := runStudy(t, tc.scenario, tc.roles...)
			if s.Classification != tc.class || s.IsolatedClassification != "no-coupling" {
				t.Fatalf("%s: %+v", tc.scenario, s)
			}
			if tc.class != "shared-state" {
				if len(s.Candidates) != 0 {
					t.Fatal("candidate without cross-port dependence")
				}
				return
			}
			c := s.Candidates[0]
			if c.Direction != "symmetric" || !slices.Equal(c.Subjects, []string{"tcp/443", "tcp/8443"}) || !slices.Equal(c.OrthogonalSignals, []string{"cooldown"}) || len(c.Alternatives) != 4 || len(c.Evidence) != 5 {
				t.Fatalf("candidate: %+v", c)
			}
			if c.Hypotheses[0].Family != "rate-limiter" || c.Hypotheses[0].Status != "hypothesis" || c.Hypotheses[0].Location != "endpoint-or-path-unresolved" || c.Hypotheses[0].Probability != nil {
				t.Fatalf("rate limiter hypothesis: %+v", c.Hypotheses)
			}
			main := s.Roles[0]
			if main.Suppressed != 8 || main.ControlAnswered.Estimate != 1 || main.TreatmentAnswered.Upper > 0.37 {
				t.Fatalf("main effect: %+v", main)
			}
		})
	}
}

// syntheticStudyReport fills a compiled precondition plan without traffic.
func syntheticStudyReport(t *testing.T, role string, answer func(model.PlannedTrial) (bool, uint8)) model.Report {
	t.Helper()
	plan, err := dsl.Compile(fastRole(t, role), crossPortPolicy())
	if err != nil {
		t.Fatal(err)
	}
	r := model.Report{APIVersion: plan.APIVersion, Experiment: plan.Experiment, ExperimentHash: plan.Hash, RunID: role, Completed: true}
	for _, p := range plan.Trials {
		tr := model.Trial{Probe: p.Probe, Pair: p.Pair, Arm: p.Arm, SentAt: time.Unix(1, 0), QualityFlags: []string{}, Features: model.Features{ResponseClass: "no-response"}}
		if ok, ttl := answer(p); ok {
			tr.Features = model.Features{ResponseClass: "syn-ack", TTL: ttl, RTTNS: 1e6}
		} else {
			tr.QualityFlags = []string{"timeout"}
		}
		r.Trials = append(r.Trials, tr)
	}
	r.Environment = Assess(r)
	r.Comparison = Compare(r)
	return r
}

func TestCrossPortAnalysisRules(t *testing.T) {
	t.Parallel()
	all := func(model.PlannedTrial) (bool, uint8) { return true, 64 }
	suppress := func(p model.PlannedTrial) (bool, uint8) { return !(p.Arm == "treatment" && p.Probe == 1), 64 }
	if r := syntheticStudyReport(t, RoleMain, suppress); r.Comparison.Status != "inferred" || r.Comparison.ControlOnly != 8 || r.Comparison.Metric != "measurement-answered" {
		t.Fatalf("precondition comparison: %+v", r.Comparison)
	}
	study := func(reports map[string]model.Report) model.CrossPortStudy {
		s, err := AnalyzeCrossPort(reports)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	// The null control shows the same dependence: not specific to the ports.
	s := study(map[string]model.Report{RoleMain: syntheticStudyReport(t, RoleMain, suppress), RoleNull: syntheticStudyReport(t, RoleNull, suppress)})
	if s.Classification != "unresolved" || len(s.Candidates) != 0 {
		t.Fatalf("null effect must leave the study unresolved: %+v", s)
	}
	// Without an orthogonal signal no infrastructure hypothesis is elevated.
	s = study(map[string]model.Report{RoleMain: syntheticStudyReport(t, RoleMain, suppress)})
	if s.Classification != "shared-state" || s.Candidates[0].Direction != "untested" {
		t.Fatalf("main only: %+v", s)
	}
	for _, h := range s.Candidates[0].Hypotheses {
		if h.Status != "not-elevated" {
			t.Fatalf("elevated without orthogonal signal: %+v", h)
		}
	}
	// Precondition replies from a different hop count are a path signal.
	ttl := func(p model.PlannedTrial) (bool, uint8) {
		if p.Arm == "treatment" && p.Probe == 0 {
			return true, 63
		}
		return suppress(p)
	}
	s = study(map[string]model.Report{RoleMain: syntheticStudyReport(t, RoleMain, ttl)})
	if !slices.Equal(s.Candidates[0].OrthogonalSignals, []string{"ttl-divergence"}) || s.Candidates[0].Hypotheses[1].Status != "hypothesis" || s.Candidates[0].Hypotheses[1].Location != "path" {
		t.Fatalf("ttl divergence: %+v", s.Candidates[0])
	}
	// No dependence anywhere, but the same-port control is missing.
	s = study(map[string]model.Report{RoleMain: syntheticStudyReport(t, RoleMain, all)})
	if s.Classification != "unresolved" {
		t.Fatal("missing same-port control resolved", s)
	}
	// One lost measurement leaves the role complete (timeouts are outcomes),
	// but a broken precondition removes its pair and the role is unresolved.
	broken := syntheticStudyReport(t, RoleMain, suppress)
	broken.Trials[0].QualityFlags = append(broken.Trials[0].QualityFlags, "receive-failed")
	broken.Comparison = Compare(broken)
	if broken.Comparison.Status != "unresolved" {
		t.Fatal("broken pair accepted", broken.Comparison)
	}
	for name, reports := range map[string]map[string]model.Report{
		"no main":      {RoleSamePort: syntheticStudyReport(t, RoleSamePort, all)},
		"swapped role": {RoleMain: syntheticStudyReport(t, RoleSamePort, all)},
		"bad same":     {RoleMain: syntheticStudyReport(t, RoleMain, all), RoleSamePort: syntheticStudyReport(t, RoleMain, all)},
		"bad timed":    {RoleMain: syntheticStudyReport(t, RoleMain, all), RoleTimeSeparated: syntheticStudyReport(t, RoleMain, all)},
		"bad reverse":  {RoleMain: syntheticStudyReport(t, RoleMain, all), RoleReverse: syntheticStudyReport(t, RoleNull, all)},
		"unknown":      {RoleMain: syntheticStudyReport(t, RoleMain, all), "other": syntheticStudyReport(t, RoleMain, all)},
	} {
		if _, err := AnalyzeCrossPort(reports); err == nil {
			t.Fatal(name, "accepted")
		}
	}
}

func TestPreconditionAdmission(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*model.Experiment){
		"unmatched wait":    func(e *model.Experiment) { e.Spec.Control.Steps[0].Wait.DurationMS = 50 },
		"sack precondition": func(e *model.Experiment) { e.Spec.Treatment.Steps[0].Send.OptionsProfile = "sack-permitted" },
		"different measure": func(e *model.Experiment) { e.Spec.Treatment.Steps[2].Send.DstPort = 8443 },
		"no precondition":   func(e *model.Experiment) { e.Spec.Treatment.Steps = e.Spec.Treatment.Steps[2:] },
		"window":            func(e *model.Experiment) { e.Spec.Treatment.Steps[3].Observe.WindowMS = 200 },
	} {
		e := loadExperiment(t, "../../lab/horizon/cross-port/main.yaml")
		mutate(&e)
		if _, err := dsl.Compile(e, crossPortPolicy()); err == nil {
			t.Fatal(name, "accepted")
		}
	}
	e := loadExperiment(t, "../../lab/horizon/cross-port/main.yaml")
	if _, err := dsl.Compile(e, model.Policy{Profile: "lab", AllowTargets: []string{"192.0.2.0/24"}, AllowPorts: []uint16{443, 8443}}); err == nil {
		t.Fatal("cross-port precondition admitted without independent permission")
	}
}
