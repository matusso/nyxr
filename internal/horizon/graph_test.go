package horizon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/horizon/model"
)

func simulated(t *testing.T, file, scenario string) model.Envelope {
	t.Helper()
	e := loadExperiment(t, "../../lab/horizon/"+file)
	e.Spec.Execution.WashoutMS, e.Spec.Limits.PacketsPerSecond = 0, 10
	e.Spec.Control.Steps[len(e.Spec.Control.Steps)-1].Observe.WindowMS = 10
	e.Spec.Treatment.Steps[len(e.Spec.Treatment.Steps)-1].Observe.WindowMS = 10
	sim, _ := NewSimulator(scenario)
	defer sim.Close()
	r, err := Run(context.Background(), e, phase3Policy(), testLink(), sim)
	sealed, sealErr := Seal(r)
	if err = errors.Join(err, sealErr); err != nil {
		t.Error(err) // may run in a helper goroutine: never FailNow here
	}
	return sealed
}

func hypothesis(t *testing.T, g model.Graph, family string) model.GraphHypothesis {
	t.Helper()
	for _, h := range g.Hypotheses {
		if h.Family == family {
			return h
		}
	}
	t.Fatalf("no %s hypothesis in %+v", family, g.Hypotheses)
	return model.GraphHypothesis{}
}

func TestGraphHypothesesProvenanceAndDecay(t *testing.T) {
	t.Parallel()
	var sack, stable, aa model.Envelope
	done := make(chan struct{}, 3)
	for _, run := range []struct {
		out            *model.Envelope
		file, scenario string
	}{{&sack, "hz-001.yaml", "sack"}, {&stable, "hz-001.yaml", "stable"}, {&aa, "hz-002.yaml", "stable"}} {
		go func() { *run.out = simulated(t, run.file, run.scenario); done <- struct{}{} }()
	}
	for range 3 {
		<-done
	}
	if t.Failed() {
		t.FailNow()
	}
	now := sack.Report.FinishedAt.Add(time.Minute)
	build := func(in GraphInput) model.Graph {
		t.Helper()
		if in.Now.IsZero() {
			in.Now = now
		}
		if in.TTL == 0 {
			in.TTL = time.Hour
		}
		g, err := BuildGraph(in)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	g := build(GraphInput{Reports: []model.Envelope{sack, aa}})
	h := hypothesis(t, g, "endpoint-stack")
	if h.Status != "supported" || h.Statement != "inferred" || h.Probability != nil || h.ObservationGrade != "good" || !slices.Equal(h.Support, []string{runNode(sack.Report)}) || h.Subject != "192.0.2.10/tcp/443" {
		t.Fatalf("supported SACK hypothesis: %+v", h)
	}
	if !slices.Equal(g.NotEvaluated, []string{"firewall-tracking", "nat-state", "proxy", "load-balancer", "rate-limiter"}) || g.Coverage.FullTCPCoverage || len(g.Contradictions) != 0 {
		t.Fatalf("graph scope: %+v %+v", g.NotEvaluated, g.Coverage)
	}
	trials := 0
	for _, n := range g.Nodes {
		if n.Type == "trial" && strings.HasPrefix(n.ID, "trial:"+sack.Report.RunID) {
			trials++
		}
	}
	if trials != len(sack.Report.Trials) {
		t.Fatal("trial provenance missing", trials)
	}
	text, err := ExplainHypothesis(g, h.ID)
	if err != nil || !strings.Contains(text, sack.SHA256) || !strings.Contains(text, sack.Report.ExperimentHash) || !strings.Contains(text, "Probability: none") {
		t.Fatalf("explain: %v\n%s", err, text)
	}
	// Saved graphs round-trip strictly and reject unlinked hypotheses.
	blob, _ := json.Marshal(g)
	if _, err := LoadGraph(bytes.NewReader(blob)); err != nil {
		t.Fatal(err)
	}
	bad := g
	bad.Hypotheses = slices.Clone(g.Hypotheses)
	bad.Hypotheses[0].Support, bad.Hypotheses[0].Against = []string{"run:missing"}, nil
	if ValidateGraph(bad) == nil {
		t.Fatal("hypothesis linked to a missing run accepted")
	}
	p := 0.9
	bad.Hypotheses[0].Support, bad.Hypotheses[0].Probability = g.Hypotheses[0].Support, &p
	if ValidateGraph(bad) == nil {
		t.Fatal("uncalibrated probability accepted")
	}

	// Disagreeing runs are a contradiction and stay unresolved.
	g = build(GraphInput{Reports: []model.Envelope{sack, stable}})
	if h := hypothesis(t, g, "endpoint-stack"); h.Status != "unresolved" || len(g.Contradictions) != 1 || len(h.Support) != 1 || len(h.Against) != 1 {
		t.Fatalf("contradiction: %+v %+v", h, g.Contradictions)
	}
	// An A/A difference on the host leaves its hypotheses unresolved.
	unstable := aa
	unstable.Report.RunID = "aa-unstable"
	unstable.Report.Comparison.Status, unstable.Report.Comparison.PValue = "inferred", 0.001
	g = build(GraphInput{Reports: []model.Envelope{sack, unstable}})
	if h := hypothesis(t, g, "endpoint-stack"); h.Status != "unresolved" || !slices.Contains(h.Against, "run:aa-unstable") {
		t.Fatalf("A/A instability: %+v", h)
	}
	// Confidence decays with age and after declared or detected changes.
	if h := hypothesis(t, build(GraphInput{Reports: []model.Envelope{sack}, Now: now.Add(2 * time.Hour)}), "endpoint-stack"); h.Status != "stale" {
		t.Fatal("expired evidence not stale", h)
	}
	change := []model.ChangeEvent{{At: now.Add(-time.Second), Scope: "host:192.0.2.10", Detail: "maintenance"}}
	if h := hypothesis(t, build(GraphInput{Reports: []model.Envelope{sack}, Changes: change}), "endpoint-stack"); h.Status != "stale" {
		t.Fatal("declared host change ignored", h)
	}
	other := []model.ChangeEvent{{At: now.Add(-time.Second), Scope: "host:192.0.2.99"}}
	if h := hypothesis(t, build(GraphInput{Reports: []model.Envelope{sack}, Changes: other}), "endpoint-stack"); h.Status != "supported" {
		t.Fatal("unrelated host change applied", h)
	}
	moved := sack
	moved.Report.RunID = "after-path-change"
	moved.Report.StartedAt = sack.Report.FinishedAt.Add(time.Second)
	moved.Report.FinishedAt = moved.Report.StartedAt.Add(time.Second)
	moved.Report.Trials = slices.Clone(sack.Report.Trials)
	for i := range moved.Report.Trials {
		moved.Report.Trials[i].Features.TTL = 61
	}
	g = build(GraphInput{Reports: []model.Envelope{sack, moved}, Now: moved.Report.FinishedAt.Add(time.Second)})
	h = hypothesis(t, g, "endpoint-stack")
	if len(g.Changes) != 1 || g.Changes[0].Source != "detected" || h.Status != "supported" || !slices.Equal(h.Support, []string{"run:after-path-change"}) || !slices.Contains(h.Against, runNode(sack.Report)) {
		t.Fatalf("detected change: %+v %+v", g.Changes, h)
	}
	for _, bad := range []GraphInput{{}, {Reports: []model.Envelope{sack}, Now: now}, {Reports: []model.Envelope{sack, sack}, Now: now, TTL: time.Hour},
		{Reports: []model.Envelope{sack}, Now: now, TTL: time.Hour, Changes: []model.ChangeEvent{{At: now, Scope: "galaxy"}}}} {
		if _, err := BuildGraph(bad); err == nil {
			t.Fatal("invalid graph input accepted")
		}
	}
}

func TestGraphCrossPortConfoundedLocation(t *testing.T) {
	t.Parallel()
	suppress := func(p model.PlannedTrial) (bool, uint8) { return !(p.Arm == "treatment" && p.Probe == 1), 64 }
	all := func(model.PlannedTrial) (bool, uint8) { return true, 64 }
	study := func(name string, main func(model.PlannedTrial) (bool, uint8)) map[string]model.Envelope {
		out := map[string]model.Envelope{}
		for role, answer := range map[string]func(model.PlannedTrial) (bool, uint8){RoleMain: main, RoleSamePort: suppress, RoleTimeSeparated: all} {
			r := syntheticStudyReport(t, role, answer)
			r.RunID, r.StartedAt, r.FinishedAt = name+"-"+role, time.Unix(90, 0), time.Unix(100, 0)
			out[role], _ = Seal(r)
		}
		return out
	}
	// Endpoint-hosted and path-hosted limiters produce the same observations.
	g, err := BuildGraph(GraphInput{Studies: []map[string]model.Envelope{study("endpoint", suppress), study("path", suppress)}, Now: time.Unix(200, 0), TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	shared, limiter, tracking := hypothesis(t, g, "shared-state"), hypothesis(t, g, "rate-limiter"), hypothesis(t, g, "firewall-tracking")
	if shared.Status != "supported" || shared.Subject != "192.0.2.10/tcp/{443,8443}" || len(shared.Support) != 2 || len(shared.Alternatives) != 4 {
		t.Fatalf("shared state: %+v", shared)
	}
	if limiter.Status != "supported" || limiter.Statement != "hypothesis" || limiter.Location != "endpoint-or-path-unresolved" || limiter.Probability != nil {
		t.Fatalf("rate limiter: %+v", limiter)
	}
	if tracking.Status != "unresolved" || tracking.Location != "endpoint-or-path-unresolved" {
		t.Fatalf("firewall tracking must stay unresolved without a path signal: %+v", tracking)
	}
	controls := 0
	for _, e := range g.Edges {
		if strings.HasPrefix(e.Relation, "control-for:") {
			controls++
		}
	}
	if controls != 4 || !slices.Equal(g.NotEvaluated, []string{"endpoint-stack", "nat-state", "proxy", "load-balancer"}) {
		t.Fatalf("controls %d, not evaluated %v", controls, g.NotEvaluated)
	}
	// A study without dependence contradicts one with it.
	g, err = BuildGraph(GraphInput{Studies: []map[string]model.Envelope{study("endpoint", suppress), study("none", all)}, Now: time.Unix(200, 0), TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if h := hypothesis(t, g, "shared-state"); h.Status != "unresolved" || len(g.Contradictions) != 1 {
		t.Fatalf("contradicting studies: %+v", h)
	}
}
