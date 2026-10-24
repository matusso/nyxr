package horizon

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/horizon/model"
)

var (
	simMu      sync.Mutex
	simReports = map[string]map[string]model.Report{}
)

// scenarioReports runs every study role once per scenario and caches them.
func scenarioReports(t *testing.T, scenario string) map[string]model.Report {
	t.Helper()
	simMu.Lock()
	defer simMu.Unlock()
	if r, ok := simReports[scenario]; ok {
		return r
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	out := map[string]model.Report{}
	for _, role := range CrossPortRoles {
		e := fastRole(t, role)
		wg.Add(1)
		go func() {
			defer wg.Done()
			sim, _ := NewSimulator(scenario)
			defer sim.Close()
			r, err := Run(context.Background(), e, crossPortPolicy(), testLink(), sim)
			if err != nil {
				t.Error(role, err)
			}
			mu.Lock()
			out[role] = r
			mu.Unlock()
		}()
	}
	wg.Wait()
	simReports[scenario] = out
	return out
}

func studyExperiments(t *testing.T) map[string]model.Experiment {
	t.Helper()
	out := map[string]model.Experiment{}
	for _, role := range CrossPortRoles {
		out[role] = fastRole(t, role)
	}
	return out
}

// oracle serves recorded reports and counts which roles were requested.
func oracle(reports map[string]model.Report, ran *[]string) RoleRunner {
	return func(_ context.Context, role string) (model.Report, error) {
		*ran = append(*ran, role)
		return reports[role], nil
	}
}

func adaptiveRun(t *testing.T, reports map[string]model.Report, task model.AdaptiveTask, budget model.Budget, profile *model.BehaviorProfile, now time.Time) (model.AdaptiveStudy, []string) {
	t.Helper()
	var ran []string
	s, err := RunAdaptive(context.Background(), AdaptiveInput{Experiments: studyExperiments(t), Policy: crossPortPolicy(), Task: task, Budget: budget,
		Profile: profile, Now: now, Run: oracle(reports, &ran)})
	if err != nil {
		t.Fatal(err)
	}
	return s, ran
}

func statement(s model.AdaptiveStudy, name string) model.CoverageStatement {
	for _, st := range s.Statements {
		if st.Statement == name {
			return st
		}
	}
	return model.CoverageStatement{}
}

func TestAdaptiveSelectsDiscriminatingRolesAndStops(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		scenario, class string
		refine          []string
		roles           []string
	}{
		{"shared-limit", "shared-state", nil, []string{RoleMain, RoleNull}},
		{"port-limit", "per-port-state", nil, []string{RoleMain, RoleSamePort}},
		{"stable", "no-coupling", nil, []string{RoleMain, RoleSamePort}},
		{"shared-limit", "shared-state", []string{"cooldown"}, []string{RoleMain, RoleNull, RoleTimeSeparated}},
		{"shared-limit", "shared-state", []string{"direction", "cooldown"}, []string{RoleMain, RoleNull, RoleReverse, RoleTimeSeparated}},
	} {
		s, ran := adaptiveRun(t, scenarioReports(t, tc.scenario), model.AdaptiveTask{Refine: tc.refine}, model.Budget{}, nil, time.Now())
		if s.StopReason != StopSufficient || s.Study.Classification != tc.class || statement(s, "classification").Value != tc.class {
			t.Fatalf("%s %v: stop %s, study %s, statements %+v", tc.scenario, tc.refine, s.StopReason, s.Study.Classification, s.Statements)
		}
		slices.Sort(ran)
		want := slices.Clone(tc.roles)
		slices.Sort(want)
		if !slices.Equal(ran, want) {
			t.Fatalf("%s %v ran %v, want %v", tc.scenario, tc.refine, ran, want)
		}
		if s.Steps[0].Role != RoleMain || s.Spent.Packets == 0 {
			t.Fatalf("main must run first and spend is measured: %+v", s.Steps[0])
		}
		// Statements for skipped refinements are never reported as tested.
		if tc.class == "shared-state" {
			for _, name := range []string{"direction", "cooldown"} {
				st := statement(s, name)
				tested := slices.Contains(tc.refine, name)
				if (st.Coverage == "tested") != tested || (!tested && st.Coverage != "not-tested") {
					t.Fatalf("%v: %s coverage %s", tc.refine, name, st.Coverage)
				}
			}
		}
	}
}

func TestAdaptiveBudgetStopsAreHonest(t *testing.T) {
	t.Parallel()
	reports := scenarioReports(t, "shared-limit")
	main := studyExperiments(t)[RoleMain]
	p, _ := compileCost(t, main)
	// Enough for main only: the stop leaves shared-state and nonspecific apart.
	s, ran := adaptiveRun(t, reports, model.AdaptiveTask{}, model.Budget{Packets: p + p/2}, nil, time.Now())
	if s.StopReason != StopBudget || !slices.Equal(ran, []string{RoleMain}) {
		t.Fatalf("stop %s ran %v", s.StopReason, ran)
	}
	if statement(s, "classification").Value != "unresolved" || s.Study.Classification != "shared-state" {
		t.Fatalf("budget stop overstated the classification: %+v", s.Statements)
	}
	// Not even main fits: no traffic.
	s, ran = adaptiveRun(t, reports, model.AdaptiveTask{}, model.Budget{Packets: p - 1}, nil, time.Now())
	if s.StopReason != StopBudget || len(ran) != 0 || s.Spent.Packets != 0 {
		t.Fatalf("over-budget main ran: %s %v", s.StopReason, ran)
	}
	// A high packet price stops refinements whose information is not worth it.
	s, ran = adaptiveRun(t, reports, model.AdaptiveTask{Refine: []string{"cooldown"}, LambdaBitsPerPacket: 1}, model.Budget{}, nil, time.Now())
	if s.StopReason != StopBudget || len(ran) != 1 {
		t.Fatalf("lambda stop: %s %v", s.StopReason, ran)
	}
}

func TestAdaptiveCounterexampleOutsideHypothesisSet(t *testing.T) {
	t.Parallel()
	stable := scenarioReports(t, "stable")
	// Dependence only from the unrelated null port: outside the declared set.
	reports := map[string]model.Report{}
	for role, r := range stable {
		reports[role] = r
	}
	null := stable[RoleNull]
	null.Trials = slices.Clone(null.Trials)
	measurement := measurementProbes(null)
	for i, trial := range null.Trials {
		if trial.Arm == "treatment" && trial.Probe == measurement["treatment"] {
			trial.Features = model.Features{ResponseClass: "no-response"}
			trial.QualityFlags = []string{"timeout"}
			null.Trials[i] = trial
		}
	}
	null.Comparison = Compare(null)
	reports[RoleNull] = null
	full, err := AnalyzeCrossPort(reports)
	if err != nil || full.Classification != "unresolved" {
		t.Fatalf("full design: %s %v", full.Classification, err)
	}
	s, ran := adaptiveRun(t, reports, model.AdaptiveTask{}, model.Budget{}, nil, time.Now())
	if s.Study.Classification != "no-coupling" || slices.Contains(ran, RoleNull) {
		t.Fatalf("expected the documented counterexample, got %s after %v", s.Study.Classification, ran)
	}
	// Requiring the null control removes the counterexample at its cost.
	s, ran = adaptiveRun(t, reports, model.AdaptiveTask{Require: []string{RoleNull}}, model.Budget{}, nil, time.Now())
	if s.Study.Classification != "unresolved" || !slices.Contains(ran, RoleNull) {
		t.Fatalf("required null: %s after %v", s.Study.Classification, ran)
	}
}

func TestAdaptiveFullCoverageNeverSkips(t *testing.T) {
	t.Parallel()
	reports := scenarioReports(t, "shared-limit")
	profile, err := BuildProfile(reports, "lab-shared", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s, ran := adaptiveRun(t, reports, model.AdaptiveTask{FullCoverage: true}, model.Budget{}, &profile, time.Now())
	if s.StopReason != StopFullCoverage || len(ran) != len(CrossPortRoles) {
		t.Fatalf("full coverage ran %v", ran)
	}
	for _, port := range s.Ports {
		if port.Coverage != "tested" {
			t.Fatalf("full coverage left %+v", port)
		}
	}
	for _, st := range s.Statements {
		if st.Coverage != "tested" {
			t.Fatalf("full coverage statement %+v", st)
		}
	}
	main, _ := compileCost(t, studyExperiments(t)[RoleMain])
	if _, err := RunAdaptive(context.Background(), AdaptiveInput{Experiments: studyExperiments(t), Policy: crossPortPolicy(), Task: model.AdaptiveTask{FullCoverage: true},
		Budget: model.Budget{Packets: 2 * main}, Run: oracle(reports, &[]string{})}); err == nil {
		t.Fatal("full coverage accepted a budget that cannot cover every role")
	}
}

func TestProfileInferenceAndInvalidation(t *testing.T) {
	t.Parallel()
	reports := scenarioReports(t, "shared-limit")
	built := time.Now()
	profile, err := BuildProfile(reports, "lab-shared", built, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Classification != "shared-state" || profile.Direction != "symmetric" || profile.Cooldown != "cooldown" {
		t.Fatalf("profile %+v", profile)
	}
	refine := model.AdaptiveTask{Refine: []string{"direction", "cooldown"}}

	// Valid profile: refinements are inferred, not re-measured.
	s, ran := adaptiveRun(t, reports, refine, model.Budget{}, &profile, built.Add(time.Minute))
	if !s.Profile.Valid || len(ran) != 2 {
		t.Fatalf("valid profile: %+v ran %v", s.Profile, ran)
	}
	for _, name := range []string{"direction", "cooldown", "rate-limiter"} {
		if st := statement(s, name); st.Coverage != "profile-inferred" {
			t.Fatalf("%s: %+v", name, st)
		}
	}

	// Expired profile: the planner falls back to testing the refinements.
	s, ran = adaptiveRun(t, reports, refine, model.Budget{}, &profile, built.Add(2*time.Hour))
	if s.Profile.Valid || len(ran) != 4 || statement(s, "cooldown").Coverage != "tested" {
		t.Fatalf("expired profile: %+v ran %v", s.Profile, ran)
	}

	invalid := func(name string, p model.BehaviorProfile, reports map[string]model.Report, changes []model.ChangeEvent) {
		t.Helper()
		p.ID = profileID(p)
		if c := CheckProfile(p, reports, changes, built.Add(time.Minute)); c.Valid || len(c.Reasons) == 0 {
			t.Fatalf("%s: profile still valid", name)
		}
	}
	path := profile
	path.Fingerprint.ReplyTTLs = []int{63}
	invalid("path change", path, reports, nil)
	host := profile
	host.Fingerprint.Options = "020405b40103030a"
	invalid("host change", host, reports, nil)
	vantage := profile
	vantage.Vantage.SourceIP = "192.0.2.99"
	invalid("vantage change", vantage, reports, nil)
	invalid("declared upgrade", profile, reports, []model.ChangeEvent{{At: built.Add(time.Second), Scope: "host:" + profile.Target, Detail: "kernel upgrade"}})
	invalid("behavior drift", profile, scenarioReports(t, "stable"), nil)
	tampered := profile
	tampered.Classification = "no-coupling"
	if c := CheckProfile(tampered, reports, nil, built.Add(time.Minute)); c.Valid {
		t.Fatal("tampered profile accepted")
	}

	// Drift in the adaptive path: a shared-state profile on a stable target.
	s, _ = adaptiveRun(t, scenarioReports(t, "stable"), refine, model.Budget{}, &profile, built.Add(time.Minute))
	if s.Profile.Valid || s.Study.Classification != "no-coupling" {
		t.Fatalf("drift: %+v %s", s.Profile, s.Study.Classification)
	}
}

func TestProfileRoundTripAndRejections(t *testing.T) {
	t.Parallel()
	reports := scenarioReports(t, "port-limit")
	now := time.Now()
	p, err := BuildProfile(reports, "lab-per-port", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(p)
	got, err := LoadProfile(bytes.NewReader(b))
	if err != nil || got.ID != p.ID || got.Classification != "per-port-state" {
		t.Fatalf("round trip: %v %+v", err, got)
	}
	tampered := bytes.Replace(b, []byte("per-port-state"), []byte("no-coupling"), 1)
	if _, err := LoadProfile(bytes.NewReader(tampered)); err == nil {
		t.Fatal("tampered profile loaded")
	}
	if _, err := BuildProfile(reports, "bad class", now, time.Hour); err == nil {
		t.Fatal("whitespace class accepted")
	}
	if _, err := BuildProfile(reports, "x", now, 31*24*time.Hour); err == nil {
		t.Fatal("over-long TTL accepted")
	}
	unresolved := map[string]model.Report{RoleMain: reports[RoleMain]}
	r := unresolved[RoleMain]
	r.Completed = false
	r.Comparison = Compare(r)
	unresolved[RoleMain] = r
	if _, err := BuildProfile(unresolved, "x", now, time.Hour); err == nil {
		t.Fatal("unresolved study became a profile")
	}
}

func compileCost(t *testing.T, e model.Experiment) (int, int64) {
	t.Helper()
	plan, err := dsl.Compile(e, crossPortPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return plan.MaxPackets, plan.MaxDurationMS
}

// A profile without a tested cooldown must not supply the limiter status:
// its "not-elevated" only records that no orthogonal signal was measured.
func TestProfileWithoutCooldownInfersNoLimiterStatus(t *testing.T) {
	t.Parallel()
	all := scenarioReports(t, "shared-limit")
	partial := map[string]model.Report{RoleMain: all[RoleMain], RoleSamePort: all[RoleSamePort]}
	built := time.Now()
	profile, err := BuildProfile(partial, "lab-shared-partial", built, time.Hour)
	if err != nil || profile.Cooldown != "untested" {
		t.Fatalf("profile %+v %v", profile, err)
	}
	s, _ := adaptiveRun(t, all, model.AdaptiveTask{Refine: []string{"direction"}}, model.Budget{}, &profile, built.Add(time.Minute))
	if st := statement(s, "rate-limiter"); st.Coverage != "not-tested" || st.Value != "untested" {
		t.Fatalf("rate-limiter %+v", st)
	}
	// The profile never ran the reverse role either, so direction is tested now.
	if st := statement(s, "direction"); st.Coverage != "tested" {
		t.Fatalf("direction %+v", st)
	}
}

// Review fixes: changes during the evidence window, malformed scopes and
// future-dated profiles all invalidate; nothing fails open.
func TestProfileCheckFailsClosed(t *testing.T) {
	t.Parallel()
	reports := scenarioReports(t, "shared-limit")
	profile, err := BuildProfile(reports, "lab-shared", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := profile.CreatedAt.Add(time.Minute)
	if c := CheckProfile(profile, reports, nil, now); !c.Valid {
		t.Fatalf("baseline invalid: %v", c.Reasons)
	}
	during := profile.EvidenceFrom.Add(profile.CreatedAt.Sub(profile.EvidenceFrom) / 2)
	for name, changes := range map[string][]model.ChangeEvent{
		"change during evidence": {{At: during, Scope: "host:" + profile.Target}},
		"malformed scope":        {{At: now, Scope: "hosts:" + profile.Target}},
		"non-canonical address":  {{At: now, Scope: "host:192.0.2.010"}},
	} {
		if c := CheckProfile(profile, reports, changes, now); c.Valid {
			t.Fatalf("%s accepted", name)
		}
	}
	if c := CheckProfile(profile, reports, nil, profile.CreatedAt.Add(-time.Minute)); c.Valid {
		t.Fatal("profile dated after the evaluation time accepted")
	}
	long := profile
	long.ValidUntil = long.CreatedAt.Add(MaxProfileTTL + time.Hour)
	long.ID = profileID(long)
	if c := CheckProfile(long, reports, nil, now); c.Valid {
		t.Fatal("over-long in-memory profile accepted")
	}
}

func TestAdaptiveErrorKeepsStepsAndUnresolvedPortsAreMarked(t *testing.T) {
	t.Parallel()
	reports := scenarioReports(t, "shared-limit")
	calls := 0
	failing := func(_ context.Context, role string) (model.Report, error) {
		if calls++; calls == 2 {
			return model.Report{}, context.Canceled
		}
		return reports[role], nil
	}
	s, err := RunAdaptive(context.Background(), AdaptiveInput{Experiments: studyExperiments(t), Policy: crossPortPolicy(), Run: failing})
	if err == nil || s.StopReason != StopError || len(s.Steps) != 1 || len(s.Statements) != 0 || s.Study.Classification != "unresolved" {
		t.Fatalf("error study: %v %s steps=%d", err, s.StopReason, len(s.Steps))
	}
	broken := reports[RoleMain]
	broken.Completed, broken.StopReason = false, "cancelled"
	broken.Comparison = Compare(broken)
	s, _ = adaptiveRun(t, map[string]model.Report{RoleMain: broken}, model.AdaptiveTask{}, model.Budget{}, nil, time.Now())
	if s.StopReason != StopMainUnresolved {
		t.Fatalf("stop %s", s.StopReason)
	}
	for _, p := range s.Ports {
		if p.Port == "tcp/443" && p.Coverage != "tested-unresolved" {
			t.Fatalf("unresolved main port %+v", p)
		}
	}
}
