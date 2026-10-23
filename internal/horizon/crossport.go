package horizon

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/matusso/nyxr/internal/horizon/model"
)

const CrossPortVersion = "horizon-cross-port/v1"

// Study roles, each a separately compiled and executed precondition experiment.
const (
	RoleMain          = "main"           // HZ-003: precondition on A, measure B
	RoleReverse       = "reverse"        // HZ-004: precondition on B, measure A
	RoleSamePort      = "same-port"      // precondition and measurement on B
	RoleTimeSeparated = "time-separated" // main ports with a longer matched wait
	RoleNull          = "null"           // precondition on an unrelated port C, measure B
)

var CrossPortRoles = []string{RoleMain, RoleReverse, RoleSamePort, RoleTimeSeparated, RoleNull}

// Competing explanations listed for every shared-state candidate.
var crossPortAlternatives = []string{
	"shared endpoint resources (SYN rate limit, listen queue, SYN cookies)",
	"shared middlebox or firewall state on the path",
	"source-side or vantage-point state",
	"ambient load coincident with preconditions",
}

// comparePrecondition tests whether the measurement probe's answer depends on
// the precondition flow: an exact paired sign test over measurement outcomes.
// Timeouts are the outcome here, not a quality failure; any other flag is.
func comparePrecondition(r model.Report) model.Comparison {
	c := comparePreconditionCounts(r)
	replicates := r.Experiment.Spec.Execution.Replicates
	want := replicates
	if r.Curtailment != nil {
		want = r.Curtailment.Pairs
	}
	if !r.Completed || r.BackendDrops > 0 || (r.CaptureArtifact != nil && r.CaptureArtifact.Dropped > 0) || c.CompletePairs < MinCurtailPairs || c.CompletePairs != want {
		return c
	}
	if r.Curtailment != nil && (r.Curtailment.Rule != CurtailRule || CurtailDecision(c.ControlOnly, c.TreatmentOnly, replicates-c.CompletePairs) != r.Curtailment.Decision) {
		c.Conclusion = "curtailment is not supported by the recorded pairs"
		return c
	}
	if r.Environment != nil && len(r.Environment.GatingFlags) > 0 {
		c.Conclusion = "environmental quality gate: " + strings.Join(r.Environment.GatingFlags, ", ")
		return c
	}
	c.Status = "inferred"
	c.Conclusion = "no detectable dependence of the measurement on the precondition flow"
	if c.PValue <= 0.05 {
		c.Conclusion = "measurement response depends on the precondition flow; shared-state candidate, mechanism unresolved"
	}
	return c
}

// comparePreconditionCounts tallies complete and discordant measurement pairs.
func comparePreconditionCounts(r model.Report) model.Comparison {
	c := model.Comparison{Status: "unresolved", Conclusion: "insufficient or confounded evidence", PValue: 1, Metric: "measurement-answered"}
	measurement := measurementProbes(r)
	pairs := map[int]map[string]model.Trial{}
	broken := map[int]bool{}
	for _, t := range r.Trials {
		if t.Arm == "reference" {
			continue
		}
		clean := t.Features.ResponseClass != "icmp-error"
		for _, f := range t.QualityFlags {
			clean = clean && f == "timeout"
		}
		if t.Probe != measurement[t.Arm] {
			// A precondition must have been transmitted; its answer is not compared.
			if t.SentAt.IsZero() || !clean {
				broken[t.Pair] = true
			}
			continue
		}
		if !clean {
			broken[t.Pair] = true
			continue
		}
		if pairs[t.Pair] == nil {
			pairs[t.Pair] = map[string]model.Trial{}
		}
		pairs[t.Pair][t.Arm] = t
	}
	for pair, arms := range pairs {
		a, aok := arms["control"]
		b, bok := arms["treatment"]
		if !aok || !bok || broken[pair] {
			continue
		}
		c.CompletePairs++
		switch x, y := answered(a), answered(b); {
		case x && !y:
			c.ControlOnly++
		case !x && y:
			c.TreatmentOnly++
		}
	}
	c.DiscordantPairs = c.ControlOnly + c.TreatmentOnly
	c.PValue = signTest(c.ControlOnly, c.TreatmentOnly)
	return c
}

// CurtailRule names exact curtailment of the fixed-n paired sign test.
const CurtailRule = "exact-sign-test-curtailment/v1"

// MinCurtailPairs is the minimum number of complete pairs for any precondition
// decision, curtailed or not.
const MinCurtailPairs = 8

// CurtailDecision reports the fixed-n decision (alpha 0.05) when every way the
// remaining pairs could turn out leads to it, and "" while it can still change.
// Concordant pairs do not affect the sign test, so only discordant splits of
// the remaining pairs are enumerated.
func CurtailDecision(controlOnly, treatmentOnly, remaining int) string {
	if remaining < 0 {
		return ""
	}
	significant, insignificant := false, false
	for x := 0; x <= remaining; x++ {
		for y := 0; x+y <= remaining; y++ {
			if signTest(controlOnly+x, treatmentOnly+y) <= 0.05 {
				significant = true
			} else {
				insignificant = true
			}
			if significant && insignificant {
				return ""
			}
		}
	}
	if significant {
		return "significant"
	}
	return "not-significant"
}

// curtailAfter returns the curtailment justified by the trials so far, which
// end with a whole pair, or nil. Any incomplete pair blocks curtailment.
func curtailAfter(r model.Report, pairs int) *model.Curtailment {
	x := r.Experiment.Spec.Execution
	if x.StopRule != "curtail" || pairs < MinCurtailPairs || pairs >= x.Replicates {
		return nil
	}
	c := comparePreconditionCounts(r)
	if c.CompletePairs != pairs {
		return nil
	}
	if decision := CurtailDecision(c.ControlOnly, c.TreatmentOnly, x.Replicates-pairs); decision != "" {
		return &model.Curtailment{Rule: CurtailRule, Pairs: pairs, Decision: decision}
	}
	return nil
}

// RetroCurtail returns what an exact-curtailment run would have recorded from
// a completed precondition report: the trials up to the first decisive pair,
// with re-derived traffic accounting, environment and comparison. Its
// FinishedAt is the next pair's first send, an upper bound. It is for
// retrospective evaluation of recorded studies only: the result declares a
// stop rule its experiment hash does not cover, so it is not replayable.
func RetroCurtail(r model.Report) model.Report {
	x := r.Experiment.Spec.Execution
	if !r.Completed || r.Curtailment != nil || r.Experiment.Spec.ChangedVariable != "precondition" {
		return r
	}
	out := r
	out.Experiment.Spec.Execution.StopRule = "curtail"
	end := 0
	for pairs := 1; pairs < x.Replicates; pairs++ {
		for end < len(r.Trials) && r.Trials[end].Pair < pairs {
			end++
		}
		out.Trials = r.Trials[:end]
		c := curtailAfter(out, pairs)
		if c == nil {
			continue
		}
		out.Curtailment, out.PacketsTX, out.CaptureBytes = c, 0, 0
		for _, t := range out.Trials {
			for _, e := range t.Evidence {
				out.CaptureBytes += len(e.Frame)
				if e.Direction == "tx" || e.Direction == "cleanup" {
					out.PacketsTX++
				}
			}
		}
		if end < len(r.Trials) && !r.Trials[end].SentAt.IsZero() {
			out.FinishedAt = r.Trials[end].SentAt
		}
		if r.Environment != nil {
			out.Environment = Assess(out)
		}
		out.Comparison = Compare(out)
		return out
	}
	return r
}

// AnalyzeCrossPort combines replayed reports by role. The main and same-port
// roles are required for a classification; the others add controls/signals.
func AnalyzeCrossPort(reports map[string]model.Report) (model.CrossPortStudy, error) {
	s := model.CrossPortStudy{Version: CrossPortVersion, Classification: "unresolved", IsolatedClassification: "unresolved", Reasons: []string{}, Candidates: []model.Candidate{},
		Limitations: []string{"Classifies observed dependence between authorized flows; it does not identify a device, OS or topology.",
			"Intervals and sign tests assume independent, stationary pairs; repeated runs on one target are not independent hosts.",
			"Matched waits exclude rate-gate spacing and cleanup packets; those differ between arms and remain confounders.",
			"Isolated classification uses only the experiments' own no-precondition control probes."}}
	effects := map[string]*model.RoleEffect{}
	for _, role := range CrossPortRoles {
		r, ok := reports[role]
		if !ok {
			continue
		}
		e, err := roleEffect(role, r)
		if err != nil {
			return s, err
		}
		if s.Target == "" {
			s.Target = r.Experiment.Spec.Scope.Targets[0]
		} else if s.Target != r.Experiment.Spec.Scope.Targets[0] {
			return s, errors.New("cross-port study reports must share one target")
		}
		s.Roles = append(s.Roles, e)
		effects[role] = &s.Roles[len(s.Roles)-1]
	}
	for role := range reports {
		if !slices.Contains(CrossPortRoles, role) {
			return s, fmt.Errorf("unknown cross-port role %q", role)
		}
	}
	main := effects[RoleMain]
	if main == nil {
		return s, errors.New("a cross-port study requires the main role")
	}
	if err := checkRoles(effects); err != nil {
		return s, err
	}
	resolved := func(e *model.RoleEffect) bool { return e != nil && e.Status == "inferred" }
	same, null, timed, reverse := effects[RoleSamePort], effects[RoleNull], effects[RoleTimeSeparated], effects[RoleReverse]

	switch {
	case !resolved(main):
		s.Reasons = append(s.Reasons, "main role unresolved")
	case resolved(null) && null.Significant:
		s.Reasons = append(s.Reasons, "null control also depends on its unrelated precondition; coupling is not specific to the declared ports")
	case main.Significant:
		s.Classification = "shared-state"
		s.Reasons = append(s.Reasons, "main measurement depends on a precondition on a different port")
	case !resolved(same):
		s.Reasons = append(s.Reasons, "no cross-port dependence detected, but the same-port control is missing or unresolved")
	case same.Significant:
		s.Classification = "per-port-state"
		s.Reasons = append(s.Reasons, "dependence appears only when precondition and measurement share a port")
	default:
		s.Classification = "no-coupling"
		s.Reasons = append(s.Reasons, "neither cross-port nor same-port dependence detected")
	}
	// Matched isolated control: the same no-precondition probes, judged alone.
	isolated := []*model.RoleEffect{main, same}
	s.IsolatedClassification = "no-coupling"
	for _, e := range isolated {
		if !resolved(e) {
			s.IsolatedClassification = "unresolved"
		} else if e.ControlAnswered.Estimate < 1 {
			s.IsolatedClassification = "unresolved"
		}
	}

	if s.Classification == "shared-state" {
		c := model.Candidate{ID: "CAND-1", Type: "shared-state-candidate", Status: "inferred", Alternatives: crossPortAlternatives, OrthogonalSignals: []string{}, Hypotheses: []model.Hypothesis{}}
		ports := append(append([]uint16{}, main.PreconditionPorts...), main.MeasurementPort)
		slices.Sort(ports)
		for _, p := range slices.Compact(ports) {
			c.Subjects = append(c.Subjects, fmt.Sprintf("tcp/%d", p))
		}
		for _, e := range s.Roles {
			c.Evidence = append(c.Evidence, fmt.Sprintf("%s:%s:%s", e.Role, e.RunID, e.ExperimentHash))
		}
		c.Direction = "untested"
		if resolved(reverse) {
			c.Direction = "one-way"
			if reverse.Significant {
				c.Direction = "symmetric"
			}
		}
		if resolved(timed) && !timed.Significant {
			c.OrthogonalSignals = append(c.OrthogonalSignals, "cooldown")
		}
		if divergentTTL(main) {
			c.OrthogonalSignals = append(c.OrthogonalSignals, "ttl-divergence")
		}
		c.Hypotheses = infrastructureHypotheses(c.OrthogonalSignals, main)
		s.Candidates = append(s.Candidates, c)
	}
	return s, nil
}

// infrastructureHypotheses elevates an explanation only with an orthogonal
// signal: a different measurement than the dependence itself.
func infrastructureHypotheses(signals []string, main *model.RoleEffect) []model.Hypothesis {
	if len(signals) == 0 {
		return []model.Hypothesis{{Family: "rate-limiter", Status: "not-elevated", Reason: "no orthogonal signal; the dependence alone does not identify infrastructure"},
			{Family: "firewall-tracking", Status: "not-elevated", Reason: "no orthogonal signal"}}
	}
	location := "endpoint-or-path-unresolved"
	if slices.Contains(signals, "ttl-divergence") {
		location = "path"
	}
	var out []model.Hypothesis
	if slices.Contains(signals, "cooldown") && main.Suppressed > main.Enabled {
		out = append(out, model.Hypothesis{Family: "rate-limiter", Status: "hypothesis", Location: location,
			Reason: "suppression decays when the precondition is separated in time"})
	} else {
		out = append(out, model.Hypothesis{Family: "rate-limiter", Status: "not-elevated", Reason: "no cooldown signal"})
	}
	if slices.Contains(signals, "ttl-divergence") {
		out = append(out, model.Hypothesis{Family: "firewall-tracking", Status: "hypothesis", Location: "path",
			Reason: "precondition and measurement replies arrive with different TTLs"})
	} else {
		out = append(out, model.Hypothesis{Family: "firewall-tracking", Status: "not-elevated", Reason: "no path-divergence signal"})
	}
	return out
}

func divergentTTL(e *model.RoleEffect) bool {
	if len(e.PreconditionTTLs) == 0 || len(e.MeasurementTTLs) == 0 {
		return false
	}
	for _, t := range e.PreconditionTTLs {
		if slices.Contains(e.MeasurementTTLs, t) {
			return false
		}
	}
	return true
}

func roleEffect(role string, r model.Report) (model.RoleEffect, error) {
	spec := r.Experiment.Spec
	if spec.ChangedVariable != "precondition" {
		return model.RoleEffect{}, fmt.Errorf("%s: not a precondition experiment", role)
	}
	e := model.RoleEffect{Role: role, RunID: r.RunID, ExperimentHash: r.ExperimentHash, PreconditionPorts: []uint16{}, PreconditionTTLs: []uint8{}, MeasurementTTLs: []uint8{}}
	var walk func([]model.Step, *[]model.Send, *int)
	walk = func(steps []model.Step, sends *[]model.Send, wait *int) {
		for _, s := range steps {
			switch {
			case s.Send != nil:
				*sends = append(*sends, *s.Send)
			case s.Wait != nil:
				*wait += s.Wait.DurationMS
			case s.Repeat != nil:
				for i := 0; i < s.Repeat.Count; i++ {
					walk(s.Repeat.Steps, sends, wait)
				}
			}
		}
	}
	var treat, control []model.Send
	var ignored int
	walk(spec.Treatment.Steps, &treat, &ignored)
	walk(spec.Control.Steps, &control, &e.MatchedWaitMS)
	for _, s := range treat[:len(treat)-1] {
		if !slices.Contains(e.PreconditionPorts, s.DstPort) {
			e.PreconditionPorts = append(e.PreconditionPorts, s.DstPort)
		}
	}
	e.MeasurementPort = control[0].DstPort
	c := r.Comparison
	e.Status, e.Conclusion, e.CompletePairs, e.Suppressed, e.Enabled, e.PValue = c.Status, c.Conclusion, c.CompletePairs, c.ControlOnly, c.TreatmentOnly, c.PValue
	e.Significant = c.Status == "inferred" && c.PValue <= 0.05
	measurement := measurementProbes(r)
	var answeredControl, answeredTreatment, n int
	pairs := map[int]map[string]bool{}
	for _, t := range r.Trials {
		if t.Arm == "reference" || !answered(t) {
			continue
		}
		if t.Probe != measurement[t.Arm] {
			if !slices.Contains(e.PreconditionTTLs, t.Features.TTL) {
				e.PreconditionTTLs = append(e.PreconditionTTLs, t.Features.TTL)
			}
			continue
		}
		if !slices.Contains(e.MeasurementTTLs, t.Features.TTL) {
			e.MeasurementTTLs = append(e.MeasurementTTLs, t.Features.TTL)
		}
		if pairs[t.Pair] == nil {
			pairs[t.Pair] = map[string]bool{}
		}
		pairs[t.Pair][t.Arm] = true
	}
	executed := r.Experiment.Spec.Execution.Replicates
	if r.Curtailment != nil {
		executed = r.Curtailment.Pairs
	}
	for pair := range executed {
		n++
		if pairs[pair]["control"] {
			answeredControl++
		}
		if pairs[pair]["treatment"] {
			answeredTreatment++
		}
	}
	slices.Sort(e.PreconditionTTLs)
	slices.Sort(e.MeasurementTTLs)
	e.ControlAnswered, e.TreatmentAnswered = rateInterval(answeredControl, n), rateInterval(answeredTreatment, n)
	return e, nil
}

func rateInterval(k, n int) model.Interval {
	if n == 0 {
		return model.Interval{Upper: 1}
	}
	return model.Interval{Estimate: float64(k) / float64(n), Lower: clopperPearsonLower(k, n, 0.025), Upper: clopperPearsonUpper(k, n, 0.025)}
}

// checkRoles verifies that each control has the structure its role requires.
func checkRoles(effects map[string]*model.RoleEffect) error {
	main := effects[RoleMain]
	if slices.Contains(main.PreconditionPorts, main.MeasurementPort) {
		return errors.New("main role must precondition a different port than it measures")
	}
	if e := effects[RoleSamePort]; e != nil && (len(e.PreconditionPorts) != 1 || e.PreconditionPorts[0] != main.MeasurementPort || e.MeasurementPort != main.MeasurementPort) {
		return errors.New("same-port role must precondition and measure the main measurement port")
	}
	if e := effects[RoleTimeSeparated]; e != nil && (!slices.Equal(e.PreconditionPorts, main.PreconditionPorts) || e.MeasurementPort != main.MeasurementPort || e.MatchedWaitMS <= main.MatchedWaitMS) {
		return errors.New("time-separated role must use the main ports with a longer matched wait")
	}
	if e := effects[RoleReverse]; e != nil && (!slices.Contains(main.PreconditionPorts, e.MeasurementPort) || !slices.Contains(e.PreconditionPorts, main.MeasurementPort)) {
		return errors.New("reverse role must swap the main precondition and measurement ports")
	}
	if e := effects[RoleNull]; e != nil {
		if e.MeasurementPort != main.MeasurementPort {
			return errors.New("null role must measure the main measurement port")
		}
		for _, p := range e.PreconditionPorts {
			if p == main.MeasurementPort || slices.Contains(main.PreconditionPorts, p) {
				return errors.New("null role must precondition an unrelated port")
			}
		}
	}
	return nil
}
