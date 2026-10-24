package horizon

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/horizon/model"
)

// Phase 6 (#72): budgeted sequential selection of cross-port study roles.
// The planner never decides the classification itself: AnalyzeCrossPort does,
// over the roles actually run. The planner only chooses which role to run
// next and when to stop.

const (
	StopSufficient        = "sufficient"
	StopBudget            = "budget"
	StopIndistinguishable = "indistinguishable"
	StopInconsistent      = "model-inconsistent"
	StopMainUnresolved    = "main-unresolved"
	StopFullCoverage      = "full-coverage"
	StopError             = "error" // a role failed or was cancelled; completed steps are kept
)

// studyHypothesis is a deterministic prediction of which roles show dependence.
type studyHypothesis struct {
	id, class, direction, cooldown string
	weight                         float64
	predicts                       map[string]bool
}

// studyHypotheses is the declared model with a uniform prior over the four
// classifier outcomes; shared-state mass is split evenly over its variants.
// A target outside this set (for example dependence that skips the main pair
// but shows on the null port) is a known counterexample: the planner can stop
// before running the role that would expose it.
func studyHypotheses() []studyHypothesis {
	h := []studyHypothesis{
		{id: "no-coupling", class: "no-coupling", weight: 0.25, predicts: map[string]bool{}},
		{id: "per-port-state", class: "per-port-state", weight: 0.25, predicts: map[string]bool{RoleSamePort: true}},
		{id: "nonspecific", class: "unresolved", weight: 0.25, predicts: map[string]bool{RoleMain: true, RoleSamePort: true, RoleNull: true, RoleReverse: true, RoleTimeSeparated: true}},
	}
	for _, d := range []string{"symmetric", "one-way"} {
		for _, c := range []string{"cooldown", "persistent"} {
			h = append(h, studyHypothesis{id: "shared-state/" + d + "/" + c, class: "shared-state", direction: d, cooldown: c, weight: 0.0625,
				predicts: map[string]bool{RoleMain: true, RoleSamePort: true, RoleReverse: d == "symmetric", RoleTimeSeparated: c == "persistent"}})
		}
	}
	return h
}

// label is the part of a hypothesis the task must resolve.
func (h studyHypothesis) label(refine []string) string {
	l := h.class
	if h.class == "shared-state" {
		if slices.Contains(refine, "direction") {
			l += "/" + h.direction
		}
		if slices.Contains(refine, "cooldown") {
			l += "/" + h.cooldown
		}
	}
	return l
}

func entropy(p float64) float64 {
	if p <= 0 || p >= 1 {
		return 0
	}
	return -p*math.Log2(p) - (1-p)*math.Log2(1-p)
}

// expectedGain is the mutual information in bits between the task label and
// the role's predicted outcome under the prior restricted to consistent.
func expectedGain(role string, consistent []studyHypothesis, refine []string) float64 {
	type mass struct{ w, yes float64 }
	var total, yes float64
	labels := map[string]*mass{}
	for _, h := range consistent {
		m := labels[h.label(refine)]
		if m == nil {
			m = &mass{}
			labels[h.label(refine)] = m
		}
		total += h.weight
		m.w += h.weight
		if h.predicts[role] {
			yes += h.weight
			m.yes += h.weight
		}
	}
	if total == 0 {
		return 0
	}
	conditional := 0.0
	for _, m := range labels {
		conditional += m.w / total * entropy(m.yes/m.w)
	}
	return math.Max(0, entropy(yes/total)-conditional)
}

// RoleRunner executes (or replays) one study role.
type RoleRunner func(ctx context.Context, role string) (model.Report, error)

// AdaptiveInput holds the role experiments, the operator policy they compile
// under, the task, budget and an optional profile. Run executes one role.
type AdaptiveInput struct {
	Experiments map[string]model.Experiment
	Policy      model.Policy
	Task        model.AdaptiveTask
	Budget      model.Budget
	Profile     *model.BehaviorProfile
	Changes     []model.ChangeEvent
	Now         time.Time
	Run         RoleRunner
}

type roleCost struct {
	packets    int
	durationMS int64
}

func fits(budget, spent model.Budget, c roleCost) bool {
	return (budget.Packets == 0 || spent.Packets+c.packets <= budget.Packets) &&
		(budget.DurationMS == 0 || spent.DurationMS+c.durationMS <= budget.DurationMS)
}

func outcomeOf(role string, r model.Report) (string, error) {
	e, err := roleEffect(role, r)
	switch {
	case err != nil:
		return "", err
	case e.Status != "inferred":
		return "unresolved", nil
	case e.Significant:
		return "dependence", nil
	}
	return "no-dependence", nil
}

func hypothesisIDs(hs []studyHypothesis) []string {
	ids := []string{}
	for _, h := range hs {
		ids = append(ids, h.id)
	}
	return ids
}

type planner struct {
	in         AdaptiveInput
	out        *model.AdaptiveStudy
	available  []string
	costs      map[string]roleCost
	reports    map[string]model.Report
	consistent []studyHypothesis
}

// RunAdaptive selects roles one at a time by expected information about the
// task minus lambda times packets, never exceeding the budget with any role's
// worst-case compiled cost. It stops when the task is resolved, the budget
// cannot fit an informative role, no available role discriminates, or the
// observations contradict every declared hypothesis. FullCoverage runs every
// available role regardless of sufficiency or profile predictions.
func RunAdaptive(ctx context.Context, in AdaptiveInput) (result model.AdaptiveStudy, err error) {
	defer func() {
		// Never leave a stale stop reason or partial statements on a failed study.
		if err != nil {
			result.StopReason, result.StopDetail = StopError, err.Error()
			result.Statements, result.Ports = []model.CoverageStatement{}, []model.PortCoverage{}
			result.Study = model.CrossPortStudy{Version: CrossPortVersion, Classification: "unresolved", IsolatedClassification: "unresolved", Roles: []model.RoleEffect{},
				Reasons: []string{"study failed: " + err.Error()}, Candidates: []model.Candidate{}, Limitations: []string{}}
		}
	}()
	task := in.Task
	task.Refine, task.Require = slices.Clone(task.Refine), slices.Clone(task.Require)
	if task.Refine == nil {
		task.Refine = []string{}
	}
	if task.Require == nil {
		task.Require = []string{}
	}
	out := model.AdaptiveStudy{APIVersion: model.AdaptiveVersion, Kind: "AdaptiveStudy", Task: task, Budget: in.Budget, Steps: []model.AdaptiveStep{}, Consistent: []string{},
		Statements: []model.CoverageStatement{}, Ports: []model.PortCoverage{},
		Limitations: []string{"Expected information uses a declared prior and deterministic role predictions; it is a selection heuristic, not a probability of the conclusion.",
			"Roles the planner skipped are not tested; their statements are profile-inferred or not-tested, never observed.",
			"Budget checks use each role's compiled worst-case packets and duration; spent values are measured.",
			"Dependence outside the declared hypothesis set (for example only on the null port) can go undetected when the planner stops before that role."}}
	for _, r := range task.Refine {
		if r != "direction" && r != "cooldown" {
			return out, fmt.Errorf("unknown refinement %q (direction, cooldown)", r)
		}
	}
	if task.LambdaBitsPerPacket < 0 || math.IsNaN(task.LambdaBitsPerPacket) || math.IsInf(task.LambdaBitsPerPacket, 0) {
		return out, errors.New("lambda must be a finite non-negative number")
	}
	if in.Budget.Packets < 0 || in.Budget.DurationMS < 0 {
		return out, errors.New("budget must be non-negative")
	}
	if in.Run == nil {
		return out, errors.New("a role runner is required")
	}
	if _, ok := in.Experiments[RoleMain]; !ok {
		return out, errors.New("an adaptive study requires the main role")
	}
	p := planner{in: in, out: &out, costs: map[string]roleCost{}, reports: map[string]model.Report{}, consistent: studyHypotheses()}
	for role := range in.Experiments {
		if !slices.Contains(CrossPortRoles, role) {
			return out, fmt.Errorf("unknown cross-port role %q", role)
		}
	}
	for _, role := range CrossPortRoles {
		e, ok := in.Experiments[role]
		if !ok {
			continue
		}
		plan, err := dsl.Compile(e, in.Policy)
		if err != nil {
			return out, fmt.Errorf("%s: %w", role, err)
		}
		p.costs[role] = roleCost{plan.MaxPackets, plan.MaxDurationMS}
		p.available = append(p.available, role)
	}
	for _, role := range task.Require {
		if _, ok := p.costs[role]; !ok {
			return out, fmt.Errorf("required role %q has no experiment", role)
		}
	}

	if task.FullCoverage {
		var total roleCost
		for _, role := range p.available {
			total.packets += p.costs[role].packets
			total.durationMS += p.costs[role].durationMS
		}
		if !fits(in.Budget, model.Budget{}, total) {
			return out, fmt.Errorf("full coverage needs a budget of %d packets and %d ms for %d roles", total.packets, total.durationMS, len(p.available))
		}
		for _, role := range p.available {
			if _, err := p.execute(ctx, role, []model.RoleScore{}); err != nil {
				return out, err
			}
		}
		out.StopReason, out.StopDetail = StopFullCoverage, "every available role was run; profile predictions never skip a role"
	} else {
		// A profile can stand in for refinements; they are planned as tests
		// after all if the profile does not survive the check.
		planned := task.Refine
		if in.Profile != nil && in.Profile.Classification == "shared-state" {
			planned = []string{}
			for _, r := range task.Refine {
				if (r == "direction" && in.Profile.Direction == "untested") || (r == "cooldown" && in.Profile.Cooldown == "untested") {
					planned = append(planned, r)
				}
			}
		}
		if err := p.plan(ctx, task.Require, planned); err != nil {
			return out, err
		}
		if in.Profile != nil && len(planned) < len(task.Refine) && out.StopReason == StopSufficient && !p.checkProfile().Valid {
			if err := p.plan(ctx, task.Require, task.Refine); err != nil {
				return out, err
			}
			out.StopDetail += " (after the profile was invalidated)"
		}
	}
	out.Consistent = hypothesisIDs(p.consistent)
	if len(p.reports) == 0 {
		// Nothing fit the budget: no traffic and no statement is tested.
		out.Study = model.CrossPortStudy{Version: CrossPortVersion, Classification: "unresolved", IsolatedClassification: "unresolved", Roles: []model.RoleEffect{},
			Reasons: []string{"no role was run"}, Candidates: []model.Candidate{}, Limitations: []string{}}
		out.Statements = []model.CoverageStatement{{Statement: "classification", Value: "unresolved", Coverage: "not-tested", Evidence: []string{}}}
		out.Ports = portCoverage(in.Experiments, p.reports, nil, nil)
		return out, nil
	}
	study, err := AnalyzeCrossPort(p.reports)
	if err != nil {
		return out, err
	}
	out.Study = study
	if in.Profile != nil {
		check := p.checkProfile()
		out.Profile = &check
	}
	out.Statements = coverageStatements(study, p.reports, in.Profile, out.Profile)
	classes := map[string]bool{}
	for _, h := range p.consistent {
		classes[h.class] = true
	}
	switch {
	case task.FullCoverage:
	case out.StopReason == StopInconsistent || (out.StopReason == StopBudget && len(classes) > 1):
		// An available role that could separate the alternatives was skipped
		// (or the model was contradicted): the adaptive statement stays unresolved.
		out.Statements[0].Value = "unresolved"
		out.Limitations = append(out.Limitations, fmt.Sprintf("Stopped (%s) before the classification %q was separated from: %s.", out.StopReason, study.Classification, strings.Join(out.Consistent, ", ")))
	case len(classes) > 1:
		// No available role discriminates: the same as a fixed study of these roles.
		out.Limitations = append(out.Limitations, fmt.Sprintf("No available role separates %q from: %s; a fixed study of the same roles has the same limit.", study.Classification, strings.Join(out.Consistent, ", ")))
	}
	out.Ports = portCoverage(in.Experiments, p.reports, in.Profile, out.Profile)
	return out, nil
}

func (p *planner) checkProfile() model.ProfileCheck {
	return CheckProfile(*p.in.Profile, p.reports, p.in.Changes, p.in.Now)
}

func (p *planner) execute(ctx context.Context, role string, candidates []model.RoleScore) (string, error) {
	r, err := p.in.Run(ctx, role)
	if err != nil {
		return "", fmt.Errorf("%s: %w", role, err)
	}
	p.reports[role] = r
	outcome, err := outcomeOf(role, r)
	if err != nil {
		return "", err
	}
	step := model.AdaptiveStep{Role: role, Candidates: candidates, Outcome: outcome, RunID: r.RunID, Packets: r.PacketsTX,
		DurationMS: r.FinishedAt.Sub(r.StartedAt).Milliseconds(), Curtailed: r.Curtailment != nil}
	p.out.Spent.Packets += step.Packets
	p.out.Spent.DurationMS += step.DurationMS
	if outcome != "unresolved" {
		var keep []studyHypothesis
		for _, h := range p.consistent {
			if h.predicts[role] == (outcome == "dependence") {
				keep = append(keep, h)
			}
		}
		p.consistent = keep
	}
	step.Consistent = hypothesisIDs(p.consistent)
	p.out.Steps = append(p.out.Steps, step)
	return outcome, nil
}

// plan runs roles until a stop rule fires. The main role and any required
// roles run first, in that order, because the classifier needs them.
func (p *planner) plan(ctx context.Context, require, refine []string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(p.consistent) == 0 {
			p.out.StopReason, p.out.StopDetail = StopInconsistent, "observations contradict every declared hypothesis"
			return nil
		}
		forced := ""
		for _, role := range append([]string{RoleMain}, require...) {
			if _, done := p.reports[role]; !done {
				forced = role
				break
			}
		}
		labels := map[string]bool{}
		for _, h := range p.consistent {
			labels[h.label(refine)] = true
		}
		if forced == "" && len(labels) == 1 {
			p.out.StopReason, p.out.StopDetail = StopSufficient, "every consistent hypothesis agrees on the task"
			return nil
		}
		candidates := []model.RoleScore{}
		for _, role := range p.available {
			c := p.costs[role]
			s := model.RoleScore{Role: role, GainBits: expectedGain(role, p.consistent, refine), MaxPackets: c.packets, MaxDurationMS: c.durationMS}
			s.Score = s.GainBits - p.in.Task.LambdaBitsPerPacket*float64(c.packets)
			_, done := p.reports[role]
			switch {
			case done:
				s.Excluded = "already run"
			case !fits(p.in.Budget, p.out.Spent, c):
				s.Excluded = "over budget"
			case role != forced && s.GainBits <= 1e-9:
				s.Excluded = "no expected information"
			case role != forced && s.Score <= 0:
				s.Excluded = "cost exceeds expected information"
			}
			candidates = append(candidates, s)
		}
		choice := forced
		if forced != "" {
			if i := slices.IndexFunc(candidates, func(s model.RoleScore) bool { return s.Role == forced }); candidates[i].Excluded == "over budget" {
				p.out.StopReason, p.out.StopDetail = StopBudget, forced+" is required but its worst-case cost exceeds the remaining budget"
				return nil
			}
		} else {
			ranked := slices.Clone(candidates)
			sort.SliceStable(ranked, func(i, j int) bool {
				if ranked[i].Score != ranked[j].Score {
					return ranked[i].Score > ranked[j].Score
				}
				return ranked[i].MaxPackets < ranked[j].MaxPackets
			})
			blocked := ""
			for _, s := range ranked {
				if s.Excluded == "" {
					choice = s.Role
					break
				}
				if blocked == "" && s.GainBits > 1e-9 && (s.Excluded == "over budget" || s.Excluded == "cost exceeds expected information") {
					blocked = s.Excluded
				}
			}
			if choice == "" {
				switch blocked {
				case "over budget":
					p.out.StopReason, p.out.StopDetail = StopBudget, "an informative role remains but none fits the remaining budget"
				case "":
					p.out.StopReason, p.out.StopDetail = StopIndistinguishable, "no available role discriminates the remaining hypotheses: "+strings.Join(hypothesisIDs(p.consistent), ", ")
				default:
					p.out.StopReason, p.out.StopDetail = StopBudget, "the remaining informative roles cost more than their expected information at this lambda"
				}
				return nil
			}
		}
		outcome, err := p.execute(ctx, choice, candidates)
		if err != nil {
			return err
		}
		if choice == RoleMain && outcome == "unresolved" {
			p.out.StopReason, p.out.StopDetail = StopMainUnresolved, "the classifier cannot resolve a study whose main role is unresolved"
			return nil
		}
	}
}
