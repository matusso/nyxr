package horizon

import (
	"bytes"
	"math"
	"slices"

	"github.com/matusso/nyxr/internal/horizon/model"
)

const environmentVersion = "horizon-environment/v1"

// Pre-registered environment rules (Phase 3, #69). Changing any of them is a
// new environmentVersion: replay recomputes and compares the saved assessment.
const (
	environmentAlpha    = 0.05
	driftMinimumSamples = 8
	driftRelative       = 0.5
	driftAbsoluteNS     = 10_000_000
	latencyConfidence   = 0.95
)

// Inherent confounders are recorded for every run, in addition to declared ones.
var inherentConfounders = []string{"ambient-load", "sequence-and-ip-id-tokens"}

// Assess derives run-level environmental quality from retained trials only.
// Gating flags make the comparison unresolved; other flags are descriptive.
func Assess(r model.Report) *model.Environment {
	spec := r.Experiment.Spec
	env := &model.Environment{Version: environmentVersion, Treatment: spec.ChangedVariable, QualityFlags: []string{}, GatingFlags: []string{}}
	env.Confounders = append(append([]string{}, inherentConfounders...), spec.Confounders...)
	if spec.CrossPort {
		env.Confounders = append(env.Confounders, "cross-port-state")
	}
	slices.Sort(env.Confounders)
	env.Confounders = slices.Compact(env.Confounders)

	half := len(r.Trials) / 2
	for i, t := range r.Trials {
		if t.Arm == "reference" {
			env.Responses.References++
			if answered(t) {
				env.Responses.ReferencesAnswered++
			}
		}
		if i < half {
			env.Responses.FirstHalf++
			if answered(t) {
				env.Responses.FirstHalfAnswered++
			}
		} else {
			env.Responses.SecondHalf++
			if answered(t) {
				env.Responses.SecondHalfAnswered++
			}
		}
		for _, e := range t.Evidence {
			if e.Timing == nil {
				continue
			}
			env.Clock.TimedEvidence++
			if e.Timing.PrecisionNS == nil {
				env.Clock.UnknownPrecision++
			}
			env.Clock.MaxResolutionNS = max(env.Clock.MaxResolutionNS, e.Timing.ResolutionNS)
		}
		if hasFlag(t.QualityFlags, "clock-instability") {
			env.Clock.UnstableTrials++
		}
		if hasFlag(t.QualityFlags, "invalid-backend-timing") {
			env.Clock.InvalidTimingTrials++
		}
	}
	// Throttling: fewer answers later in the schedule (one-sided Fisher test).
	rs := env.Responses
	env.Responses.ThrottlingPValue = fisherLower(rs.SecondHalfAnswered, rs.SecondHalf-rs.SecondHalfAnswered, rs.FirstHalfAnswered, rs.FirstHalf-rs.FirstHalfAnswered)
	if env.Responses.ThrottlingPValue <= environmentAlpha {
		env.GatingFlags = append(env.GatingFlags, "throttling-suspected")
	}
	if rs.References > rs.ReferencesAnswered {
		env.GatingFlags = append(env.GatingFlags, "reference-loss")
	}
	if env.Clock.UnstableTrials > 0 || env.Clock.InvalidTimingTrials > 0 {
		env.GatingFlags = append(env.GatingFlags, "clock-unreliable")
	}
	if env.Clock.UnknownPrecision > 0 {
		env.QualityFlags = append(env.QualityFlags, "clock-precision-unknown")
	}

	// Drift: RTT of answered trials in schedule order, first versus second half.
	var rtts []int64
	for _, t := range r.Trials {
		if answered(t) && t.Features.RTTNS > 0 {
			rtts = append(rtts, t.Features.RTTNS)
		}
	}
	env.Drift.Samples = len(rtts)
	if len(rtts) >= driftMinimumSamples {
		a, b := median(rtts[:len(rtts)/2]), median(rtts[len(rtts)/2:])
		env.Drift.FirstHalfMedianNS, env.Drift.SecondHalfMedianNS = &a, &b
		if d := math.Abs(float64(b - a)); d > driftAbsoluteNS && d > driftRelative*float64(a) {
			env.QualityFlags = append(env.QualityFlags, "rtt-drift")
		}
	}

	// Pairs of the first probe: carryover (discordance by arm order),
	// stability of non-treatment features and paired latency.
	type pairTrials struct {
		first          string
		control, treat *model.Trial
	}
	pairs := map[int]*pairTrials{}
	var order []int
	for i := range r.Trials {
		t := &r.Trials[i]
		if t.Probe != 0 || (t.Arm != "control" && t.Arm != "treatment") {
			continue
		}
		p := pairs[t.Pair]
		if p == nil {
			p = &pairTrials{first: t.Arm}
			pairs[t.Pair] = p
			order = append(order, t.Pair)
		}
		if t.Arm == "control" {
			p.control = t
		} else {
			p.treat = t
		}
	}
	var controls, treats, diffs []int64
	for _, id := range order {
		p := pairs[id]
		if p.control != nil && answered(*p.control) && p.control.Features.RTTNS > 0 {
			controls = append(controls, p.control.Features.RTTNS)
		}
		if p.treat != nil && answered(*p.treat) && p.treat.Features.RTTNS > 0 {
			treats = append(treats, p.treat.Features.RTTNS)
		}
		if p.control == nil || p.treat == nil || !answered(*p.control) || !answered(*p.treat) {
			continue
		}
		a, b := p.control.Features, p.treat.Features
		env.Stability.CompletePairs++
		if a.ResponseClass != b.ResponseClass {
			env.Stability.ResponseClassChanges++
		}
		if a.TTL != b.TTL {
			env.Stability.TTLChanges++
		}
		if !bytes.Equal(withoutSACK(a.TCPOptions), withoutSACK(b.TCPOptions)) {
			env.Stability.OtherOptionChanges++
		}
		if a.RTTNS > 0 && b.RTTNS > 0 {
			diffs = append(diffs, b.RTTNS-a.RTTNS)
		}
		discordant := a.ResponseClass == "syn-ack" && b.ResponseClass == "syn-ack" && sack(a.TCPOptions) != sack(b.TCPOptions)
		if p.first == "control" {
			env.Carryover.ControlFirstPairs++
			if discordant {
				env.Carryover.ControlFirstDiscordant++
			}
		} else {
			env.Carryover.TreatmentFirstPairs++
			if discordant {
				env.Carryover.TreatmentFirstDiscordant++
			}
		}
	}
	c := env.Carryover
	env.Carryover.PValue = fisherTwoSided(c.ControlFirstDiscordant, c.ControlFirstPairs-c.ControlFirstDiscordant, c.TreatmentFirstDiscordant, c.TreatmentFirstPairs-c.TreatmentFirstDiscordant)
	if env.Carryover.PValue <= environmentAlpha {
		env.GatingFlags = append(env.GatingFlags, "carryover-suspected")
	}
	if env.Stability.ResponseClassChanges > 0 || env.Stability.TTLChanges > 0 || env.Stability.OtherOptionChanges > 0 {
		env.QualityFlags = append(env.QualityFlags, "paired-response-instability")
	}
	if len(controls) > 0 {
		v := median(controls)
		env.Latency.ControlMedianNS = &v
	}
	if len(treats) > 0 {
		v := median(treats)
		env.Latency.TreatmentMedianNS = &v
	}
	env.Latency.PairedSamples = len(diffs)
	if len(diffs) > 0 {
		v := median(diffs)
		env.Latency.PairedMedianNS = &v
		if lo, hi, conf, ok := medianInterval(diffs, latencyConfidence); ok {
			env.Latency.PairedLowerNS, env.Latency.PairedUpperNS, env.Latency.Confidence = &lo, &hi, conf
		}
	}
	return env
}

func answered(t model.Trial) bool {
	return t.Features.ResponseClass == "syn-ack" || t.Features.ResponseClass == "rst-ack"
}

// withoutSACK removes SACK-permitted and NOP/EOL padding, so the changed
// variable and the alignment it causes are excluded from stability checks.
func withoutSACK(b []byte) []byte {
	var out []byte
	for i := 0; i < len(b); {
		if b[i] == 0 {
			break
		}
		if b[i] == 1 {
			i++
			continue
		}
		if i+2 > len(b) || b[i+1] < 2 || i+int(b[i+1]) > len(b) {
			return append(out, b[i:]...)
		}
		if b[i] != 4 {
			out = append(out, b[i:i+int(b[i+1])]...)
		}
		i += int(b[i+1])
	}
	return out
}

// median is the lower median of a copy, so it is an observed integer value.
func median(v []int64) int64 {
	s := slices.Clone(v)
	slices.Sort(s)
	return s[(len(s)-1)/2]
}

// medianInterval returns the order-statistic interval [x(k), x(n-k+1)] with
// the largest k whose exact binomial coverage is at least the target.
func medianInterval(v []int64, target float64) (int64, int64, float64, bool) {
	n := len(v)
	s := slices.Clone(v)
	slices.Sort(s)
	best, coverage := 0, 0.0
	for k := 1; k <= n/2; k++ {
		c := 1 - 2*binomialCDF(k-1, n, 0.5)
		if c < target {
			break
		}
		best, coverage = k, c
	}
	if best == 0 {
		return 0, 0, 0, false
	}
	return s[best-1], s[n-best], coverage, true
}

func binomialCDF(k, n int, p float64) float64 {
	if k < 0 {
		return 0
	}
	if k >= n {
		return 1
	}
	if p <= 0 {
		return 1
	}
	if p >= 1 {
		return 0
	}
	sum := 0.0
	for i := 0; i <= k; i++ {
		sum += math.Exp(logChoose(n, i) + float64(i)*math.Log(p) + float64(n-i)*math.Log1p(-p))
	}
	return math.Min(1, sum)
}

func logChoose(n, k int) float64 {
	a, _ := math.Lgamma(float64(n + 1))
	b, _ := math.Lgamma(float64(k + 1))
	c, _ := math.Lgamma(float64(n - k + 1))
	return a - b - c
}

// hypergeometric is the probability of the 2x2 table [[a,b],[c,d]] given its margins.
func hypergeometric(a, b, c, d int) float64 {
	return math.Exp(logChoose(a+b, a) + logChoose(c+d, c) - logChoose(a+b+c+d, a+c))
}

// fisherLower is the one-sided Fisher exact p-value that row one has fewer
// column-one outcomes than expected when rows are exchangeable.
func fisherLower(a, b, c, d int) float64 {
	if a+b == 0 || c+d == 0 || a+c == 0 || b+d == 0 {
		return 1
	}
	sum := 0.0
	for x := max(0, a-d); x <= a; x++ {
		sum += hypergeometric(x, a+b-x, a+c-x, d-a+x)
	}
	return math.Min(1, sum)
}

// fisherTwoSided sums every table at most as probable as the observed one.
func fisherTwoSided(a, b, c, d int) float64 {
	if a+b == 0 || c+d == 0 || a+c == 0 || b+d == 0 {
		return 1
	}
	observed := hypergeometric(a, b, c, d)
	sum := 0.0
	for x := max(0, a-d); x <= min(a+b, a+c); x++ {
		if p := hypergeometric(x, a+b-x, a+c-x, d-a+x); p <= observed*(1+1e-9) {
			sum += p
		}
	}
	return math.Min(1, sum)
}
