package horizon

import (
	"math"

	"github.com/matusso/nyxr/internal/horizon/model"
)

func sack(b []byte) bool {
	for i := 0; i < len(b); {
		if b[i] == 0 {
			return false
		}
		if b[i] == 1 {
			i++
			continue
		}
		if i+2 > len(b) || b[i+1] < 2 || i+int(b[i+1]) > len(b) {
			return false
		}
		if b[i] == 4 && b[i+1] == 2 {
			return true
		}
		i += int(b[i+1])
	}
	return false
}

// Compare uses one pre-registered binary outcome and an exact two-sided
// sign test of discordant pairs (McNemar's exact conditional test).
// Missing/poor-quality trials are not silently removed to hide attrition.
func Compare(r model.Report) model.Comparison {
	c := model.Comparison{Status: "unresolved", Conclusion: "insufficient or confounded evidence", PValue: 1}
	if r.Experiment.APIVersion == model.GeneralVersion {
		if r.Experiment.Spec.ChangedVariable != "sackPermitted" {
			c.Conclusion = "exploratory sequence observations; inference is not implemented"
			return c
		}
		for _, t := range r.Trials {
			if t.Probe != 0 {
				c.Conclusion = "multi-probe sequence observations; inference is not implemented"
				return c
			}
		}
	}
	pairs := make(map[int]map[string]model.Trial)
	for _, t := range r.Trials {
		if t.Features.ResponseClass != "syn-ack" || len(t.QualityFlags) > 0 {
			continue
		}
		if pairs[t.Pair] == nil {
			pairs[t.Pair] = make(map[string]model.Trial)
		}
		pairs[t.Pair][t.Arm] = t
	}
	for _, pair := range pairs {
		a, aok := pair["control"]
		b, bok := pair["treatment"]
		if !aok || !bok {
			continue
		}
		c.CompletePairs++
		x, y := sack(a.Features.TCPOptions), sack(b.Features.TCPOptions)
		if x && !y {
			c.ControlOnlySACK++
		}
		if !x && y {
			c.TreatmentOnlySACK++
		}
	}
	c.DiscordantPairs = c.ControlOnlySACK + c.TreatmentOnlySACK
	if c.DiscordantPairs > 0 {
		n, k := c.DiscordantPairs, min(c.ControlOnlySACK, c.TreatmentOnlySACK)
		term := math.Pow(0.5, float64(n))
		sum := term
		for i := 1; i <= k; i++ {
			term *= float64(n-i+1) / float64(i)
			sum += term
		}
		c.PValue = math.Min(1, 2*sum)
	}
	if !r.Completed || r.BackendDrops > 0 || (r.CaptureArtifact != nil && r.CaptureArtifact.Dropped > 0) || c.CompletePairs < 8 || c.CompletePairs != r.Experiment.Spec.Execution.Replicates {
		return c
	}
	c.Status = "inferred"
	c.Conclusion = "no detectable difference in SACK permission"
	if c.PValue <= 0.05 {
		c.Conclusion = "SACK permission response differs between paired arms; causal explanation unresolved"
	}
	return c
}
