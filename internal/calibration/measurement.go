package calibration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// Registration is a plan frozen before collecting predictions. Its content hash
// must be retained in an external dated record; an embedded timestamp alone
// cannot demonstrate preregistration. All planned cases must be accounted for.
type Registration struct {
	ID           string        `json:"id"`
	RegisteredAt time.Time     `json:"registered_at"`
	RecordRef    string        `json:"record_ref"`
	Population   string        `json:"population"`
	ModelRef     string        `json:"model_ref"`
	Cases        []PlannedCase `json:"cases"`
}

type PlannedCase struct {
	ID      string `json:"id"`
	Group   string `json:"group"`
	Split   string `json:"split"`
	Kind    string `json:"kind"`
	Model   string `json:"model"`
	Stratum string `json:"stratum"`
}

// Measurement names independently checked truth and retained raw artifacts.
// Hashes establish artifact identity, not accuracy or independence of labels.
// CounterSource describes exactly what packets were counted (e.g. independent
// capture, scanner TX only); ClockSource identifies the duration measurement.
type Measurement struct {
	ObservedAt     time.Time `json:"observed_at"`
	TruthRef       string    `json:"truth_ref"`
	EvidenceSHA256 string    `json:"evidence_sha256"`
	CounterSource  string    `json:"counter_source"`
	ClockSource    string    `json:"clock_source"`
}

type Interval struct {
	Lower float64 `json:"lower"`
	Upper float64 `json:"upper"`
}

type RateIntervals struct {
	Correct     Interval `json:"correct"`
	FalseMatch  Interval `json:"false_match"`
	MissedMatch Interval `json:"missed_match"`
	Unknown     Interval `json:"unknown"`
}

// wilson returns a two-sided 95% binomial interval. This is conditional on IID
// cases, not a claim of independent targets, cluster-adjusted uncertainty, or a
// confidence interval on ECE/Brier.
func wilson(k, n int) Interval {
	const z = 1.959963984540054
	p, count := float64(k)/float64(n), float64(n)
	denominator := 1 + z*z/count
	center := (p + z*z/(2*count)) / denominator
	half := z * math.Sqrt(p*(1-p)/count+z*z/(4*count*count)) / denominator
	return Interval{Lower: math.Max(0, center-half), Upper: math.Min(1, center+half)}
}

func validateRegistration(dataset Dataset) (string, error) {
	if dataset.Schema == Schema {
		if dataset.Registration != nil {
			return "", errors.New("registration requires calibration/v2")
		}
		for _, c := range dataset.Cases {
			if c.Measurement != nil {
				return "", errors.New("measurement provenance requires calibration/v2")
			}
		}
		return "", nil
	}
	r := dataset.Registration
	if r == nil || strings.TrimSpace(r.ID) == "" || r.RegisteredAt.IsZero() || strings.TrimSpace(r.RecordRef) == "" || strings.TrimSpace(r.Population) == "" || strings.TrimSpace(r.ModelRef) == "" || len(r.Cases) != len(dataset.Cases) {
		return "", errors.New("v2 requires a dated registration, record ref, population, frozen model ref and every planned case")
	}
	planned := make(map[string]PlannedCase, len(r.Cases))
	for _, p := range r.Cases {
		if strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.Stratum) == "" {
			return "", errors.New("registration requires case ids and explicit strata")
		}
		if _, ok := planned[p.ID]; ok {
			return "", fmt.Errorf("duplicate registered case %q", p.ID)
		}
		planned[p.ID] = p
	}
	for _, c := range dataset.Cases {
		p, ok := planned[c.ID]
		if !ok || p != (PlannedCase{ID: c.ID, Group: c.Group, Split: c.Split, Kind: c.Kind, Model: c.Model, Stratum: c.Stratum}) {
			return "", fmt.Errorf("case %q differs from its registered assignment", c.ID)
		}
		delete(planned, c.ID)
		m := c.Measurement
		if m == nil || !m.ObservedAt.After(r.RegisteredAt) || strings.TrimSpace(m.TruthRef) == "" || strings.TrimSpace(m.TruthRef) == strings.TrimSpace(c.EvidenceRef) || strings.TrimSpace(m.CounterSource) == "" || strings.TrimSpace(m.ClockSource) == "" || !validSHA256(m.EvidenceSHA256) {
			return "", fmt.Errorf("case %q requires post-registration measurement, separate truth ref, evidence SHA-256, counter and clock provenance", c.ID)
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(c.LabelSource)), "synthetic:") || strings.HasPrefix(strings.ToLower(strings.TrimSpace(c.EvidenceRef)), "fixture:") {
			return "", fmt.Errorf("case %q: synthetic fixtures cannot supply measured v2 evidence", c.ID)
		}
	}
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func validSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}
