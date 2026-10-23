package horizon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"time"

	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/horizon/model"
)

const CalibrationVersion = "horizon-calibration/v1"

// CalibrationProtocol pre-registers synthetic decision-rule calibration. It
// exercises the compiled schedule, environment gates and paired comparison;
// it sends no traffic and is not evidence about any real network.
type CalibrationProtocol struct {
	Version              string                `json:"version"`
	ID                   string                `json:"id"`
	RegisteredAt         string                `json:"registeredAt"`
	Seed                 int64                 `json:"seed"`
	RunsPerScenario      int                   `json:"runsPerScenario"`
	Replicates           int                   `json:"replicates"`
	ReferenceEvery       int                   `json:"referenceEvery"`
	Alpha                float64               `json:"alpha"`
	Confidence           float64               `json:"confidence"`
	MaxFalsePositiveRate float64               `json:"maxFalsePositiveRate"`
	MinimumPower         float64               `json:"minimumPower"`
	Scenarios            []CalibrationScenario `json:"scenarios"`
}

// CalibrationScenario is a generative model of one trial population.
// Probabilities are per answered trial; RTT values are milliseconds.
type CalibrationScenario struct {
	Name          string  `json:"name"`
	Gate          string  `json:"gate"` // false-positive, power or descriptive
	Variable      string  `json:"variable"`
	ControlSACK   float64 `json:"controlSack"`
	TreatmentSACK float64 `json:"treatmentSack"`
	Loss          float64 `json:"loss"`
	BaseRTTMS     float64 `json:"baseRttMs"`
	JitterMS      float64 `json:"jitterMs"`
	DriftMS       float64 `json:"driftMs"`
	ThrottleAfter float64 `json:"throttleAfter"`
	ThrottleLoss  float64 `json:"throttleLoss"`
	// TreatmentFirstOnly confines the effect to treatment-first pairs (carryover).
	TreatmentFirstOnly bool `json:"treatmentFirstOnly"`
}

type CalibrationResult struct {
	Name         string         `json:"name"`
	Gate         string         `json:"gate"`
	Runs         int            `json:"runs"`
	Difference   int            `json:"difference"`
	WrongDirect  int            `json:"wrongDirection"`
	NoDifference int            `json:"noDifference"`
	Unresolved   int            `json:"unresolved"`
	GatingFlags  map[string]int `json:"gatingFlags"`
	Rate         float64        `json:"rate"`
	Bound        float64        `json:"bound"`
	BoundKind    string         `json:"boundKind,omitempty"`
	Passed       *bool          `json:"passed"`
}

type CalibrationReport struct {
	Version        string              `json:"version"`
	ProtocolID     string              `json:"protocolId"`
	ProtocolSHA256 string              `json:"protocolSha256"`
	Passed         bool                `json:"passed"`
	Results        []CalibrationResult `json:"results"`
	Limitations    []string            `json:"limitations"`
}

// LoadCalibrationProtocol reads a bounded, strict protocol and its hash.
func LoadCalibrationProtocol(r io.Reader) (CalibrationProtocol, string, error) {
	var p CalibrationProtocol
	b, err := io.ReadAll(io.LimitReader(r, (64<<10)+1))
	if err != nil {
		return p, "", err
	}
	if len(b) > 64<<10 {
		return p, "", errors.New("calibration protocol exceeds 64 KiB")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, "", err
	}
	if d.More() {
		return p, "", errors.New("calibration protocol has trailing data")
	}
	h := sha256.Sum256(b)
	return p, hex.EncodeToString(h[:]), nil
}

func (p CalibrationProtocol) validate() error {
	if p.Version != CalibrationVersion || p.ID == "" || p.RegisteredAt == "" {
		return errors.New("calibration protocol requires version, id and registeredAt")
	}
	if _, err := time.Parse(time.RFC3339, p.RegisteredAt); err != nil {
		return fmt.Errorf("registeredAt: %w", err)
	}
	// The runner's alpha is fixed; a protocol cannot register a different one.
	if p.Alpha != 0.05 || p.Confidence <= 0.5 || p.Confidence >= 1 || p.MaxFalsePositiveRate <= 0 || p.MaxFalsePositiveRate >= 1 || p.MinimumPower <= 0 || p.MinimumPower > 1 {
		return errors.New("invalid alpha, confidence or registered thresholds")
	}
	if p.RunsPerScenario < 1 || p.RunsPerScenario > 5000 || len(p.Scenarios) == 0 || len(p.Scenarios) > 32 {
		return errors.New("require 1..5000 runs and 1..32 scenarios")
	}
	gates := map[string]bool{}
	for _, s := range p.Scenarios {
		probabilities := []float64{s.ControlSACK, s.TreatmentSACK, s.Loss, s.ThrottleAfter, s.ThrottleLoss}
		for _, v := range probabilities {
			if v < 0 || v > 1 || math.IsNaN(v) {
				return fmt.Errorf("scenario %q has an invalid probability", s.Name)
			}
		}
		if s.Name == "" || s.BaseRTTMS <= 0 || s.JitterMS < 0 || s.DriftMS < 0 || (s.Variable != "sackPermitted" && s.Variable != "none") {
			return fmt.Errorf("scenario %q needs a name, variable and positive RTT", s.Name)
		}
		if s.Gate != "false-positive" && s.Gate != "power" && s.Gate != "descriptive" {
			return fmt.Errorf("scenario %q has unknown gate %q", s.Name, s.Gate)
		}
		if s.Variable == "none" && (s.ControlSACK != s.TreatmentSACK || s.TreatmentFirstOnly) {
			return fmt.Errorf("A/A scenario %q must have identical arms", s.Name)
		}
		gates[s.Gate] = true
	}
	if !gates["false-positive"] || !gates["power"] {
		return errors.New("protocol must register at least one false-positive and one power scenario")
	}
	return nil
}

// Calibrate is deterministic for a protocol. Every planned run stays in each
// denominator; unresolved runs are neither detections nor null successes.
func Calibrate(p CalibrationProtocol, protocolHash string) (CalibrationReport, error) {
	out := CalibrationReport{Version: CalibrationVersion, ProtocolID: p.ID, ProtocolSHA256: protocolHash, Passed: true,
		Limitations: []string{"Synthetic generative model: calibrates the decision rules and environment gates only, not live network behavior or capture.",
			"Runs are independent by construction; live trials may be dependent and nonstationary.",
			"Bounds are exact one-sided Clopper-Pearson binomial bounds over all planned runs."}}
	if err := p.validate(); err != nil {
		return out, err
	}
	for si, s := range p.Scenarios {
		res := CalibrationResult{Name: s.Name, Gate: s.Gate, Runs: p.RunsPerScenario, GatingFlags: map[string]int{}}
		for run := 0; run < p.RunsPerScenario; run++ {
			seed := p.Seed + int64(si)*1_000_003 + int64(run)
			r, err := syntheticReport(p, s, seed)
			if err != nil {
				return out, fmt.Errorf("scenario %s: %w", s.Name, err)
			}
			for _, f := range r.Environment.GatingFlags {
				res.GatingFlags[f]++
			}
			c := r.Comparison
			switch {
			case c.Status != "inferred":
				res.Unresolved++
			case c.PValue > p.Alpha:
				res.NoDifference++
			case c.TreatmentOnlySACK > c.ControlOnlySACK || s.Gate == "false-positive":
				res.Difference++
			default:
				res.WrongDirect++
			}
		}
		passed := true
		switch s.Gate {
		case "false-positive":
			errorsFound := res.Difference + res.WrongDirect
			res.Rate = float64(errorsFound) / float64(res.Runs)
			res.Bound, res.BoundKind = clopperPearsonUpper(errorsFound, res.Runs, 1-p.Confidence), "upper"
			passed = res.Bound <= p.MaxFalsePositiveRate
		case "power":
			res.Rate = float64(res.Difference) / float64(res.Runs)
			res.Bound, res.BoundKind = clopperPearsonLower(res.Difference, res.Runs, 1-p.Confidence), "lower"
			passed = res.Rate >= p.MinimumPower && res.WrongDirect == 0
		default:
			res.Rate = float64(res.Difference) / float64(res.Runs)
		}
		if s.Gate != "descriptive" {
			res.Passed = &passed
			out.Passed = out.Passed && passed
		}
		out.Results = append(out.Results, res)
	}
	return out, nil
}

// syntheticReport fills the exact compiled schedule with generated features.
func syntheticReport(p CalibrationProtocol, s CalibrationScenario, seed int64) (model.Report, error) {
	treatment := "sack-permitted"
	if s.Variable == "none" {
		treatment = "baseline"
	}
	arm := func(profile string) model.Sequence {
		return model.Sequence{Steps: []model.Step{{Send: &model.Send{Protocol: "tcp", Flags: []string{"SYN"}, DstPort: 443, OptionsProfile: profile}}, {Observe: &model.Observe{WindowMS: 800}}}}
	}
	e := model.Experiment{APIVersion: model.GeneralVersion, Kind: "Experiment", Metadata: model.Metadata{Name: "calibration"}, Spec: model.Spec{
		Scope: model.Scope{Targets: []string{"192.0.2.10"}, TCPPorts: []uint16{443}}, ChangedVariable: s.Variable,
		Control: arm("baseline"), Treatment: arm(treatment),
		Execution: model.Execution{Replicates: p.Replicates, RandomizedOrder: true, Seed: seed, ReferenceEvery: p.ReferenceEvery},
		Limits:    model.Limits{MaxPackets: 200, MaxDurationSeconds: 1800, PacketsPerSecond: 10, MaxConcurrentFlows: 1, MaxReceiveFrames: 16, MaxMemoryBytes: 2 << 20},
		Capture:   model.Capture{MaxBytes: 1 << 20}}}
	plan, err := dsl.Compile(e, model.Policy{Profile: "lab", AllowTargets: []string{"192.0.2.10/32"}, AllowPorts: []uint16{443}})
	if err != nil {
		return model.Report{}, err
	}
	rng := rand.New(rand.NewSource(seed))
	r := model.Report{APIVersion: plan.APIVersion, Kind: "EvidenceReport", Experiment: plan.Experiment, ExperimentHash: plan.Hash, Completed: true, Backend: "synthetic/calibration"}
	first := map[int]string{}
	at := time.Unix(0, 0).UTC()
	for i, planned := range plan.Trials {
		if _, ok := first[planned.Pair]; !ok && planned.Arm != "reference" {
			first[planned.Pair] = planned.Arm
		}
		t := model.Trial{Probe: planned.Probe, Pair: planned.Pair, Arm: planned.Arm, SentAt: at, QualityFlags: []string{}, Features: model.Features{ResponseClass: "no-response"}}
		position := float64(i) / float64(len(plan.Trials))
		loss := s.Loss
		if s.ThrottleLoss > 0 && position >= s.ThrottleAfter {
			loss = s.ThrottleLoss
		}
		if rng.Float64() < loss {
			t.QualityFlags = append(t.QualityFlags, "timeout")
		} else {
			probability := s.ControlSACK
			if planned.Arm == "treatment" && (!s.TreatmentFirstOnly || first[planned.Pair] == "treatment") {
				probability = s.TreatmentSACK
			}
			options := []byte{2, 4, 5, 180}
			if rng.Float64() < probability {
				options = append(options, 4, 2, 1, 1)
			}
			rtt := s.BaseRTTMS + s.DriftMS*position + math.Abs(rng.NormFloat64())*s.JitterMS
			t.Features = model.Features{ResponseClass: "syn-ack", TTL: 64, TCPOptions: options, RTTNS: int64(rtt * 1e6), Correlation: "exact", ResponseSource: "192.0.2.10"}
		}
		r.Trials = append(r.Trials, t)
		at = at.Add(time.Second)
	}
	r.Environment = Assess(r)
	r.Comparison = Compare(r)
	return r, nil
}

// clopperPearsonUpper is the exact one-sided upper bound for k of n events.
func clopperPearsonUpper(k, n int, alpha float64) float64 {
	if k >= n {
		return 1
	}
	return bisect(func(p float64) bool { return binomialCDF(k, n, p) > alpha })
}

// clopperPearsonLower is the exact one-sided lower bound for k of n events.
func clopperPearsonLower(k, n int, alpha float64) float64 {
	if k <= 0 {
		return 0
	}
	return bisect(func(p float64) bool { return 1-binomialCDF(k-1, n, p) < alpha })
}

// bisect finds the boundary of a predicate that is true below it on [0,1].
func bisect(below func(float64) bool) float64 {
	lo, hi := 0.0, 1.0
	for i := 0; i < 64; i++ {
		mid := (lo + hi) / 2
		if below(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	return (lo + hi) / 2
}
