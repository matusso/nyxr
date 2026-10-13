// Package calibration evaluates labeled ordinary claims offline. It does not
// alter scanner inference or HORIZON experimental statistics.
package calibration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
)

const Schema = "nyxr/calibration/v1"
const maxDatasetBytes = 8 << 20
const maxCases = 10000

// Case is a ground-truth comparison for one ordinary service, device, stack,
// port-state or asset-link claim. Group identifies a physical fixture or
// identity and may occur in only one split, preventing repeated observations
// of the same target from leaking from tuning into held-out evaluation.
type Case struct {
	ID          string   `json:"id"`
	Split       string   `json:"split"`
	Group       string   `json:"group"`
	Kind        string   `json:"kind"`
	Model       string   `json:"model"`
	LabelSource string   `json:"label_source"`
	EvidenceRef string   `json:"evidence_ref"`
	Truth       string   `json:"truth"`
	Prediction  string   `json:"prediction"`
	Score       *float64 `json:"score,omitempty"`
	PacketsTX   int      `json:"packets_tx"`
	DurationNS  int64    `json:"duration_ns"`
}

type Dataset struct {
	Schema string `json:"schema"`
	ID     string `json:"id"`
	Cases  []Case `json:"cases"`
}

type Metrics struct {
	Split           string  `json:"split"`
	Kind            string  `json:"kind"`
	Model           string  `json:"model"`
	Count           int     `json:"count"`
	Scored          int     `json:"scored"`
	Correct         int     `json:"correct"`
	FalseMatches    int     `json:"false_matches"`
	MissedMatches   int     `json:"missed_matches"`
	Unknown         int     `json:"unknown"`
	CorrectRate     float64 `json:"correct_rate"`
	FalseMatchRate  float64 `json:"false_match_rate"`
	MissedMatchRate float64 `json:"missed_match_rate"`
	UnknownRate     float64 `json:"unknown_rate"`
	PacketsTX       int64   `json:"packets_tx"`
	DurationNS      int64   `json:"duration_ns"`
	// ECE and Brier are diagnostics on the supplied scores, not proof that
	// the model is calibrated beyond this labeled population.
	ECE   *float64 `json:"diagnostic_ece,omitempty"`
	Brier *float64 `json:"diagnostic_brier,omitempty"`
}

type Report struct {
	Schema           string    `json:"schema"`
	DatasetID        string    `json:"dataset_id"`
	DatasetSHA256    string    `json:"dataset_sha256"`
	CalibrationClaim string    `json:"calibration_claim"`
	Results          []Metrics `json:"results"`
}

type accumulator struct {
	metrics Metrics
	binN    [10]int
	binP    [10]float64
	binY    [10]float64
	brier   float64
}

func Evaluate(reader io.Reader) (Report, error) {
	var report Report
	data, err := io.ReadAll(io.LimitReader(reader, maxDatasetBytes+1))
	if err != nil {
		return report, err
	}
	if len(data) > maxDatasetBytes {
		return report, errors.New("calibration dataset exceeds 8 MiB")
	}
	var dataset Dataset
	if err := json.Unmarshal(data, &dataset); err != nil {
		return report, err
	}
	if dataset.Schema != Schema || dataset.ID == "" || len(dataset.Cases) == 0 || len(dataset.Cases) > maxCases {
		return report, errors.New("invalid calibration dataset schema, id or case count")
	}
	groups, ids, splits := map[string]string{}, map[string]bool{}, map[string]bool{}
	acc := map[string]*accumulator{}
	for _, c := range dataset.Cases {
		if err := validateCase(c); err != nil {
			return report, fmt.Errorf("case %q: %w", c.ID, err)
		}
		if ids[c.ID] {
			return report, fmt.Errorf("duplicate case id %q", c.ID)
		}
		ids[c.ID] = true
		if previous, ok := groups[c.Group]; ok && previous != c.Split {
			return report, fmt.Errorf("group %q occurs in tuning and holdout", c.Group)
		}
		groups[c.Group], splits[c.Split] = c.Split, true
		key := c.Split + "\x00" + c.Kind + "\x00" + c.Model
		a := acc[key]
		if a == nil {
			a = &accumulator{metrics: Metrics{Split: c.Split, Kind: c.Kind, Model: c.Model}}
			acc[key] = a
		}
		m := &a.metrics
		m.Count++
		m.PacketsTX += int64(c.PacketsTX)
		m.DurationNS += c.DurationNS
		unknown := c.Prediction == "" || c.Prediction == "unknown"
		if unknown {
			m.Unknown++
		}
		correct := !unknown && c.Prediction == c.Truth
		if correct {
			m.Correct++
		}
		if !unknown && !correct {
			m.FalseMatches++
		}
		if !correct && c.Truth != "unknown" {
			m.MissedMatches++
		}
		if c.Score != nil && !unknown {
			m.Scored++
			p, y := *c.Score, 0.0
			if correct {
				y = 1
			}
			bin := int(p * 10)
			if bin == 10 {
				bin = 9
			}
			a.binN[bin]++
			a.binP[bin] += p
			a.binY[bin] += y
			a.brier += (p - y) * (p - y)
		}
	}
	if !splits["tuning"] || !splits["holdout"] {
		return report, errors.New("dataset requires disjoint tuning and holdout cases")
	}
	hash := sha256.Sum256(data)
	report = Report{Schema: Schema, DatasetID: dataset.ID, DatasetSHA256: "sha256:" + hex.EncodeToString(hash[:]),
		CalibrationClaim: "diagnostic only; scores remain heuristic pending representative held-out validation"}
	for _, a := range acc {
		m := a.metrics
		m.CorrectRate = float64(m.Correct) / float64(m.Count)
		m.FalseMatchRate = float64(m.FalseMatches) / float64(m.Count)
		m.MissedMatchRate = float64(m.MissedMatches) / float64(m.Count)
		m.UnknownRate = float64(m.Unknown) / float64(m.Count)
		if m.Scored > 0 {
			var ece float64
			for i, n := range a.binN {
				if n > 0 {
					ece += float64(n) / float64(m.Scored) * math.Abs(a.binP[i]/float64(n)-a.binY[i]/float64(n))
				}
			}
			brier := a.brier / float64(m.Scored)
			m.ECE, m.Brier = &ece, &brier
		}
		report.Results = append(report.Results, m)
	}
	sort.Slice(report.Results, func(i, j int) bool {
		a, b := report.Results[i], report.Results[j]
		if a.Split != b.Split {
			return a.Split < b.Split
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Model < b.Model
	})
	return report, nil
}

func validateCase(c Case) error {
	if c.ID == "" || c.Group == "" || c.Model == "" || c.LabelSource == "" || c.EvidenceRef == "" || c.Truth == "" {
		return errors.New("missing id, group, model, label source, evidence ref or truth")
	}
	if c.Split != "tuning" && c.Split != "holdout" {
		return errors.New("split must be tuning or holdout")
	}
	switch c.Kind {
	case "port_state", "protocol", "product", "os", "device", "asset_link":
	default:
		return errors.New("unsupported claim kind")
	}
	if c.PacketsTX < 0 || c.DurationNS < 0 {
		return errors.New("negative packet or time cost")
	}
	if c.Score != nil && (math.IsNaN(*c.Score) || math.IsInf(*c.Score, 0) || *c.Score < 0 || *c.Score > 1 || strings.TrimSpace(c.Prediction) == "") {
		return errors.New("score must be in [0,1] with a prediction")
	}
	return nil
}
