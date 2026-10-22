package calibration

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

// This metadata-only test dataset is not measured evidence and is never
// delivered as a corpus or used to claim scanner accuracy.
func registeredTestDataset() Dataset {
	at := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	d := Dataset{Schema: MeasuredSchema, ID: "validation-test"}
	d.Registration = &Registration{ID: "plan-test", RegisteredAt: at, RecordRef: "test:dated-plan", Population: "test metadata", ModelRef: "test:frozen-source"}
	for _, split := range []string{"tuning", "holdout"} {
		for _, stratum := range []string{"clean", "impaired"} {
			id := split + "-" + stratum
			d.Registration.Cases = append(d.Registration.Cases, PlannedCase{ID: id, Group: split, Split: split, Kind: "protocol", Model: "test/v1", Stratum: stratum})
			d.Cases = append(d.Cases, Case{ID: id, Group: split, Split: split, Kind: "protocol", Model: "test/v1", Stratum: stratum,
				LabelSource: "test:independent-label", EvidenceRef: "test:" + id, Truth: "ssh", Prediction: "unknown", PacketsTX: 2, DurationNS: 100,
				Measurement: &Measurement{ObservedAt: at.Add(time.Hour), TruthRef: "test:host-config", EvidenceSHA256: "sha256:" + strings.Repeat("a", 64), CounterSource: "test:scanner-tx", ClockSource: "test:monotonic-elapsed"}})
		}
	}
	return d
}

func evaluateDataset(d Dataset) (Report, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return Report{}, err
	}
	return Evaluate(strings.NewReader(string(data)))
}

func TestMeasuredRegistrationAndStrata(t *testing.T) {
	d := registeredTestDataset()
	r, err := evaluateDataset(d)
	if err != nil {
		t.Fatal(err)
	}
	if r.Schema != MeasuredSchema || !validSHA256(r.RegistrationSHA256) || len(r.Results) != 4 || len(r.Limitations) < 4 {
		t.Fatalf("incomplete measured report: %+v", r)
	}
	for _, m := range r.Results {
		if m.Count != 1 || m.Groups != 1 || m.Unknown != 1 || m.MissedMatches != 1 || m.Scored != 0 || m.ECE != nil || m.UnknownRate != 1 || m.PacketsTX != 2 || m.DurationNS != 100 {
			t.Fatalf("unknown measurements must remain in their stratum: %+v", m)
		}
	}
	d.Registration.Population = "changed population"
	changed, err := evaluateDataset(d)
	if err != nil || changed.RegistrationSHA256 == r.RegistrationSHA256 {
		t.Fatalf("registration hash did not change: %v", err)
	}
}

func TestRejectsInvalidMeasurementProvenance(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Dataset)
	}{
		{"no plan", func(d *Dataset) { d.Registration = nil }},
		{"missing planned outcome", func(d *Dataset) { d.Cases = d.Cases[:3] }},
		{"unplanned outcome", func(d *Dataset) { d.Cases[0].ID = "extra" }},
		{"changed split", func(d *Dataset) { d.Cases[0].Split = "holdout" }},
		{"changed stratum", func(d *Dataset) { d.Cases[0].Stratum = "different" }},
		{"duplicate planned id", func(d *Dataset) { d.Registration.Cases[1] = d.Registration.Cases[0] }},
		{"no stratum", func(d *Dataset) { d.Registration.Cases[0].Stratum = ""; d.Cases[0].Stratum = "" }},
		{"no frozen model", func(d *Dataset) { d.Registration.ModelRef = "" }},
		{"no external record", func(d *Dataset) { d.Registration.RecordRef = "" }},
		{"no measurement", func(d *Dataset) { d.Cases[0].Measurement = nil }},
		{"predates registration", func(d *Dataset) { d.Cases[0].Measurement.ObservedAt = d.Registration.RegisteredAt.Add(-time.Second) }},
		{"same time as registration", func(d *Dataset) { d.Cases[0].Measurement.ObservedAt = d.Registration.RegisteredAt }},
		{"no independent truth", func(d *Dataset) { d.Cases[0].Measurement.TruthRef = "" }},
		{"circular truth", func(d *Dataset) { d.Cases[0].Measurement.TruthRef = d.Cases[0].EvidenceRef }},
		{"invalid artifact hash", func(d *Dataset) { d.Cases[0].Measurement.EvidenceSHA256 = "sha256:bad" }},
		{"no counter provenance", func(d *Dataset) { d.Cases[0].Measurement.CounterSource = "" }},
		{"no clock provenance", func(d *Dataset) { d.Cases[0].Measurement.ClockSource = "" }},
		{"synthetic labels", func(d *Dataset) { d.Cases[0].LabelSource = "synthetic:ssh" }},
		{"synthetic evidence", func(d *Dataset) { d.Cases[0].EvidenceRef = "fixture:ssh" }},
		{"v1 registration ignored", func(d *Dataset) { d.Schema = Schema }},
		{"v1 measurement ignored", func(d *Dataset) { d.Schema = Schema; d.Registration = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := registeredTestDataset()
			tt.change(&d)
			if _, err := evaluateDataset(d); err == nil {
				t.Fatal("accepted invalid measured dataset")
			}
		})
	}
}

func TestConditionalWilsonIntervals(t *testing.T) {
	for _, test := range []struct {
		k, n         int
		lower, upper float64
	}{
		{0, 1, 0, 0.7934506856},
		{1, 1, 0.2065493144, 1},
		{5, 10, 0.2365930905, 0.7634069095},
		{0, 60, 0, 0.0601718521},
	} {
		got := wilson(test.k, test.n)
		if math.Abs(got.Lower-test.lower) > 1e-9 || math.Abs(got.Upper-test.upper) > 1e-9 {
			t.Fatalf("wilson(%d,%d) = %+v", test.k, test.n, got)
		}
	}
}

func TestRejectsCostOverflow(t *testing.T) {
	d := registeredTestDataset()
	d.Cases[1].Stratum = d.Cases[0].Stratum
	d.Registration.Cases[1].Stratum = d.Cases[0].Stratum
	d.Cases[0].DurationNS = math.MaxInt64
	if _, err := evaluateDataset(d); err == nil || !strings.Contains(err.Error(), "overflows") {
		t.Fatalf("expected aggregate overflow rejection: %v", err)
	}
}

func TestRepeatedGroupsNotIndependentTargets(t *testing.T) {
	d := registeredTestDataset()
	d.Cases[1].Stratum = d.Cases[0].Stratum
	d.Registration.Cases[1].Stratum = d.Cases[0].Stratum
	r, err := evaluateDataset(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range r.Results {
		if m.Split == "tuning" && (m.Count != 2 || m.Groups != 1) {
			t.Fatalf("repeated observations inflated group count: %+v", m)
		}
	}
}

func TestMeasuredCostsMustBeExplicit(t *testing.T) {
	for _, field := range []string{"packets_tx", "duration_ns"} {
		for _, value := range []string{"missing", "null"} {
			t.Run(field+"-"+value, func(t *testing.T) {
				data, err := json.Marshal(registeredTestDataset())
				if err != nil {
					t.Fatal(err)
				}
				var raw map[string]any
				if err := json.Unmarshal(data, &raw); err != nil {
					t.Fatal(err)
				}
				first := raw["cases"].([]any)[0].(map[string]any)
				if value == "missing" {
					delete(first, field)
				} else {
					first[field] = nil
				}
				data, err = json.Marshal(raw)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Evaluate(strings.NewReader(string(data))); err == nil || !strings.Contains(err.Error(), "explicit "+field) {
					t.Fatalf("missing cost became an observed zero: %v", err)
				}
			})
		}
	}
}

func TestScoreDiagnosticsAndClaimSeparation(t *testing.T) {
	d := registeredTestDataset()
	d.Cases[1].Stratum = d.Cases[0].Stratum
	d.Registration.Cases[1].Stratum = d.Cases[0].Stratum
	score := 0.8
	d.Cases[0].Prediction, d.Cases[0].Score = "ssh", &score
	d.Cases[1].Prediction, d.Cases[1].Score = "http", &score
	// A claim on the same group remains a separate kind, even with the same
	// model and stratum; never pool port state with protocol confidence.
	c := d.Cases[0]
	c.ID, c.Kind, c.Truth, c.Prediction = "port", "port_state", "open", "open"
	d.Cases = append(d.Cases, c)
	d.Registration.Cases = append(d.Registration.Cases, PlannedCase{ID: c.ID, Group: c.Group, Split: c.Split, Kind: c.Kind, Model: c.Model, Stratum: c.Stratum})
	r, err := evaluateDataset(d)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range r.Results {
		if m.Split != "tuning" || m.Kind != "protocol" {
			continue
		}
		found = true
		if m.Count != 2 || m.Correct != 1 || m.FalseMatches != 1 || m.MissedMatches != 1 || m.Scored != 2 || m.ECE == nil || m.Brier == nil || math.Abs(*m.ECE-0.3) > 1e-12 || math.Abs(*m.Brier-0.34) > 1e-12 {
			t.Fatalf("score diagnostics or denominators changed: %+v", m)
		}
	}
	if !found {
		t.Fatal("protocol stratum absent")
	}
}
