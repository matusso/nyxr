package calibration

import (
	"os"
	"strings"
	"testing"
)

func TestSyntheticCorpus(t *testing.T) {
	f, err := os.Open("../../lab/horizon/calibration/synthetic-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	report, err := Evaluate(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(report.DatasetSHA256, "sha256:") || len(report.Results) == 0 {
		t.Fatalf("invalid report: %+v", report)
	}
	for _, m := range report.Results {
		if m.Kind == "os" && m.Split == "holdout" && (m.FalseMatches != 1 || m.MissedMatches != 1) {
			t.Fatalf("wrong named OS must be a false and missed match: %+v", m)
		}
		if m.Kind == "protocol" && m.Split == "holdout" {
			if m.Count != 2 || m.Correct != 1 || m.MissedMatches != 1 || m.Unknown != 1 || m.UnknownRate != 0.5 || m.PacketsTX != 4 || m.ECE == nil {
				t.Fatalf("protocol metrics: %+v", m)
			}
			return
		}
	}
	t.Fatal("missing held-out protocol metrics")
}

func TestRejectsSplitLeakage(t *testing.T) {
	input := `{"schema":"nyxr/calibration/v1","id":"test","cases":[` +
		`{"id":"a","split":"tuning","group":"same","kind":"protocol","model":"m","label_source":"fixture","evidence_ref":"a","truth":"ssh","prediction":"ssh"},` +
		`{"id":"b","split":"holdout","group":"same","kind":"protocol","model":"m","label_source":"fixture","evidence_ref":"b","truth":"ssh","prediction":"ssh"}]}`
	if _, err := Evaluate(strings.NewReader(input)); err == nil || !strings.Contains(err.Error(), "tuning and holdout") {
		t.Fatalf("expected leakage error, got %v", err)
	}
}
