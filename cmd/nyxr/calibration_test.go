package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/calibration"
)

func TestCalibrationEvaluateCLI(t *testing.T) {
	var out bytes.Buffer
	if err := runCalibration([]string{"evaluate", "--dataset", "../../lab/horizon/calibration/synthetic-v1.json"}, &out); err != nil {
		t.Fatal(err)
	}
	var report calibration.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Results) == 0 || len(report.Limitations) == 0 || !strings.Contains(report.CalibrationClaim, "heuristic") {
		t.Fatalf("CLI omitted results or calibration caveat: %+v", report)
	}
	for _, m := range report.Results {
		if m.Groups < 1 || m.RateIntervals.Unknown.Upper <= 0 {
			t.Fatalf("CLI omitted group counts or uncertainty: %+v", m)
		}
	}
}

func TestCalibrationCLIInvalidArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"fit"}, {"evaluate"}, {"evaluate", "--dataset", "missing.json"}, {"evaluate", "--dataset", "x", "extra"}} {
		var out bytes.Buffer
		if err := runCalibration(args, &out); err == nil || out.Len() != 0 {
			t.Fatalf("arguments %v produced success output: %q, %v", args, out.String(), err)
		}
	}
}
