package horizon

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestPhase3CalibrationProtocol(t *testing.T) {
	t.Parallel()
	f, err := os.Open("../../lab/horizon/calibration/hz-phase3-protocol.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, hash, err := LoadCalibrationProtocol(f)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Calibrate(p, hash)
	if err != nil || !r.Passed || len(r.Results) != len(p.Scenarios) || len(hash) != 64 {
		t.Fatalf("registered gates failed: %+v %v", r, err)
	}
	again, _ := Calibrate(p, hash)
	for i, res := range r.Results {
		if res.Difference+res.WrongDirect+res.NoDifference+res.Unresolved != p.RunsPerScenario || again.Results[i].Difference != res.Difference {
			t.Fatalf("%s: runs left the denominator or calibration is nondeterministic", res.Name)
		}
		switch res.Name {
		case "effect-carryover":
			if res.GatingFlags["carryover-suspected"] < p.RunsPerScenario*9/10 {
				t.Fatalf("injected carryover not gated: %+v", res)
			}
		case "null-throttle", "effect-throttle":
			if res.Unresolved < p.RunsPerScenario*9/10 || res.GatingFlags["throttling-suspected"] < p.RunsPerScenario*9/10 {
				t.Fatalf("injected throttling not gated: %+v", res)
			}
		}
	}
}

func TestCalibrationProtocolValidation(t *testing.T) {
	t.Parallel()
	valid := `{"version":"horizon-calibration/v1","id":"x","registeredAt":"2026-10-23T10:00:00Z","seed":1,"runsPerScenario":2,"replicates":8,"referenceEvery":0,"alpha":0.05,"confidence":0.95,"maxFalsePositiveRate":0.05,"minimumPower":0.9,"scenarios":[
{"name":"n","gate":"false-positive","variable":"sackPermitted","controlSack":0,"treatmentSack":0,"loss":0,"baseRttMs":1,"jitterMs":0,"driftMs":0,"throttleAfter":0,"throttleLoss":0,"treatmentFirstOnly":false},
{"name":"e","gate":"power","variable":"sackPermitted","controlSack":0,"treatmentSack":1,"loss":0,"baseRttMs":1,"jitterMs":0,"driftMs":0,"throttleAfter":0,"throttleLoss":0,"treatmentFirstOnly":false}]}`
	p, hash, err := LoadCalibrationProtocol(strings.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	// Two clean null runs cannot bound the false-positive rate below 5%.
	if r, err := Calibrate(p, hash); err != nil || r.Passed || *r.Results[0].Passed || !*r.Results[1].Passed {
		t.Fatal("underpowered protocol must fail closed", r, err)
	}
	for _, bad := range []string{
		strings.Replace(valid, `"alpha":0.05`, `"alpha":0.2`, 1),
		strings.Replace(valid, `"gate":"power"`, `"gate":"descriptive"`, 1),
		strings.Replace(valid, `"treatmentSack":1`, `"treatmentSack":1.5`, 1),
		strings.Replace(valid, `"registeredAt":"2026-10-23T10:00:00Z"`, `"registeredAt":"yesterday"`, 1),
		strings.Replace(valid, `"seed":1`, `"seed":1,"extra":1`, 1),
		valid + "{}",
	} {
		p, hash, err := LoadCalibrationProtocol(strings.NewReader(bad))
		if err == nil {
			_, err = Calibrate(p, hash)
		}
		if err == nil {
			t.Fatal("invalid protocol accepted:", bad[len(bad)-40:])
		}
	}
	if _, _, err := LoadCalibrationProtocol(bytes.NewReader(make([]byte, 65<<10))); err == nil {
		t.Fatal("oversized protocol accepted")
	}
}

func TestExactBounds(t *testing.T) {
	t.Parallel()
	// Zero events in 60 trials: 1 - 0.05^(1/60) = 4.8703%.
	if u := clopperPearsonUpper(0, 60, 0.05); u < 0.04870 || u > 0.04871 {
		t.Fatal("upper bound", u)
	}
	if l := clopperPearsonLower(60, 60, 0.05); l < 0.95129 || l > 0.95130 {
		t.Fatal("lower bound", l)
	}
	// Fisher exact reference values (R fisher.test).
	if p := fisherTwoSided(3, 1, 1, 3); p < 0.4857 || p > 0.4858 {
		t.Fatal("two-sided Fisher", p)
	}
	if p := fisherLower(0, 12, 12, 0); p > 1e-6 {
		t.Fatal("one-sided Fisher", p)
	}
	// n=12: k=3 gives 1 - 2*P(B<=2) = 0.96143.
	lo, hi, conf, ok := medianInterval([]int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, 0.95)
	if !ok || lo != 3 || hi != 10 || conf < 0.9614 || conf > 0.9615 {
		t.Fatal("median interval", lo, hi, conf)
	}
	if _, _, _, ok := medianInterval([]int64{1, 2, 3, 4, 5}, 0.95); ok {
		t.Fatal("five samples cannot reach 95% coverage")
	}
}
