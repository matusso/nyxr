package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/horizon/model"
)

func horizonArgs() []string {
	return []string{"horizon", "resolve", "--experiment", "../../lab/horizon/hz-001.yaml", "--allow-targets", "192.0.2.0/24", "--allow-ports", "443"}
}

func TestHorizonCLIAdmissionAndDryRun(t *testing.T) {
	var out bytes.Buffer
	args := append(horizonArgs(), "--dry-run", "--interface", "must-not-open")
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	var plan model.Plan
	if err := json.Unmarshal(out.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.MaxPackets != 48 || len(plan.Trials) != 24 || plan.Hash == "" {
		t.Fatalf("bad plan: %+v", plan)
	}
	for _, extra := range [][]string{{"--allow-targets", ""}, {"--allow-ports", "80"}, {"--target", "192.0.2.20"}, {"--ports", "80"}, {"--simulate", "sack", "--interface", "eth0"}, {"extra-target"}} {
		out.Reset()
		if err := run(append(horizonArgs(), extra...), &out); err == nil {
			t.Fatalf("bad arguments accepted: %v", extra)
		}
	}
	out.Reset()
	if err := run([]string{"horizon", "recognize"}, &out); err == nil {
		t.Fatal("unsupported mode accepted")
	}
}

func TestHorizonCLISyntheticExportAndReplay(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile("../../lab/horizon/hz-001.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Keep this CLI smoke small; eight-pair inference is covered by runner tests.
	text := strings.ReplaceAll(string(data), "replicates: 12", "replicates: 2")
	text = strings.ReplaceAll(text, "packetsPerSecond: 3", "packetsPerSecond: 10")
	text = strings.ReplaceAll(text, "windowMs: 100", "windowMs: 10")
	text = strings.ReplaceAll(text, "washoutMs: 50", "washoutMs: 0")
	definition := filepath.Join(dir, "experiment.yaml")
	report := filepath.Join(dir, "report.json")
	if err := os.WriteFile(definition, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"horizon", "resolve", "--experiment", definition, "--allow-targets", "192.0.2.0/24", "--allow-ports", "443", "--simulate", "sack", "--output", report}
	var out bytes.Buffer
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(saved, out.Bytes()) {
		t.Fatal("stdout/file evidence differs")
	}
	info, err := os.Stat(report)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatal("evidence permissions too broad")
	}
	out.Reset()
	if err := run([]string{"horizon", "replay", report}, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(saved, out.Bytes()) {
		t.Fatal("CLI replay is not deterministic")
	}
	out.Reset()
	if err := run([]string{"horizon", "explain", report}, &out); err != nil || !strings.Contains(out.String(), "unresolved") {
		t.Fatalf("explain failed: %v", err)
	}
	out.Reset()
	if err := run(args, &out); err == nil {
		t.Fatal("existing evidence overwritten")
	}
	still, _ := os.ReadFile(report)
	if !bytes.Equal(still, saved) {
		t.Fatal("failed overwrite altered evidence")
	}
}

func TestHorizonHelpAndCompletion(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"horizon", "--help"}, &out); err != nil || !strings.Contains(out.String(), "replay") {
		t.Fatalf("missing Horizon help: %v", err)
	}
	for _, shell := range completionShells {
		out.Reset()
		if err := run([]string{"completion", shell}, &out); err != nil || !strings.Contains(out.String(), "horizon") {
			t.Fatalf("missing completion for %s: %v", shell, err)
		}
	}
}
