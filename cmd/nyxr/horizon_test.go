package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/horizon"
	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/observe"
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
	first := append([]byte(nil), out.Bytes()...)
	out.Reset()
	if err := run(args, &out); err != nil || !bytes.Equal(first, out.Bytes()) {
		t.Fatalf("dry-run output changed on repeated compilation: %v", err)
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

func TestHorizonCLIRejectsInvalidWireTypes(t *testing.T) {
	b, err := os.ReadFile("../../lab/horizon/hz-001.yaml")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "experiment.yaml")
	for _, data := range []string{
		strings.Replace(string(b), "replicates: 12", "replicates: 12.9", 1),
		strings.Replace(string(b), "tcpPorts: [443]", "tcpPorts: [443.9]", 1),
		strings.Replace(string(b), "seed: 42", "seed: null", 1),
	} {
		if err := os.WriteFile(file, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		args := append(horizonArgs(), "--experiment", file, "--dry-run", "--interface", "must-not-open")
		var out bytes.Buffer
		if err := run(args, &out); err == nil || out.Len() != 0 {
			t.Fatalf("invalid experiment produced a dry-run plan: %v %s", err, out.String())
		}
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
	captureFile := filepath.Join(dir, "evidence.pcapng")
	if err := os.WriteFile(definition, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"horizon", "resolve", "--experiment", definition, "--allow-targets", "192.0.2.0/24", "--allow-ports", "443", "--simulate", "sack", "--output", report, "--pcapng", captureFile, "--pcapng-minimize"}
	var out bytes.Buffer
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(captureFile); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("capture permissions: %v", err)
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
	if err := run([]string{"horizon", "verify-capture", report, captureFile}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"horizon", "explain", report}, &out); err != nil || !strings.Contains(out.String(), "unresolved") {
		t.Fatalf("explain failed: %v", err)
	}
	out.Reset()
	if err := run([]string{"horizon", "references", report}, &out); err != nil {
		t.Fatal(err)
	}
	var refs horizon.ReportReferences
	if err := json.Unmarshal(out.Bytes(), &refs); err != nil || refs.Source.ArtifactID != observe.ArtifactID(saved) || refs.Kind != "experiment-reference" || len(refs.Trials) != 4 || refs.CaptureArtifact == nil || len(refs.Trials[0].Packets) != 3 {
		t.Fatalf("reference adapter: %+v %v", refs, err)
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

func TestGeneralHorizonCLIPolicyAndExactDryRun(t *testing.T) {
	args := []string{"horizon", "resolve", "--experiment", "../../lab/horizon/sequence-v1alpha2.yaml", "--allow-targets", "192.0.2.0/24", "--allow-ports", "443,8443", "--dry-run", "--interface", "must-not-open"}
	var out bytes.Buffer
	if err := run(args, &out); err == nil {
		t.Fatal("v1alpha2 did not require policy")
	}
	args = append(args, "--policy", "lab")
	if err := run(args, &out); err == nil {
		t.Fatal("cross-port did not require independent permission")
	}
	args = append(args, "--permit", "cross-port", "--ports", "8443,443")
	out.Reset()
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	var plan model.Plan
	if err := json.Unmarshal(out.Bytes(), &plan); err != nil || len(plan.Trials) != 12 || plan.Trials[0].OptionsHex == "" || plan.MaxPackets != 24 {
		t.Fatal("missing exact plan", err)
	}
}

func TestHorizonCLIEnvironmentAndCalibration(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"horizon", "calibrate", "--protocol", "../../lab/horizon/calibration/hz-phase3-protocol.json"}, &out); err != nil {
		t.Fatal(err)
	}
	var calibration horizon.CalibrationReport
	if err := json.Unmarshal(out.Bytes(), &calibration); err != nil || !calibration.Passed || len(calibration.ProtocolSHA256) != 64 {
		t.Fatalf("calibration: %+v %v", calibration, err)
	}
	for _, args := range [][]string{{"horizon", "calibrate"}, {"horizon", "calibrate", "--protocol", "missing.json"}, {"horizon", "environment"}} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	report := filepath.Join(t.TempDir(), "aa.json")
	out.Reset()
	if err := run([]string{"horizon", "resolve", "--experiment", "../../lab/horizon/hz-002.yaml", "--policy", "lab", "--allow-targets", "192.0.2.0/24", "--allow-ports", "443", "--simulate", "stable", "--output", report}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"horizon", "environment", report}, &out); err != nil {
		t.Fatal(err)
	}
	var env model.Environment
	if err := json.Unmarshal(out.Bytes(), &env); err != nil || env.Responses.References != 3 || env.Treatment != "none" {
		t.Fatalf("environment: %+v %v", env, err)
	}
	out.Reset()
	if err := run([]string{"horizon", "explain", report}, &out); err != nil || !strings.Contains(out.String(), "A/A control") || !strings.Contains(out.String(), "References answered: 3/3") || !strings.Contains(out.String(), "Paired RTT difference") {
		t.Fatalf("explain: %v\n%s", err, out.String())
	}
}

func TestHorizonCLICrossPortStudy(t *testing.T) {
	dir := t.TempDir()
	reports := map[string]string{}
	for _, role := range []string{"main", "same-port"} {
		b, err := os.ReadFile("../../lab/horizon/cross-port/" + role + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		fast := strings.NewReplacer("replicates: 12", "replicates: 8", "washoutMs: 600", "washoutMs: 300", "windowMs: 100", "windowMs: 20", "durationMs: 100", "durationMs: 20").Replace(string(b))
		experiment := filepath.Join(dir, role+".yaml")
		if err := os.WriteFile(experiment, []byte(fast), 0o600); err != nil {
			t.Fatal(err)
		}
		reports[role] = filepath.Join(dir, role+".json")
		args := []string{"horizon", "resolve", "--experiment", experiment, "--policy", "lab", "--permit", "cross-port", "--allow-targets", "192.0.2.0/24", "--allow-ports", "443,8443", "--simulate", "port-limit", "--output", reports[role]}
		if err := run(args, &bytes.Buffer{}); err != nil {
			t.Fatal(role, err)
		}
	}
	var out bytes.Buffer
	if err := run([]string{"horizon", "cross-port", "--main", reports["main"], "--same-port", reports["same-port"]}, &out); err != nil {
		t.Fatal(err)
	}
	var study model.CrossPortStudy
	if err := json.Unmarshal(out.Bytes(), &study); err != nil || study.Classification != "per-port-state" || len(study.Roles) != 2 {
		t.Fatalf("study: %+v %v", study, err)
	}
	for _, args := range [][]string{{"horizon", "cross-port"}, {"horizon", "cross-port", "--same-port", reports["same-port"]}, {"horizon", "cross-port", "--main", reports["same-port"]}} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestHorizonCLIGraphAndExplain(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "sack.json")
	if err := run([]string{"horizon", "resolve", "--experiment", "../../lab/horizon/hz-001-environment.yaml", "--policy", "lab", "--allow-targets", "192.0.2.0/24", "--allow-ports", "443", "--simulate", "sack", "--output", report}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	graph := filepath.Join(dir, "graph.json")
	var out bytes.Buffer
	if err := run([]string{"horizon", "graph", "--report", report, "--ttl", "8760h", "--output", graph}, &out); err != nil {
		t.Fatal(err)
	}
	var g model.Graph
	if err := json.Unmarshal(out.Bytes(), &g); err != nil || len(g.Hypotheses) != 1 || g.Hypotheses[0].Status != "supported" || g.APIVersion != model.GraphVersion {
		t.Fatalf("graph: %+v %v", g.Hypotheses, err)
	}
	out.Reset()
	if err := run([]string{"horizon", "explain", "--graph", graph, "--hypothesis", "HYP-1"}, &out); err != nil || !strings.Contains(out.String(), "HYP-1 [supported] endpoint-stack") {
		t.Fatalf("explain: %v\n%s", err, out.String())
	}
	for _, args := range [][]string{
		{"horizon", "graph"},
		{"horizon", "graph", "--report", report, "--output", graph},
		{"horizon", "graph", "--study", "bogus=" + report},
		{"horizon", "graph", "--report", report, "--change", "yesterday@network"},
		{"horizon", "graph", "--report", report, "--now", "now"},
		{"horizon", "explain", "--graph", graph},
		{"horizon", "explain", "--graph", graph, "--hypothesis", "HYP-9"},
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	out.Reset()
	if err := run([]string{"horizon", "graph", "--report", report, "--change", "2999-01-01T00:00:00Z@host:192.0.2.10@upgrade", "--now", "2999-01-02T00:00:00Z", "--ttl", "876000h"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &g); err != nil || g.Hypotheses[0].Status != "stale" {
		t.Fatalf("declared change: %+v %v", g.Hypotheses, err)
	}
}

func TestHorizonCLIAdaptAndProfile(t *testing.T) {
	dir := t.TempDir()
	evidence := filepath.Join(dir, "evidence")
	if err := os.Mkdir(evidence, 0o700); err != nil {
		t.Fatal(err)
	}
	args := []string{"horizon", "adapt", "--policy", "lab", "--permit", "cross-port", "--allow-targets", "192.0.2.0/24", "--allow-ports", "443,8443",
		"--simulate", "port-limit", "--evidence-dir", evidence, "--output", filepath.Join(dir, "study.json")}
	for _, role := range []string{"main", "same-port"} {
		b, err := os.ReadFile("../../lab/horizon/cross-port/" + role + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		fast := strings.NewReplacer("replicates: 12", "replicates: 8", "washoutMs: 600", "washoutMs: 300", "windowMs: 100", "windowMs: 20", "durationMs: 100", "durationMs: 20").Replace(string(b))
		experiment := filepath.Join(dir, role+".yaml")
		if err := os.WriteFile(experiment, []byte(fast), 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--"+role, experiment)
	}
	var out bytes.Buffer
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	var study model.AdaptiveStudy
	if err := json.Unmarshal(out.Bytes(), &study); err != nil || study.Study.Classification != "per-port-state" || study.StopReason != "sufficient" {
		t.Fatalf("adapt: %+v %v", study, err)
	}
	// Existing evidence or output is refused before any traffic is sent.
	start := time.Now()
	if err := run(args, &bytes.Buffer{}); err == nil || time.Since(start) > time.Second {
		t.Fatalf("collision not refused up front: %v after %s", err, time.Since(start))
	}
	replay := "main=" + filepath.Join(evidence, "main.json") + ",same-port=" + filepath.Join(evidence, "same-port.json")
	out.Reset()
	if err := run([]string{"horizon", "adapt", "--replay", replay}, &out); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(dir, "profile.json")
	if err := run([]string{"horizon", "profile", "build", "--study", replay, "--class", "lab-per-port", "--output", profile}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"horizon", "profile", "check", "--profile", profile, "--study", replay}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{
		{"horizon", "profile", "check", "--profile", profile, "--study", replay, "--change", "2026-10-23T00:00:00Z@hosts:192.0.2.10"},
		{"horizon", "adapt", "--replay", replay, "--change", "2026-10-23T00:00:00Z@192.0.2.10"},
		{"horizon", "adapt", "--replay", replay, "--simulate", "stable"},
		{"horizon", "adapt", "--replay", replay, "--retro-curtail", "--evidence-dir", evidence},
	} {
		if err := run(bad, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}
