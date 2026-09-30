package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestProfilesCommand(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"profiles"}, &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"discovery", "ot-safe", "available", "planned"} {
		if !strings.Contains(s, want) {
			t.Fatalf("profiles output missing %q:\n%s", want, s)
		}
	}
}

func TestScanDryRunJSON(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"scan", "--profile", "tcp", "--ports", "80,443", "--dry-run", "--json", "192.0.2.0/30"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	var plan struct {
		Profile string `json:"profile"`
		Targets int    `json:"targets"`
		Tasks   int    `json:"tasks"`
	}
	if err := json.Unmarshal(out.Bytes(), &plan); err != nil {
		t.Fatalf("dry-run should emit JSON plan: %v\n%s", err, out.String())
	}
	if plan.Profile != "tcp" || plan.Targets != 4 || plan.Tasks != 8 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}

func TestScanPlannedProfileError(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"scan", "--profile", "deep", "192.0.2.1"}, &out)
	if err == nil || !strings.Contains(err.Error(), "planned") {
		t.Fatalf("expected planned-profile error, got %v", err)
	}
}

func TestScanUnknownProfileError(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"scan", "--profile", "bogus", "192.0.2.1"}, &out)
	if err == nil || !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("expected unknown-profile error, got %v", err)
	}
}
