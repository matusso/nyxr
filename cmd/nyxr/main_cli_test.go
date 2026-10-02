package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfilesCommand(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"profiles"}, &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"discovery", "ot-safe", "available", "database"} {
		if !strings.Contains(s, want) {
			t.Fatalf("profiles output missing %q:\n%s", want, s)
		}
	}
}

func TestScanDryRunJSON(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"scan", "--profile", "tcp-basic", "--ports", "80,443", "--dry-run", "--json", "192.0.2.0/30"}, &out)
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
	if plan.Profile != "tcp-basic" || plan.Targets != 4 || plan.Tasks != 8 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}

func TestScanDatabaseProfileDryRun(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"scan", "--profile", "database", "--dry-run", "--json", "192.0.2.1"}, &out)
	if err != nil || !strings.Contains(out.String(), `"profile":"database"`) || !strings.Contains(out.String(), `"probes":["database"]`) {
		t.Fatalf("expected database profile plan, got %v: %s", err, out.String())
	}
}

func TestScanNSEDryRun(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"scan", "--ports", "80", "--nse-scripts", "http-title", "--nse-timeout", "12s",
		"--no-db", "--dry-run", "--json", "127.0.0.1"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	var plan struct {
		NSE struct {
			Scripts []string `json:"scripts"`
			Timeout string   `json:"timeout"`
			Safety  string   `json:"safety"`
		} `json:"nse"`
	}
	if err := json.Unmarshal(out.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.NSE.Scripts) != 1 || plan.NSE.Scripts[0] != "http-title" || plan.NSE.Timeout != "12s" || plan.NSE.Safety != "safe" {
		t.Fatalf("NSE missing from CLI dry-run: %+v", plan)
	}
}

func TestScanUnknownProfileError(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"scan", "--profile", "bogus", "192.0.2.1"}, &out)
	if err == nil || !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("expected unknown-profile error, got %v", err)
	}
}

func TestCompletionScripts(t *testing.T) {
	syntaxCheck := map[string][]string{
		"bash": {"bash", "-n"},
		"zsh":  {"zsh", "-n"},
		"fish": {"fish", "--no-execute"},
	}
	for _, shell := range completionShells {
		t.Run(shell, func(t *testing.T) {
			var out bytes.Buffer
			if err := run([]string{"completion", shell}, &out); err != nil {
				t.Fatal(err)
			}
			s := out.String()
			for _, want := range []string{"scan", "dry-run", "ot-safe", "top100"} {
				if !strings.Contains(s, want) {
					t.Fatalf("%s completion missing %q", shell, want)
				}
			}
			if !strings.Contains(s, "research") {
				t.Fatalf("%s completion omits available research profile", shell)
			}
			check, ok := syntaxCheck[shell]
			if !ok {
				return
			}
			path, err := exec.LookPath(check[0])
			if err != nil {
				t.Skipf("%s not installed", check[0])
			}
			script := filepath.Join(t.TempDir(), "nyxr."+shell)
			if err := os.WriteFile(script, out.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			if msg, err := exec.Command(path, append(check[1:], script)...).CombinedOutput(); err != nil {
				t.Fatalf("%s rejected completion script: %v\n%s", shell, err, msg)
			}
		})
	}
}

func TestCompletionErrors(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"completion"}, &out); err == nil {
		t.Fatal("expected error without a shell")
	}
	if err := run([]string{"completion", "tcsh"}, &out); err == nil || !strings.Contains(err.Error(), "unsupported shell") {
		t.Fatalf("expected unsupported-shell error, got %v", err)
	}
}
