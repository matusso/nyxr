package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleProbes = `# synthetic
Exclude T:9100-9107
Probe TCP NULL q||
match ftp m|^220[- ].*FTP| p/$1/
softmatch smtp m|^220 |
match broken m|^(x)\1| p/never/
`

func writeProbes(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nmap-service-probes")
	if err := os.WriteFile(path, []byte(sampleProbes), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProbeImportJSON(t *testing.T) {
	path := writeProbes(t)
	var out bytes.Buffer
	if err := run([]string{"probe", "import", "--json", path}, &out); err != nil {
		t.Fatal(err)
	}
	var sum struct {
		Source     string `json:"source"`
		SHA256     string `json:"sha256"`
		Probes     int    `json:"probes"`
		MatchRules int    `json:"match_rules"`
		SoftMatch  int    `json:"softmatch"`
		Usable     int    `json:"usable"`
		Skipped    int    `json:"skipped"`
		NullRules  int    `json:"null_rules"`
		Exclusions int    `json:"exclusions"`
		License    string `json:"license"`
	}
	if err := json.Unmarshal(out.Bytes(), &sum); err != nil {
		t.Fatalf("expected JSON: %v\n%s", err, out.String())
	}
	if sum.Probes != 1 || sum.MatchRules != 3 || sum.SoftMatch != 1 || sum.Skipped != 1 || sum.Usable != 2 {
		t.Fatalf("unexpected stats: %+v", sum)
	}
	if sum.NullRules != 2 || sum.Exclusions != 1 || len(sum.SHA256) != 64 {
		t.Fatalf("unexpected provenance: %+v", sum)
	}
	if !strings.Contains(sum.License, "Nmap Project") {
		t.Fatalf("license notice missing: %q", sum.License)
	}
}

func TestProbeImportText(t *testing.T) {
	path := writeProbes(t)
	var out bytes.Buffer
	if err := run([]string{"probe", "import", path}, &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"source", "sha256", "probes", "skipped", "Nmap Project"} {
		if !strings.Contains(s, want) {
			t.Fatalf("text summary missing %q:\n%s", want, s)
		}
	}
}

func TestProbeImportErrors(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"probe"}, &out); err == nil {
		t.Fatal("probe without a subcommand should fail")
	}
	out.Reset()
	if err := run([]string{"probe", "import"}, &out); err == nil {
		t.Fatal("import without a file should fail")
	}
	out.Reset()
	if err := run([]string{"probe", "bogus"}, &out); err == nil {
		t.Fatal("unknown subcommand should fail")
	}
}

func TestScanDryRunShowsNmapProbes(t *testing.T) {
	path := writeProbes(t)
	var out bytes.Buffer
	err := run([]string{"scan", "--profile", "tcp-common", "--service", "--nmap-service-probes", path,
		"--ports", "21,80", "--dry-run", "192.0.2.10"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "nmap-probes") || !strings.Contains(out.String(), path) {
		t.Fatalf("dry-run plan should list the nmap probes file:\n%s", out.String())
	}
}
