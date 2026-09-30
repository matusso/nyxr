package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestResearchDryRunAndPolicy(t *testing.T) {
	args := []string{"scan", "--profile", "research", "--protocols", "sctp", "--ports", "2905", "--interface", "eth0", "--allow-targets", "192.0.2.0/24", "--dry-run", "--json", "192.0.2.10"}
	var out bytes.Buffer
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	var p struct {
		Profile   string   `json:"profile"`
		Protocols []string `json:"protocols"`
		Tasks     int      `json:"tasks"`
		Research  struct {
			Kind string `json:"kind"`
		} `json:"research"`
	}
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Profile != "research" || p.Research.Kind != "sctp" || p.Tasks != 1 || len(p.Protocols) != 1 || p.Protocols[0] != "sctp" {
		t.Fatalf("bad plan: %+v", p)
	}
	args[13] = "198.51.100.10"
	if err := run(args, &out); err == nil || !strings.Contains(err.Error(), "outside --allow-targets") {
		t.Fatalf("out-of-policy research accepted: %v", err)
	}
}
