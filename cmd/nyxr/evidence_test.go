package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestServiceDryRunIncludesStage(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"scan", "--profile", "deep", "--db", "x.db", "--dry-run", "--json", "192.0.2.1"}, &out); err != nil {
		t.Fatal(err)
	}
	var plan struct {
		Profile string `json:"profile"`
		Tasks   int    `json:"tasks"`
		DB      string `json:"db"`
		Service *struct {
			Probes   []string `json:"probes"`
			Fallback []string `json:"fallback"`
		} `json:"service"`
	}
	if err := json.Unmarshal(out.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Profile != "deep" || plan.Tasks < 90 || plan.DB != "x.db" || plan.Service == nil || strings.Join(plan.Service.Fallback, ",") != "tls,http" {
		t.Fatalf("unexpected plan %+v", plan)
	}
	out.Reset()
	if err := run([]string{"scan", "--profile", "tcp", "--dry-run", "192.0.2.1"}, &out); err != nil || strings.Contains(out.String(), "service") {
		t.Fatalf("discovery-only plan must not mention a service stage: %v\n%s", err, out.String())
	}
}

func TestServiceFlagErrors(t *testing.T) {
	for args, want := range map[string]string{
		"--profile ot-safe --allow-targets 192.0.2.1 --service-probes http": "does not allow service probe",
		"--profile tcp --service-probes ssh":                                "require --service",
		"--profile service --service-probes smb":                            "unknown service probe",
		"--profile tcp --pcapng x.pcapng":                                   "requires --interface",
	} {
		var out bytes.Buffer
		err := run(append(append([]string{"scan"}, strings.Fields(args)...), "192.0.2.1"), &out)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: want %q, got %v", args, want, err)
		}
	}
}

func TestServiceScanStoresAndHistoryQueries(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, "SSH-2.0-OpenSSH_9.6p1\r\n")
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	db := filepath.Join(t.TempDir(), "nyxr.db")

	var out bytes.Buffer
	err = run([]string{"scan", "--profile", "tcp", "--service", "--ports", fmt.Sprint(port), "--rate", "0", "--db", db, "--json", "127.0.0.1"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	var scanID string
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		var rec struct {
			Kind    string `json:"kind"`
			ScanID  string `json:"scan_id"`
			Product string `json:"product"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, rec.Kind)
		scanID = rec.ScanID
		if rec.Kind == "service" && rec.Product != "OpenSSH" {
			t.Fatalf("service record: %s", sc.Text())
		}
	}
	if strings.Join(kinds, ",") != "port,service,scan" {
		t.Fatalf("record kinds %v", kinds)
	}

	out.Reset()
	if err := run([]string{"history", "--db", db}, &out); err != nil || !strings.Contains(out.String(), scanID) || !strings.Contains(out.String(), "completed") {
		t.Fatalf("history list: %v\n%s", err, out.String())
	}
	out.Reset()
	if err := run([]string{"history", "--db", db, "--scan", scanID}, &out); err != nil || !strings.Contains(out.String(), "svc ssh") || !strings.Contains(out.String(), "OpenSSH 9.6p1") {
		t.Fatalf("history scan: %v\n%s", err, out.String())
	}
	out.Reset()
	if err := run([]string{"history", "--db", db, "--assets"}, &out); err != nil || !strings.Contains(out.String(), fmt.Sprintf("%d/tcp", port)) || !strings.Contains(out.String(), "ssh") {
		t.Fatalf("history assets: %v\n%s", err, out.String())
	}
	out.Reset()
	if err := run([]string{"history", "--db", db, "--keep", "1", "--json"}, &out); err != nil || !strings.Contains(out.String(), `"deleted_scans":0`) {
		t.Fatalf("history prune: %v\n%s", err, out.String())
	}
	if err := run([]string{"history"}, &out); err == nil {
		t.Fatal("history without --db accepted")
	}
}
