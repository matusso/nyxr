package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/storage"
)

func TestHistoryTopologyTimeline(t *testing.T) {
	db := filepath.Join(t.TempDir(), "topology.db")
	s, err := storage.Open(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)
	if err := s.BeginScan(context.Background(), observe.Scan{ID: "topology", Profile: "test", Started: at, Status: "running"}); err != nil {
		t.Fatal(err)
	}
	o := observe.Observation{Kind: observe.KindHost, Timestamp: at, Target: netip.MustParseAddr("192.0.2.5"),
		Transport: "passive", State: "observed", Probe: "pcap-passive", MAC: "02:01:02:03:04:05",
		Fields: map[string]string{"vlan.id": "42"}}
	o.Stamp("topology")
	if err := s.AddObservations(context.Background(), []observe.Observation{o}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	var out bytes.Buffer
	if err := run([]string{"history", "--db", db, "--topology-timeline", "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	var timeline storage.TemporalTopology
	if err := json.Unmarshal(out.Bytes(), &timeline); err != nil || len(timeline.Claims) != 1 ||
		timeline.Claims[0].VLANID != 42 || timeline.Schema != storage.TopologySchema {
		t.Fatalf("CLI timeline: %+v %v", timeline, err)
	}
	reviewFile := filepath.Join(t.TempDir(), "review.json")
	reviewJSON, _ := json.Marshal(storage.TopologyReviewInput{Address: "192.0.2.5",
		InterfaceID: timeline.Claims[0].InterfaceID, Decision: "join", ValidFrom: at,
		ValidUntil: at.Add(time.Hour), Note: "reviewed switch record"})
	if err := os.WriteFile(reviewFile, reviewJSON, 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"history", "--db", db, "--topology-review", reviewFile, "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"decision":"join"`) {
		t.Fatalf("CLI review: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"history", "--db", db, "--topology-timeline", "--at", at.Add(time.Second).Format(time.RFC3339), "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &timeline); err != nil || len(timeline.Claims) != 0 || len(timeline.Reviews) != 1 {
		t.Fatalf("CLI valid time: %+v %v", timeline, err)
	}
}

func TestServiceDryRunIncludesStage(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"scan", "--profile", "tcp-common", "--db", "x.db", "--dry-run", "--json", "192.0.2.1"}, &out); err != nil {
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
	if plan.Profile != "tcp-common" || plan.Tasks < 90 || plan.DB != "x.db" || plan.Service == nil || strings.Join(plan.Service.Fallback, ",") != "tls,http" {
		t.Fatalf("unexpected plan %+v", plan)
	}
	out.Reset()
	if err := run([]string{"scan", "--profile", "tcp-basic", "--dry-run", "192.0.2.1"}, &out); err != nil || strings.Contains(out.String(), "service") {
		t.Fatalf("discovery-only plan must not mention a service stage: %v\n%s", err, out.String())
	}
}

func TestHistoryImportsScopedIdentifiers(t *testing.T) {
	dir := t.TempDir()
	db, input := filepath.Join(dir, "inventory.db"), filepath.Join(dir, "ids.json")
	data := `[{"address":"192.0.2.5","kind":"cloud.aws.instance_id","scope":"account-1/us-east-1","value":"i-123"},` +
		`{"address":"192.0.2.6","kind":"cloud.aws.instance_id","scope":"account-1/us-east-1","value":"i-123"}]`
	if err := os.WriteFile(input, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"history", "--db", db, "--import-identifiers", input, "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"profile":"inventory-import"`) {
		t.Fatalf("import result: %s", out.String())
	}
	out.Reset()
	if err := run([]string{"history", "--db", db, "--identities", "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(out.String()), "\n"); len(lines) != 1 || !strings.Contains(lines[0], `"link_confidence":99`) {
		t.Fatalf("correlated import: %s", out.String())
	}
}

func TestServiceFlagErrors(t *testing.T) {
	for args, want := range map[string]string{
		"--profile ot-safe --allow-targets 192.0.2.1 --service-probes http": "does not allow service probe",
		"--profile tcp-basic --service-probes ssh":                          "require --service",
		"--profile tcp-common --service-probes telnet":                      "unknown service probe",
		"--profile tcp-basic --pcapng x.pcapng":                             "requires --interface",
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
	err = run([]string{"scan", "--profile", "tcp-basic", "--service", "--ports", fmt.Sprint(port), "--rate", "0", "--db", db, "--json", "127.0.0.1"}, &out)
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
	if err := run([]string{"history", "extra"}, &out); err == nil {
		t.Fatal("history with a positional argument accepted")
	}
}

func TestKnownOpenDryRunAndHistoryFilters(t *testing.T) {
	db := filepath.Join(t.TempDir(), "known.db")
	ctx := context.Background()
	store, err := openStore(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	sc := observe.Scan{ID: "seed", Profile: "tcp-basic", Started: now, Status: "running", Targets: 2}
	if err := store.BeginScan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	var obs []observe.Observation
	for _, o := range []struct {
		addr  string
		port  uint16
		state string
	}{{"192.0.2.1", 22, "open"}, {"192.0.2.1", 25, "filtered"}, {"192.0.2.9", 80, "open"}, {"198.51.100.1", 443, "open"}} {
		ob := observe.Observation{Timestamp: now, Target: netip.MustParseAddr(o.addr), Transport: "tcp", Port: o.port, State: o.state, Confidence: 100, Reason: "seed", Probe: "tcp-connect"}
		ob.Stamp(sc.ID)
		obs = append(obs, ob)
	}
	if err := store.AddObservations(ctx, obs); err != nil {
		t.Fatal(err)
	}
	store.Close()

	var out bytes.Buffer
	if err := run([]string{"scan", "--known-open", "--db", db, "--dry-run", "--json", "192.0.2.0/24"}, &out); err != nil {
		t.Fatal(err)
	}
	var plan struct {
		Targets   int  `json:"targets"`
		Tasks     int  `json:"tasks"`
		KnownOpen bool `json:"known_open"`
		Service   any  `json:"service"`
	}
	if err := json.Unmarshal(out.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Targets != 2 || plan.Tasks != 2 || !plan.KnownOpen || plan.Service == nil {
		t.Fatalf("known-open plan %s", out.String())
	}
	if err := run([]string{"scan", "--known-open", "--no-db", "192.0.2.1"}, &out); err == nil || !strings.Contains(err.Error(), "--no-db") {
		t.Fatalf("--known-open with --no-db: %v", err)
	}

	out.Reset()
	if err := run([]string{"history", "--db", db, "--assets", "--open", "--scope", "192.0.2.1-9", "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(out.String()), "\n"); len(lines) != 2 || strings.Contains(out.String(), `"filtered"`) || strings.Contains(out.String(), "198.51.100.1") {
		t.Fatalf("history --assets --open --scope:\n%s", out.String())
	}
	out.Reset()
	if err := run([]string{"history", "--db", db, "--identities", "--open", "--scope", "192.0.2.1-9", "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(out.String()), "\n"); len(lines) != 2 || !strings.Contains(out.String(), `"id":"NYXR-`) || strings.Contains(out.String(), "198.51.100.1") {
		t.Fatalf("history --identities --open --scope:\n%s", out.String())
	}
}
