package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/storage"
)

func TestEvidenceShowCloneAndOfflineReplay(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "nyxr.db")
	ctx := context.Background()
	store, err := storage.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.BeginScan(ctx, observe.Scan{ID: "cli-scan", Profile: "tcp-common", Started: now, Status: "running"}); err != nil {
		t.Fatal(err)
	}
	o := observe.Observation{Kind: observe.KindService, Timestamp: now, Target: netip.MustParseAddr("192.0.2.4"), Transport: "tcp", Port: 6379,
		State: "open", Service: "redis", Fingerprint: observe.FingerprintMatched,
		Evidence: []observe.Evidence{{Probe: "database/redis", Layer: "tcp", Request: []byte("PING\r\n"), Response: []byte("+PONG\r\n"), Matched: "database"}}}
	o.Stamp("cli-scan")
	if err := store.AddObservations(ctx, []observe.Observation{o}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishScan(ctx, observe.Scan{ID: "cli-scan", Status: "completed", Finished: now, Observations: 1}); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Observations(ctx, storage.Filter{ScanID: "cli-scan"})
	store.Close()
	if err != nil || len(stored) != 1 {
		t.Fatal(err)
	}
	id := stored[0].ID

	var out bytes.Buffer
	if err := run([]string{"--no-color", "evidence", "show", "--db", db, id}, &out); err != nil {
		t.Fatal(err)
	}
	if text := out.String(); !strings.Contains(text, "database/redis tcp database") || !strings.Contains(text, "PACKETS unavailable") ||
		!strings.Contains(text, "recorded no pcapng capture") {
		t.Fatalf("evidence show:\n%s", text)
	}
	draft := filepath.Join(dir, "clone.yaml")
	out.Reset()
	if err := run([]string{"probe", "clone", "--db", db, "-o", draft, id}, &out); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"probe", "clone", "--db", db, "-o", draft, id}, &out); err == nil {
		t.Fatal("clone overwrote an existing definition")
	}
	out.Reset()
	if err := run([]string{"probe", "replay", "--db", db, "--definition", draft, "--dry-run", id}, &out); err != nil ||
		!strings.Contains(out.String(), "traffic     none") {
		t.Fatalf("dry run: %v\n%s", err, out.String())
	}
	if err := run([]string{"probe", "replay", "--db", db, "--definition", draft, "--live", "--target", "192.0.2.5", id}, &out); err == nil {
		t.Fatal("live resend to another target accepted")
	}
	out.Reset()
	if err := run([]string{"probe", "replay", "--db", db, "--definition", draft, "--json", id}, &out); err != nil {
		t.Fatal(err)
	}
	var result observe.ProbeRun
	if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.Status != observe.ProbeRunMatched || result.Mode != observe.ProbeRunOffline {
		t.Fatalf("offline replay: %v %s", err, out.String())
	}
	out.Reset()
	if err := run([]string{"--no-color", "evidence", "show", "--db", db, id}, &out); err != nil || !strings.Contains(out.String(), result.ID+" offline matched") {
		t.Fatalf("replay not listed: %v\n%s", err, out.String())
	}
	if _, err := os.Stat(draft); err != nil {
		t.Fatal(err)
	}
}
