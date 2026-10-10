package storage

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

func TestImmutableSourceRoundTripAndRetention(t *testing.T) {
	s, path := openTest(t)
	o := serviceObs(t0, 9999, "", "")
	o.Fingerprint = observe.FingerprintUnknown
	o.ID = "old/1"
	o.Stamp("old")
	o.Evidence[1].Decoded = []observe.ByteField{{Offset: 0, Length: 1, Bytes: "00", Field: "custom", Value: "retained"}}
	source, err := o.Seal()
	if err != nil {
		t.Fatal(err)
	}
	storeScan(t, s, "old", t0, o)
	storeScan(t, s, "new", t0.Add(time.Hour), portObs(t0.Add(time.Hour), 22, "open"))
	got, err := s.Observations(ctx, Filter{ScanID: "old"})
	if err != nil || len(got) != 1 || !reflect.DeepEqual(o, got[0]) {
		t.Fatalf("stream/history diverged: %+v %v", got, err)
	}
	resolved, err := s.ResolveSource(ctx, *o.Evidence[1].Source)
	if err != nil || resolved.Status != "available" || !bytes.Equal(resolved.Artifact, source) {
		t.Fatalf("source mapping lost: %+v %v", resolved, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resolved, err = s.ResolveSource(ctx, *o.Source)
	if err != nil || !bytes.Equal(resolved.Artifact, source) {
		t.Fatal("source changed after reopen")
	}
	bad := *o.Source
	bad.RunID = "another-run"
	if result, err := s.ResolveSource(ctx, bad); err != nil || result.Status != "unavailable" {
		t.Fatal("wrong run accepted")
	}
	if n, err := s.Prune(ctx, Retention{KeepLast: 1}, t0.Add(2*time.Hour)); err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	resolved, err = s.ResolveSource(ctx, *o.Source)
	if err != nil || resolved.Status != "unavailable" || resolved.Reason == "" || resolved.Reference != *o.Source || len(resolved.Artifact) != 0 {
		t.Fatalf("pruned provenance: %+v %v", resolved, err)
	}
}

func TestSourceMigrationPreservesLineageAndHistoricalBytes(t *testing.T) {
	s, path := openTest(t)
	storeScan(t, s, "legacy", t0, serviceObs(t0, 443, "http", "nginx"))
	before, err := s.IdentityGraph(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the released v6 layout, keeping its original observation and
	// evidence columns; the new source table did not exist in that release.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE observation_sources; ALTER TABLE packet_flows DROP COLUMN capture_artifact_id; DELETE FROM schema_migrations WHERE version = 7`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	after, err := s.IdentityGraph(ctx)
	if err != nil || len(after) != 1 || after[0].ID != before[0].ID || after[0].GlobalID != before[0].GlobalID {
		t.Fatalf("migration changed identity: %+v %v", after, err)
	}
	obs, err := s.Observations(ctx, Filter{ScanID: "legacy"})
	if err != nil || len(obs) != 1 {
		t.Fatalf("migration: %+v %v", obs, err)
	}
	o := obs[0]
	if o.ID == "" || o.Source == nil || o.Evidence[1].ParserVersion != "unknown" || !bytes.Equal(o.Evidence[1].Response, []byte{0, 1, 2, 255}) {
		t.Fatalf("historical provenance: %+v", o)
	}
	r, err := s.ResolveSource(ctx, *o.Evidence[1].Source)
	if err != nil || r.Status != "available" {
		t.Fatalf("migrated source: %+v %v", r, err)
	}
	var canonical observe.Observation
	if err := json.Unmarshal(r.Artifact, &canonical); err != nil || canonical.Source != nil {
		t.Fatal("source not canonical")
	}
}
