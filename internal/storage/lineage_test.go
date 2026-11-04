package storage

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

func TestLineageExportCarriesFleetProvenance(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	if err := s.CreateFleetJob(ctx, FleetJob{ID: "job-1", Created: now, Request: []byte(`{}`), Options: []byte(`{}`), MaxAttempts: 2, Targets: 1},
		[]FleetUnit{{Targets: []string{"10.0.0.1"}, TargetCount: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.LeaseFleetUnit(ctx, "job-1", 0, "lease-1", "agent-1", now, now.Add(time.Minute), 3*time.Second); err != nil || !ok {
		t.Fatalf("lease: %v %v", ok, err)
	}
	scan := observe.Scan{ID: "agent-scan-1", Profile: "default", Started: now, Status: "running"}
	o := observe.Observation{Target: netip.MustParseAddr("10.0.0.1"), Timestamp: now, Transport: "tcp", Port: 22, State: "open", Confidence: 90, Probe: "syn", ScanID: scan.ID}
	o.Stamp(scan.ID)
	done := scan
	done.Status, done.Finished = "completed", now.Add(time.Second)
	if _, err := s.ApplyFleetBatch(ctx, "lease-1", 1, []FleetRecord{{Kind: FleetBegin, Scan: scan}, {Kind: FleetObservation, Observation: o},
		{Kind: FleetFinish, Scan: done}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportExternalIdentifiers(ctx, []ExternalIdentifier{{Address: netip.MustParseAddr("10.0.0.2"), Kind: "kubernetes.node_uid", Scope: "prod", Value: "uid-1"}}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.LineageObservations(ctx, 0, 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows: %d %v", len(rows), err)
	}
	fleet, local := rows[0], rows[1]
	if !fleet.Fleet || fleet.AgentID != "agent-1" || fleet.LeaseID != "lease-1" || fleet.JobID != "job-1" || fleet.Attempt != 1 || fleet.ClockOffset != 3*time.Second {
		t.Fatalf("fleet provenance: %+v", fleet)
	}
	if local.Fleet || local.AgentID != "" {
		t.Fatalf("local observation has fleet provenance: %+v", local)
	}
	if got, err := observe.ReadSource(fleet.Source, fleet.ArtifactID); err != nil || got.ScanID != scan.ID {
		t.Fatalf("sealed source: %v", err)
	}
	if more, err := s.LineageObservations(ctx, local.RowID, 10); err != nil || len(more) != 0 {
		t.Fatalf("cursor past the end: %d %v", len(more), err)
	}
	scans, err := s.LineageScans(ctx)
	if err != nil || len(scans) != 2 || scans[0].AgentID != "agent-1" || scans[1].AgentID != "" {
		t.Fatalf("scans: %+v %v", scans, err)
	}
	members, err := s.LineageMembers(ctx)
	if err != nil || len(members.Members) != 2 || members.Revision == 0 {
		t.Fatalf("members: %+v %v", members, err)
	}
	ns, _ := s.Namespace(ctx)
	for _, id := range members.Members {
		if len(id) < len(ns) || id[:len("urn:nyxr:")+len(ns)] != "urn:nyxr:"+ns {
			t.Fatalf("member %s is not in namespace %s", id, ns)
		}
	}
	strong := StrongIdentityValues(func() observe.Observation {
		o := observe.Observation{State: "observed", Probe: "inventory-import", Confidence: 100,
			Fields: map[string]string{"external.kind": "cloud.gcp.instance_id", "external.scope": "p", "external.value": "1"}}
		return o
	}())
	if len(strong) != 1 || !strong[0].Scoped || PortableIdentityID(strong[0]) == "" {
		t.Fatalf("scoped value: %+v", strong)
	}
}
