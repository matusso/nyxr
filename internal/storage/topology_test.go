package storage

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/capture"
	"github.com/matusso/nyxr/internal/observe"
)

func passiveObservation(address netip.Addr, mac string, at time.Time, vlan string) observe.Observation {
	return observe.Observation{Kind: observe.KindHost, Timestamp: at, Target: address,
		Transport: "passive", State: "observed", Probe: "pcap-passive", MAC: mac,
		Fields: map[string]string{"vlan.id": vlan}}
}

func TestTopologyKeepsMultiInterfaceClaimsAndConflictsSeparate(t *testing.T) {
	s, _ := openTest(t)
	other := netip.MustParseAddr("192.0.2.6")
	storeScan(t, s, "same-time", t0,
		passiveObservation(host, "02:01:02:03:04:05", t0, "100"),
		passiveObservation(host, "02:01:02:03:04:06", t0, "200"),
		passiveObservation(other, "02:01:02:03:04:05", t0, "100"))
	graph, err := s.IdentityGraph(ctx)
	if err != nil || len(graph) != 2 {
		t.Fatalf("passive MAC must not merge addresses: %+v %v", graph, err)
	}
	timeline, err := s.TopologyTimeline(ctx, 10, time.Time{})
	if err != nil || timeline.Schema != TopologySchema || len(timeline.Claims) != 3 ||
		!timeline.Claims[1].Conflict || !timeline.Claims[2].Conflict || timeline.Claims[0].Conflict {
		t.Fatalf("conflicting interface claims: %+v %v", timeline, err)
	}
	if timeline.Claims[1].VLANID != 200 || timeline.Claims[2].VLANID != 100 ||
		timeline.Claims[1].Source.ArtifactID == "" || timeline.Claims[1].Validity != "point" {
		t.Fatalf("VLAN/source/valid time missing: %+v", timeline.Claims)
	}
	if timeline.Claims[0].InterfaceID == timeline.Claims[2].InterfaceID {
		t.Fatal("equal passive MACs on distinct assets acquired one interface ID")
	}
	for _, claim := range timeline.Claims {
		resolved, err := s.ResolveSource(ctx, claim.Source)
		if err != nil || resolved.Status != "available" {
			t.Fatalf("claim source unavailable: %+v %v", resolved, err)
		}
	}
	when, err := s.TopologyTimeline(ctx, 10, t0.Add(time.Nanosecond))
	if err != nil || len(when.Claims) != 0 {
		t.Fatalf("a packet must not imply future ownership: %+v %v", when, err)
	}
	if n, err := s.Prune(ctx, Retention{KeepLast: 0, OlderThan: time.Hour}, t0.Add(2*time.Hour)); err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	pruned, err := s.TopologyTimeline(ctx, 10, time.Time{})
	if err != nil || len(pruned.Claims) != 0 {
		t.Fatalf("retained claims outlived evidence: %+v %v", pruned, err)
	}
}

func lldpCapture(t *testing.T, at time.Time, address bool) *bytes.Buffer {
	t.Helper()
	frame := []byte{1, 0x80, 0xc2, 0, 0, 0x0e, 2, 1, 2, 3, 4, 5, 0x81, 0x00, 0, 100, 0x88, 0xcc}
	appendTLV := func(kind uint16, value []byte) {
		var header [2]byte
		binary.BigEndian.PutUint16(header[:], kind<<9|uint16(len(value)))
		frame = append(frame, header[:]...)
		frame = append(frame, value...)
	}
	appendTLV(1, []byte{4, 2, 1, 2, 3, 4, 5})
	appendTLV(2, []byte{5, 'p', 'o', 'r', 't'})
	appendTLV(3, []byte{0, 120})
	if address {
		appendTLV(8, []byte{5, 1, 192, 0, 2, 5, 2, 0, 0, 0, 1, 0})
	}
	appendTLV(0, nil)
	var file bytes.Buffer
	writer, err := capture.NewPCAPNGWriter(&file, "en0", 65535, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePacket(at, frame, len(frame), capture.DirectionRX, 1, ""); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	return &file
}

func TestTopologyLLDPReplayTTLAndUnlinkedChassis(t *testing.T) {
	s, _ := openTest(t)
	file := lldpCapture(t, t0, false)
	if _, err := s.ImportPassiveCapture(ctx, file, "en0"); err != nil {
		t.Fatal(err)
	}
	all, err := s.TopologyTimeline(ctx, 10, time.Time{})
	if err != nil || len(all.Adjacencies) != 1 || len(all.Claims) != 0 {
		t.Fatalf("unlinked LLDP: %+v %v", all, err)
	}
	link := all.Adjacencies[0]
	if link.IdentityID != "" || link.ManagementAddress != "" || link.TTLSeconds != 120 ||
		link.FrameHash == "" || link.Validity != "advertised_ttl" || !link.ValidUntil.Equal(t0.Add(120*time.Second)) ||
		link.Source == nil || link.EvidenceStatus != "retained" {
		t.Fatalf("LLDP provenance and validity: %+v", link)
	}
	resolved, err := s.ResolveSource(ctx, *link.Source)
	if err != nil || resolved.Status != "available" {
		t.Fatalf("LLDP source unavailable: %+v %v", resolved, err)
	}
	var retained struct {
		Frame []byte `json:"frame"`
	}
	if err := json.Unmarshal(resolved.Artifact, &retained); err != nil || observe.ArtifactID(retained.Frame) != link.FrameHash {
		t.Fatalf("LLDP frame hash mismatch: %v", err)
	}
	within, err := s.TopologyTimeline(ctx, 10, t0.Add(60*time.Second))
	if err != nil || len(within.Adjacencies) != 1 {
		t.Fatalf("LLDP within TTL: %+v %v", within, err)
	}
	expired, err := s.TopologyTimeline(ctx, 10, t0.Add(121*time.Second))
	if err != nil || len(expired.Adjacencies) != 0 {
		t.Fatalf("expired LLDP remained valid: %+v %v", expired, err)
	}
	if n, err := s.Prune(ctx, Retention{OlderThan: time.Hour}, time.Now().Add(2*time.Hour)); err != nil || n != 1 {
		t.Fatalf("LLDP retention: %d %v", n, err)
	}
	resolved, err = s.ResolveSource(ctx, *link.Source)
	if err != nil || resolved.Status != "unavailable" {
		t.Fatalf("pruned LLDP source: %+v %v", resolved, err)
	}
}

func TestTopologyLLDPOverlappingAdjacencyClaimsStaySeparate(t *testing.T) {
	s, _ := openTest(t)
	if _, err := s.ImportPassiveCapture(ctx, lldpCapture(t, t0, false), "en0"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportPassiveCapture(ctx, lldpCapture(t, t0.Add(30*time.Second), false), "en1"); err != nil {
		t.Fatal(err)
	}
	timeline, err := s.TopologyTimeline(ctx, 10, t0.Add(60*time.Second))
	if err != nil || len(timeline.Adjacencies) != 2 ||
		!timeline.Adjacencies[0].Conflict || !timeline.Adjacencies[1].Conflict {
		t.Fatalf("overlapping LLDP claims: %+v %v", timeline, err)
	}
	after, err := s.TopologyTimeline(ctx, 10, t0.Add(120*time.Second))
	if err != nil || len(after.Adjacencies) != 1 || after.Adjacencies[0].LocalInterface != "en1" {
		t.Fatalf("expired LLDP claim: %+v %v", after, err)
	}
}

func TestTopologyMigrationBackfillsOnlyRetainedObservations(t *testing.T) {
	s, path := openTest(t)
	storeScan(t, s, "retained", t0, passiveObservation(host, "02:01:02:03:04:05", t0, "42"))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE probe_runs; DROP TABLE topology_reviews; DROP TABLE topology_claims; DROP TABLE passive_link_sources;
		ALTER TABLE passive_links DROP COLUMN source_artifact_id; ALTER TABLE passive_links DROP COLUMN ttl_seconds;
		ALTER TABLE passive_links DROP COLUMN frame_index; ALTER TABLE passive_links DROP COLUMN frame_hash;
		ALTER TABLE passive_links DROP COLUMN valid_until; DELETE FROM schema_migrations WHERE version >= 8`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	timeline, err := s.TopologyTimeline(ctx, 10, time.Time{})
	if err != nil || len(timeline.Claims) != 1 || timeline.Claims[0].VLANID != 42 ||
		timeline.HistoryBefore != "unknown" {
		t.Fatalf("migration claim: %+v %v", timeline, err)
	}
	before, err := s.TopologyTimeline(ctx, 10, t0.Add(-time.Hour))
	if err != nil || len(before.Claims) != 0 {
		t.Fatalf("migration invented earlier history: %+v %v", before, err)
	}
}

func TestTopologyReviewedIntervalsAndOverrides(t *testing.T) {
	s, _ := openTest(t)
	storeScan(t, s, "observed", t0,
		passiveObservation(host, "02:01:02:03:04:05", t0, "100"),
		passiveObservation(host, "02:01:02:03:04:06", t0, "200"))
	initial, err := s.TopologyTimeline(ctx, 10, time.Time{})
	if err != nil || len(initial.Claims) != 2 {
		t.Fatalf("initial claims: %+v %v", initial, err)
	}
	first := initial.Claims[0].InterfaceID
	second := initial.Claims[1].InterfaceID
	input := TopologyReviewInput{Address: host.String(), InterfaceID: first, VLANID: 200,
		Decision: "join", ValidFrom: t0.Add(-time.Minute), ValidUntil: t0.Add(time.Hour), Note: "switch export reviewed"}
	joined, err := s.ReviewTopology(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if resolved, err := s.ResolveSource(ctx, joined.Source); err != nil || resolved.Status != "available" {
		t.Fatalf("review source: %+v %v", resolved, err)
	}
	input.InterfaceID, input.Decision, input.Note = second, "separate", "operator confirmed different port"
	if _, err := s.ReviewTopology(ctx, input); err != nil {
		t.Fatal(err)
	}
	at, err := s.TopologyTimeline(ctx, 10, t0)
	if err != nil || len(at.Reviews) != 2 || len(at.Claims) != 2 {
		t.Fatalf("reviewed time: %+v %v", at, err)
	}
	if !at.Claims[0].Conflict || !at.Claims[1].Overridden {
		t.Fatalf("review effects missing: %+v", at.Claims)
	}
	later, err := s.TopologyTimeline(ctx, 10, t0.Add(2*time.Hour))
	if err != nil || len(later.Reviews) != 0 || len(later.Claims) != 0 {
		t.Fatalf("expired review interval: %+v %v", later, err)
	}
	input.InterfaceID = "unknown"
	if _, err := s.ReviewTopology(ctx, input); err == nil {
		t.Fatal("unobserved interface accepted as reviewed fact")
	}
}
