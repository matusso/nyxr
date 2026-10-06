package storage

import (
	"database/sql"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

func identityObs(addr netip.Addr, at time.Time, mac string) observe.Observation {
	return observe.Observation{Timestamp: at, Target: addr, Kind: observe.KindHost,
		Transport: "arp", State: "responsive", Confidence: 100, Probe: "arp-solicitation", MAC: mac}
}

func TestIdentityGraphJoinsStrongSignalsAndKeepsWeakSignalsSeparate(t *testing.T) {
	s, path := openTest(t)
	other := netip.MustParseAddr("2001:db8::5")
	third := netip.MustParseAddr("192.0.2.9")
	a := identityObs(host, t0, "02:01:02:03:04:05")
	b := identityObs(other, t0.Add(time.Second), "02:01:02:03:04:05")
	b.Probe = "ndp-solicitation"
	c := serviceObs(t0, 443, "https", "nginx")
	c.Target = third // same presented certificate must not merge this address
	storeScan(t, s, "identity-a", t0, a, b, c)
	graph, err := s.IdentityGraph(ctx)
	if err != nil || len(graph) != 2 {
		t.Fatalf("graph: %+v, %v", graph, err)
	}
	var joined *IdentityAsset
	for i := range graph {
		if len(graph[i].Addresses) == 2 {
			joined = &graph[i]
		}
	}
	if joined == nil || len(joined.Signals) != 2 || joined.LinkConfidence != 85 ||
		joined.ID != joined.Addresses[0].IdentityID || joined.ID != joined.Addresses[1].IdentityID {
		t.Fatalf("joined asset: %+v", graph)
	}
	_ = s.Close()
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again, err := reopened.IdentityGraph(ctx)
	if err != nil || len(again) != 2 || again[0].ID != graph[0].ID || again[1].ID != graph[1].ID {
		t.Fatalf("persistent identities: %+v, %v", again, err)
	}
}

func TestIdentityGraphSplitsChangedDeviceID(t *testing.T) {
	s, _ := openTest(t)
	other := netip.MustParseAddr("192.0.2.6")
	guidA := "00112233-4455-6677-8899-aabbccddeeff"
	guidB := "ffeeddcc-bbaa-9988-7766-554433221100"
	makeSMB := func(addr netip.Addr, at time.Time, guid string) observe.Observation {
		return observe.Observation{Kind: observe.KindService, Timestamp: at, Target: addr, Transport: "tcp", Port: 445,
			State: "open", Service: "smb", Confidence: 100, Attributes: map[string]string{"smb.server_guid": guid}}
	}
	storeScan(t, s, "first", t0, makeSMB(host, t0, guidA), makeSMB(other, t0, guidA))
	before, err := s.IdentityGraph(ctx)
	if err != nil || len(before) != 1 || len(before[0].Addresses) != 2 {
		t.Fatalf("initial join: %+v, %v", before, err)
	}
	storeScan(t, s, "changed", t0.Add(time.Hour), makeSMB(other, t0.Add(time.Hour), guidB))
	after, err := s.IdentityGraph(ctx)
	if err != nil || len(after) != 2 {
		t.Fatalf("changed graph: %+v, %v", after, err)
	}
	for _, asset := range after {
		if len(asset.Addresses) != 1 {
			t.Fatalf("changed device remained joined: %+v", asset)
		}
		if asset.Addresses[0].Address == other && (asset.ID == before[0].ID || !asset.FirstSeen.Equal(t0.Add(time.Hour)) || len(asset.Signals) != 2 || asset.Signals[0].Active == asset.Signals[1].Active) {
			t.Fatalf("old signal not retired: %+v", asset)
		}
	}
}

func TestIdentityMigrationBackfillsStoredObservations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(migrations[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?)`, ts(t0)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO scans(id, schema, profile, started_at, status) VALUES ('old', 'nyxr/v1', 'test', ?, 'completed')`, ts(t0)); err != nil {
		t.Fatal(err)
	}
	for i, addr := range []netip.Addr{host, netip.MustParseAddr("2001:db8::5")} {
		assetID := i + 1
		if _, err := db.Exec(`INSERT INTO assets(id, address, first_seen, last_seen) VALUES (?, ?, ?, ?)`, assetID, addr.String(), ts(t0), ts(t0)); err != nil {
			t.Fatal(err)
		}
		o := identityObs(addr, t0, "02:01:02:03:04:05")
		body, _ := json.Marshal(o)
		if _, err := db.Exec(`INSERT INTO observations(scan_id, asset_id, kind, observed_at, transport, port, state, confidence, reason, probe, service, product, version, fingerprint, record)
			VALUES ('old', ?, 'host', ?, 'arp', 0, 'responsive', 100, '', 'arp-solicitation', '', '', '', '', ?)`, assetID, ts(t0), string(body)); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	graph, err := s.IdentityGraph(ctx)
	if err != nil || len(graph) != 1 || len(graph[0].Addresses) != 2 || len(graph[0].Signals) != 2 {
		t.Fatalf("backfilled graph: %+v, %v", graph, err)
	}
	events, err := s.IdentityHistory(ctx, netip.MustParseAddr("2001:db8::5"))
	if err != nil || len(events) != 2 || events[0].Cause != "migration_baseline" || events[1].Cause != "signal_merge:mac" {
		t.Fatalf("migration audit baseline: %+v, %v", events, err)
	}
}

func TestIdentityGraphUnlinksWhenEvidenceIsPruned(t *testing.T) {
	s, _ := openTest(t)
	other := netip.MustParseAddr("192.0.2.6")
	storeScan(t, s, "linked", t0,
		identityObs(host, t0, "02:01:02:03:04:05"), identityObs(other, t0, "02:01:02:03:04:05"))
	later := t0.Add(48 * time.Hour)
	a := portObs(later, 22, "open")
	b := portObs(later, 22, "open")
	b.Target = other
	storeScan(t, s, "ports", later, a, b)
	before, err := s.IdentityGraph(ctx)
	if err != nil || len(before) != 1 {
		t.Fatalf("before prune: %+v, %v", before, err)
	}
	if _, err := s.Prune(ctx, Retention{OlderThan: 24 * time.Hour}, later.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	after, err := s.IdentityGraph(ctx)
	if err != nil || len(after) != 2 || len(after[0].Signals) != 0 || len(after[1].Signals) != 0 || after[0].ID == after[1].ID {
		t.Fatalf("unsupported link kept after prune: %+v, %v", after, err)
	}
}

func TestIdentityGraphSplitsChangedMACWithoutStableDeviceID(t *testing.T) {
	s, _ := openTest(t)
	other := netip.MustParseAddr("192.0.2.6")
	storeScan(t, s, "mac-old", t0,
		identityObs(host, t0, "02:01:02:03:04:05"), identityObs(other, t0, "02:01:02:03:04:05"))
	later := t0.Add(time.Hour)
	storeScan(t, s, "mac-new", later, identityObs(other, later, "02:01:02:03:04:06"))
	graph, err := s.IdentityGraph(ctx)
	if err != nil || len(graph) != 2 {
		t.Fatalf("changed MAC stayed linked: %+v, %v", graph, err)
	}
	for _, asset := range graph {
		if asset.Addresses[0].Address == other && (len(asset.Signals) != 2 || asset.Signals[0].Active == asset.Signals[1].Active) {
			t.Fatalf("old MAC was not retired: %+v", asset)
		}
	}
}

func TestIdentityMembershipAuditSurvivesSplitAndPrune(t *testing.T) {
	s, _ := openTest(t)
	other := netip.MustParseAddr("192.0.2.6")
	storeScan(t, s, "joined", t0,
		identityObs(host, t0, "02:01:02:03:04:05"), identityObs(other, t0, "02:01:02:03:04:05"))
	joined, err := s.IdentityGraph(ctx)
	if err != nil || len(joined) != 1 {
		t.Fatalf("joined graph: %+v, %v", joined, err)
	}
	later := t0.Add(time.Hour)
	storeScan(t, s, "changed", later, identityObs(other, later, "02:01:02:03:04:06"))
	events, err := s.IdentityHistory(ctx, other)
	if err != nil || len(events) != 3 {
		t.Fatalf("membership events: %+v, %v", events, err)
	}
	if events[0].Cause != "first_observed" || events[1].Cause != "signal_merge:mac" ||
		events[2].Cause != "signal_changed:mac" || events[2].FromIdentity != joined[0].ID ||
		events[2].ToIdentity == joined[0].ID || events[2].ScanID != "changed" {
		t.Fatalf("incorrect membership audit: %+v", events)
	}
	if _, err := s.Prune(ctx, Retention{OlderThan: time.Minute}, later.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	after, err := s.IdentityHistory(ctx, other)
	if err != nil || len(after) != 4 || after[3].Cause != "retention_removed" || after[3].ToIdentity != "" {
		t.Fatalf("retention audit: %+v, %v", after, err)
	}
}

func TestIdentityCluesRelateWithoutMerging(t *testing.T) {
	s, path := openTest(t)
	other := netip.MustParseAddr("192.0.2.6")
	makeTLS := func(addr netip.Addr) observe.Observation {
		return observe.Observation{Kind: observe.KindService, Timestamp: t0, Target: addr, Transport: "tcp", Port: 443,
			State: "open", Confidence: 100, Service: "https", TLS: &observe.TLS{Certificates: []observe.Certificate{{
				SHA256:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				DNSNames: []string{"Router.Example."},
			}}}}
	}
	storeScan(t, s, "tls", t0, makeTLS(host), makeTLS(other))
	graph, err := s.IdentityGraph(ctx)
	if err != nil || len(graph) != 2 || graph[0].GlobalID == graph[1].GlobalID ||
		len(graph[0].Clues) != 2 || len(graph[1].Clues) != 2 ||
		len(graph[0].Hypotheses) != 1 || graph[0].Hypotheses[0].Confidence != 35 || graph[0].Hypotheses[0].Blocked {
		t.Fatalf("clue graph: %+v, %v", graph, err)
	}
	relations, err := s.IdentityRelations(ctx)
	if err != nil || len(relations) != 2 || relations[0].LeftID == relations[0].RightID {
		t.Fatalf("weak relationships: %+v, %v", relations, err)
	}
	_ = s.Close()
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	again, err := reopened.IdentityGraph(ctx)
	if err != nil || again[0].GlobalID != graph[0].GlobalID {
		t.Fatalf("global ID changed: %+v, %v", again, err)
	}
}

func TestIdentityManualReviewOverridesAutomaticCorrelation(t *testing.T) {
	s, _ := openTest(t)
	other := netip.MustParseAddr("192.0.2.6")
	plain := func(addr netip.Addr, at time.Time) observe.Observation {
		return observe.Observation{Kind: observe.KindHost, Target: addr, Timestamp: at,
			Transport: "icmp", State: "responsive", Confidence: 100}
	}
	storeScan(t, s, "first", t0, plain(host, t0), plain(other, t0))
	if err := s.ReviewIdentityPair(ctx, host, other, "join", "same appliance"); err != nil {
		t.Fatal(err)
	}
	joined, err := s.IdentityGraph(ctx)
	if err != nil || len(joined) != 1 {
		t.Fatalf("manual join: %+v, %v", joined, err)
	}
	later := t0.Add(time.Hour)
	storeScan(t, s, "strong", later,
		identityObs(host, later, "02:01:02:03:04:05"), identityObs(other, later, "02:01:02:03:04:05"))
	if err := s.ReviewIdentityPair(ctx, host, other, "separate", "distinct virtual machines"); err != nil {
		t.Fatal(err)
	}
	storeScan(t, s, "same-signal", later.Add(time.Hour), identityObs(other, later.Add(time.Hour), "02:01:02:03:04:05"))
	separate, err := s.IdentityGraph(ctx)
	if err != nil || len(separate) != 2 {
		t.Fatalf("reviewed separation was undone: %+v, %v", separate, err)
	}
	if err := s.ReviewIdentityPair(ctx, host, other, "clear", "recheck correlation"); err != nil {
		t.Fatal(err)
	}
	storeScan(t, s, "reconcile", later.Add(2*time.Hour), identityObs(other, later.Add(2*time.Hour), "02:01:02:03:04:05"))
	joined, err = s.IdentityGraph(ctx)
	if err != nil || len(joined) != 1 {
		t.Fatalf("clear did not permit recorrelation: %+v, %v", joined, err)
	}
	reviews, err := s.IdentityReviews(ctx)
	if err != nil || len(reviews) != 3 || reviews[2].Decision != "clear" {
		t.Fatalf("review audit: %+v, %v", reviews, err)
	}
}

func TestIdentityProfileSynthesizesValidatedClaimsAndKeepsConflicts(t *testing.T) {
	s, _ := openTest(t)
	modbus := observe.Observation{Kind: observe.KindService, Target: host, Timestamp: t0,
		Transport: "tcp", Port: 502, State: "open", Service: "modbus", Product: "Controller A", Confidence: 100}
	smb := observe.Observation{Kind: observe.KindService, Target: host, Timestamp: t0,
		Transport: "tcp", Port: 445, State: "open", Service: "smb", Confidence: 100,
		Attributes: map[string]string{"smb.os_version": "10.0"}}
	device := observe.Observation{Kind: observe.KindDevice, Target: host, Timestamp: t0,
		Transport: "device", Confidence: 90, Attributes: map[string]string{"device.class": "industrial device"}}
	storeScan(t, s, "profile", t0, modbus, smb, device)
	graph, err := s.IdentityGraph(ctx)
	if err != nil || len(graph) != 1 || graph[0].Profile.Class != "industrial device" ||
		graph[0].Profile.Model != "Controller A" || graph[0].Profile.OS != "Windows 10.0" || len(graph[0].Profile.Claims) != 3 {
		t.Fatalf("profile: %+v, %v", graph, err)
	}
	other := netip.MustParseAddr("192.0.2.6")
	storeScan(t, s, "second", t0.Add(time.Hour), identityObs(host, t0.Add(time.Hour), "02:01:02:03:04:05"),
		identityObs(other, t0.Add(time.Hour), "02:01:02:03:04:05"),
		observe.Observation{Kind: observe.KindService, Target: other, Timestamp: t0.Add(time.Hour),
			Transport: "tcp", Port: 445, State: "open", Service: "smb", Confidence: 100,
			Attributes: map[string]string{"smb.os_version": "11.0"}})
	graph, err = s.IdentityGraph(ctx)
	if err != nil || len(graph) != 1 || graph[0].Profile.OS != "" || len(graph[0].Profile.Claims) != 4 {
		t.Fatalf("conflicting OS claim was flattened: %+v, %v", graph, err)
	}
}

func TestIdentityGraphJoinsVerifiedSSHHostKey(t *testing.T) {
	s, _ := openTest(t)
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	sshObs := func(addr netip.Addr) observe.Observation {
		return observe.Observation{Kind: observe.KindService, Target: addr, Timestamp: t0,
			Transport: "tcp", Port: 22, State: "open", Service: "ssh", Probe: "ssh", Confidence: 100,
			Attributes: map[string]string{"ssh.host_key_sha256": key, "ssh.host_key_type": "ssh-ed25519"}}
	}
	storeScan(t, s, "ssh", t0, sshObs(host), sshObs(netip.MustParseAddr("2001:db8::5")))
	graph, err := s.IdentityGraph(ctx)
	if err != nil || len(graph) != 1 || graph[0].LinkConfidence != 95 || len(graph[0].Addresses) != 2 {
		t.Fatalf("SSH identity link: %+v, %v", graph, err)
	}
}

func TestScopedExternalIdentifiersJoinOnlyWithinScope(t *testing.T) {
	s, _ := openTest(t)
	a := netip.MustParseAddr("192.0.2.5")
	b := netip.MustParseAddr("192.0.2.6")
	c := netip.MustParseAddr("192.0.2.7")
	_, err := s.ImportExternalIdentifiers(ctx, []ExternalIdentifier{
		{Address: a, Kind: "kubernetes.node_uid", Scope: "cluster-a", Value: "node-123"},
		{Address: b, Kind: "kubernetes.node_uid", Scope: "cluster-a", Value: "node-123"},
		{Address: c, Kind: "kubernetes.node_uid", Scope: "cluster-b", Value: "node-123"},
	})
	if err != nil {
		t.Fatal(err)
	}
	graph, err := s.IdentityGraph(ctx)
	if err != nil || len(graph) != 2 || len(graph[0].Addresses) != 2 || graph[0].LinkConfidence != 99 {
		t.Fatalf("scoped graph: %+v, %v", graph, err)
	}
	second, _ := openTest(t)
	if _, err := second.ImportExternalIdentifiers(ctx, []ExternalIdentifier{{Address: a, Kind: "kubernetes.node_uid", Scope: "cluster-a", Value: "node-123"}}); err != nil {
		t.Fatal(err)
	}
	otherGraph, err := second.IdentityGraph(ctx)
	if err != nil || len(otherGraph) != 1 || len(graph[0].PortableIDs) != 1 ||
		graph[0].PortableIDs[0] != otherGraph[0].PortableIDs[0] || graph[0].GlobalID == otherGraph[0].GlobalID {
		t.Fatalf("cross-database IDs: %+v, %+v, %v", graph, otherGraph, err)
	}
	if _, err := s.ImportExternalIdentifiers(ctx, []ExternalIdentifier{{Address: a, Kind: "cloud.aws.instance_id", Scope: "", Value: "i-123"}}); err == nil {
		t.Fatal("accepted unscoped cloud identifier")
	}
}

func TestManualSeparationPreservesOtherReviewedJoins(t *testing.T) {
	s, _ := openTest(t)
	b := netip.MustParseAddr("192.0.2.6")
	c := netip.MustParseAddr("192.0.2.7")
	storeScan(t, s, "three", t0,
		identityObs(host, t0, ""), identityObs(b, t0, ""), identityObs(c, t0, ""))
	if err := s.ReviewIdentityPair(ctx, host, b, "join", "one group"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReviewIdentityPair(ctx, b, c, "join", "second group"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReviewIdentityPair(ctx, host, b, "separate", "host is separate"); err != nil {
		t.Fatal(err)
	}
	graph, err := s.IdentityGraph(ctx)
	if err != nil || len(graph) != 2 {
		t.Fatalf("separated graph: %+v, %v", graph, err)
	}
	for _, asset := range graph {
		if len(asset.Addresses) == 2 && (asset.Addresses[0].Address != b || asset.Addresses[1].Address != c) {
			t.Fatalf("reviewed pair split: %+v", graph)
		}
	}
}
