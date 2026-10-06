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
	if joined == nil || len(joined.Signals) != 2 || joined.ID != joined.Addresses[0].IdentityID || joined.ID != joined.Addresses[1].IdentityID {
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
