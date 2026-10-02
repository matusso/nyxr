package storage

import (
	"context"
	"database/sql"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

var (
	ctx  = context.Background()
	host = netip.MustParseAddr("192.0.2.5")
	t0   = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
)

func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nyxr.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func storeScan(t *testing.T, s *Store, id string, started time.Time, obs ...observe.Observation) {
	t.Helper()
	scan := observe.Scan{ID: id, Profile: "tcp-common", Started: started, Status: "running", Targets: 1}
	if err := s.BeginScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	for i := range obs {
		obs[i].Stamp(id)
	}
	if err := s.AddObservations(ctx, obs); err != nil {
		t.Fatal(err)
	}
	scan.Status, scan.Finished, scan.Observations = "completed", started.Add(time.Minute), len(obs)
	scan.Capture = &observe.CaptureStats{Path: "scan.pcapng", Written: 2}
	if err := s.FinishScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
}

func portObs(at time.Time, port uint16, state string) observe.Observation {
	return observe.Observation{Timestamp: at, Target: host, Transport: "tcp", Port: port, State: state, Confidence: 100, Reason: "r", Probe: "tcp-connect"}
}

func serviceObs(at time.Time, port uint16, service, product string) observe.Observation {
	return observe.Observation{Kind: observe.KindService, Timestamp: at, Target: host, Transport: "tcp", Port: port, State: "open",
		Service: service, Product: product, Fingerprint: observe.FingerprintMatched, Confidence: 100,
		TLS: &observe.TLS{Version: "TLS 1.3", Certificates: []observe.Certificate{{Subject: "CN=x", SHA256: "ab"}}},
		Evidence: []observe.Evidence{
			{Probe: "banner", Layer: "tcp", Error: "timeout"},
			{Probe: "http", Layer: "tls", Request: []byte("GET / HTTP/1.1\r\n\r\n"), Response: []byte{0, 1, 2, 0xff}, Matched: "http", Truncated: true},
		}}
}

func TestMigrationsAreIdempotentAndVersioned(t *testing.T) {
	s, path := openTest(t)
	v, err := s.SchemaVersion(ctx)
	if err != nil || v != len(migrations) {
		t.Fatalf("schema version %d, %v", v, err)
	}
	_ = s.Close()
	again, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	_ = again.Close()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (999, 'future')`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := Open(ctx, path); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("a newer schema must be refused, got %v", err)
	}
}

func TestObservationRoundTripWithEvidence(t *testing.T) {
	s, _ := openTest(t)
	storeScan(t, s, "scan-a", t0, portObs(t0, 443, "open"), serviceObs(t0.Add(time.Second), 443, "https", "nginx"),
		observe.Observation{Timestamp: t0, Target: host, Transport: "icmp", State: "responsive"})
	all, err := s.Observations(ctx, Filter{ScanID: "scan-a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("want 3 observations, got %d", len(all))
	}
	services, err := s.Observations(ctx, Filter{Kind: observe.KindService, Address: host, Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 1 {
		t.Fatalf("service filter: %+v", services)
	}
	got := services[0]
	if got.Schema != observe.SchemaVersion || got.ScanID != "scan-a" || got.Product != "nginx" || got.TLS == nil || got.TLS.Certificates[0].Subject != "CN=x" {
		t.Fatalf("record fields lost: %+v", got)
	}
	if len(got.Evidence) != 2 || string(got.Evidence[1].Response) != "\x00\x01\x02\xff" || !got.Evidence[1].Truncated || got.Evidence[0].Error != "timeout" {
		t.Fatalf("evidence lost: %+v", got.Evidence)
	}
	if hosts, _ := s.Observations(ctx, Filter{Kind: observe.KindHost}); len(hosts) != 1 || hosts[0].Transport != "icmp" {
		t.Fatalf("host kind: %+v", hosts)
	}
	scans, err := s.Scans(ctx, 10)
	if err != nil || len(scans) != 1 || scans[0].Status != "completed" || scans[0].Observations != 3 || scans[0].Capture.Written != 2 {
		t.Fatalf("scan summary: %+v %v", scans, err)
	}
}

func TestUnknownFingerprintQuery(t *testing.T) {
	s, _ := openTest(t)
	unknown := serviceObs(t0, 9999, "", "")
	unknown.Fingerprint = observe.FingerprintUnknown
	storeScan(t, s, "scan-u", t0, unknown, serviceObs(t0, 22, "ssh", "OpenSSH"))
	got, err := s.Observations(ctx, Filter{Unknown: true})
	if err != nil || len(got) != 1 || got[0].Port != 9999 {
		t.Fatalf("unknown query: %+v %v", got, err)
	}
}

func TestAssetsShowLatestStateAcrossScans(t *testing.T) {
	s, _ := openTest(t)
	storeScan(t, s, "scan-1", t0, portObs(t0, 22, "open"), serviceObs(t0, 22, "ssh", "OpenSSH"), portObs(t0, 80, "open"), serviceObs(t0, 80, "http", "Apache"))
	later := t0.Add(24 * time.Hour)
	storeScan(t, s, "scan-2", later, portObs(later, 80, "closed"))
	assets, err := s.Assets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].Address != host || !assets[0].FirstSeen.Equal(t0) || !assets[0].LastSeen.Equal(later) {
		t.Fatalf("asset: %+v", assets)
	}
	ports := assets[0].Ports
	if len(ports) != 2 {
		t.Fatalf("ports: %+v", ports)
	}
	if ports[0].Port != 22 || ports[0].Service != "ssh" || ports[0].Product != "OpenSSH" {
		t.Fatalf("port 22: %+v", ports[0])
	}
	if ports[1].Port != 80 || ports[1].State != "closed" || ports[1].Service != "" || ports[1].ScanID != "scan-2" {
		t.Fatalf("a newer closed state must hide the stale service: %+v", ports[1])
	}
}

func TestPacketEvidenceRoundTrip(t *testing.T) {
	s, _ := openTest(t)
	storeScan(t, s, "scan-p", t0, portObs(t0, 443, "open"))
	pe := observe.PacketEvidence{ScanID: "scan-p", Target: host, Transport: "tcp", Port: 443, Capture: "scan.pcapng", Truncated: true,
		Packets: []observe.Packet{{ID: 1, Timestamp: t0, Direction: "tx", Length: 54, Summary: "syn"}, {ID: 2, Timestamp: t0, Direction: "rx", Length: 60, Summary: "syn-ack"}}}
	if err := s.AddPacketEvidence(ctx, []observe.PacketEvidence{pe}); err != nil {
		t.Fatal(err)
	}
	got, err := s.PacketEvidence(ctx, "scan-p", host)
	if err != nil || len(got) != 1 || len(got[0].Packets) != 2 || got[0].Packets[1].Summary != "syn-ack" || !got[0].Truncated || got[0].Port != 443 {
		t.Fatalf("packet evidence: %+v %v", got, err)
	}
	if err := s.AddPacketEvidence(ctx, []observe.PacketEvidence{pe}); err == nil {
		t.Fatal("duplicate flow for one scan must be rejected")
	}
}

func TestPruneRetention(t *testing.T) {
	s, _ := openTest(t)
	for i, id := range []string{"old", "mid", "new"} {
		at := t0.Add(time.Duration(i) * 48 * time.Hour)
		storeScan(t, s, id, at, serviceObs(at, 443, "https", "nginx"))
	}
	if err := s.AddPacketEvidence(ctx, []observe.PacketEvidence{{ScanID: "old", Target: host, Transport: "tcp", Port: 443, Capture: "c", Packets: []observe.Packet{{ID: 1, Timestamp: t0}}}}); err != nil {
		t.Fatal(err)
	}
	now := t0.Add(5 * 24 * time.Hour)
	n, err := s.Prune(ctx, Retention{OlderThan: 72 * time.Hour}, now)
	if err != nil || n != 1 {
		t.Fatalf("age prune deleted %d, %v", n, err)
	}
	n, err = s.Prune(ctx, Retention{KeepLast: 1}, now)
	if err != nil || n != 1 {
		t.Fatalf("count prune deleted %d, %v", n, err)
	}
	scans, _ := s.Scans(ctx, 10)
	if len(scans) != 1 || scans[0].ID != "new" {
		t.Fatalf("remaining scans: %+v", scans)
	}
	var evidence, flows int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM evidence`).Scan(&evidence)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM packet_flows`).Scan(&flows)
	if evidence != 2 || flows != 0 {
		t.Fatalf("cascade left evidence=%d flows=%d", evidence, flows)
	}
	s.Prune(ctx, Retention{OlderThan: time.Hour}, now.Add(365*24*time.Hour))
	if assets, _ := s.Assets(ctx); len(assets) != 0 {
		t.Fatalf("orphan assets kept: %+v", assets)
	}
	if _, err := s.Prune(ctx, Retention{KeepLast: -1}, now); err == nil {
		t.Fatal("negative retention accepted")
	}
}

func TestOpenOnlyAndKnownOpen(t *testing.T) {
	s, _ := openTest(t)
	storeScan(t, s, "scan-1", t0, portObs(t0, 22, "open"), portObs(t0, 80, "open"), portObs(t0, 81, "filtered"))
	later := t0.Add(time.Hour)
	storeScan(t, s, "scan-2", later, portObs(later, 80, "closed"))
	other := portObs(t0, 443, "closed")
	other.Target = netip.MustParseAddr("192.0.2.6")
	storeScan(t, s, "scan-3", t0, other)
	assets, err := s.Assets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	open := OpenOnly(assets)
	if len(open) != 1 || open[0].Address != host || len(open[0].Ports) != 1 || open[0].Ports[0].Port != 22 {
		t.Fatalf("open-only assets: %+v", open)
	}
	if len(assets[0].Ports) != 3 {
		t.Fatal("OpenOnly must not modify its input")
	}
	known, err := s.KnownOpen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(known) != 1 || known[0].Address != host || known[0].Port != 22 || known[0].Transport != "tcp" {
		t.Fatalf("known open: %+v", known)
	}
}
