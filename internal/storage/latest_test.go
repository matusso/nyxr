package storage

import (
	"database/sql"
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// legacyAssets is the window-function query Assets used before
// latest_observations existed. It ranks every stored observation per call,
// so it is the reference the maintained table must match exactly.
func legacyAssets(t *testing.T, s *Store) []Asset {
	t.Helper()
	rows, err := s.db.QueryContext(ctx, `
		WITH ranked AS (
			SELECT o.*, ROW_NUMBER() OVER (PARTITION BY o.asset_id, o.transport, o.port, o.kind ORDER BY o.observed_at DESC, o.id DESC) AS rn
			FROM observations o WHERE o.kind IN ('port', 'service')
		)
		SELECT m.identity_id, a.address, a.first_seen, a.last_seen, p.transport, p.port, p.state, p.scan_id, p.observed_at,
			COALESCE(s.service, ''), COALESCE(s.product, ''), COALESCE(s.version, '')
		FROM assets a JOIN identity_members m ON m.asset_id = a.id
		LEFT JOIN ranked p ON p.asset_id = a.id AND p.kind = 'port' AND p.rn = 1
		LEFT JOIN ranked s ON s.asset_id = a.id AND s.kind = 'service' AND s.rn = 1 AND s.transport = p.transport AND s.port = p.port
			AND s.observed_at >= p.observed_at
		ORDER BY a.address, p.transport, p.port`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		var identityID int64
		var address, first, last string
		var transport, state, scanID, observed sql.NullString
		var port sql.NullInt64
		var ps PortSummary
		if err := rows.Scan(&identityID, &address, &first, &last, &transport, &port, &state, &scanID, &observed, &ps.Service, &ps.Product, &ps.Version); err != nil {
			t.Fatal(err)
		}
		addr, _ := netip.ParseAddr(address)
		if len(out) == 0 || out[len(out)-1].Address != addr {
			out = append(out, Asset{IdentityID: identityName(identityID), Address: addr, FirstSeen: parseTS(first), LastSeen: parseTS(last)})
		}
		if transport.Valid {
			ps.Transport, ps.Port, ps.State, ps.ScanID, ps.ObservedAt = transport.String, uint16(port.Int64), state.String, scanID.String, parseTS(observed.String)
			out[len(out)-1].Ports = append(out[len(out)-1].Ports, ps)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func checkMatchesLegacy(t *testing.T, s *Store, label string) {
	t.Helper()
	want := legacyAssets(t, s)
	got, err := s.Assets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: Assets differs from the legacy query\n got %+v\nwant %+v", label, got, want)
	}
	open, err := s.AssetsWith(ctx, OpenPorts, true)
	if err != nil {
		t.Fatal(err)
	}
	if wantOpen := OpenOnly(want); !reflect.DeepEqual(open, wantOpen) && !(len(open) == 0 && len(wantOpen) == 0) {
		t.Fatalf("%s: open assets differ\n got %+v\nwant %+v", label, open, wantOpen)
	}
	bare, err := s.AssetsWith(ctx, NoPorts, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(bare) != len(want) {
		t.Fatalf("%s: NoPorts returned %d addresses, want %d", label, len(bare), len(want))
	}
	for i := range bare {
		if bare[i].Address != want[i].Address || len(bare[i].Ports) != 0 {
			t.Fatalf("%s: NoPorts address %d = %+v", label, i, bare[i])
		}
	}
	hosts, openPorts, services, err := s.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantOpenPorts, wantServices := 0, 0
	for _, a := range want {
		for _, p := range a.Ports {
			if p.State == "open" {
				wantOpenPorts++
				if p.Service != "" {
					wantServices++
				}
			}
		}
	}
	if hosts != len(want) || openPorts != wantOpenPorts || services != wantServices {
		t.Fatalf("%s: inventory %d/%d/%d, want %d/%d/%d", label, hosts, openPorts, services, len(want), wantOpenPorts, wantServices)
	}
}

// TestLatestObservationsMatchLegacyQuery drives inserts in shuffled time
// order with timestamp ties, services before and after port results, and
// scan pruning, and checks every inventory read against the legacy query.
func TestLatestObservationsMatchLegacyQuery(t *testing.T) {
	s, _ := openTest(t)
	rng := rand.New(rand.NewSource(7))
	hosts := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::7")}
	states := []string{"open", "closed", "filtered", "open|filtered"}
	for scan := range 12 {
		started := t0.Add(time.Duration(scan) * time.Hour)
		var obs []observe.Observation
		for range 40 {
			// Timestamps land on a coarse grid so equal observed_at values occur.
			at := t0.Add(time.Duration(rng.Intn(48)) * 15 * time.Minute)
			h := hosts[rng.Intn(len(hosts))]
			transport := []string{"tcp", "udp"}[rng.Intn(2)]
			port := uint16(20 + rng.Intn(6))
			if rng.Intn(4) == 0 {
				obs = append(obs, observe.Observation{Kind: observe.KindService, Timestamp: at, Target: h, Transport: transport, Port: port,
					State: "open", Service: fmt.Sprintf("svc%d", rng.Intn(3)), Product: "p", Version: "1", Confidence: 100, Reason: "r", Probe: "banner"})
				continue
			}
			obs = append(obs, observe.Observation{Timestamp: at, Target: h, Transport: transport, Port: port,
				State: states[rng.Intn(len(states))], Confidence: 100, Reason: "r", Probe: "tcp-connect"})
		}
		storeScan(t, s, fmt.Sprintf("scan-%02d", scan), started, obs...)
		checkMatchesLegacy(t, s, fmt.Sprintf("after scan %d", scan))
	}
	// Pruning deletes observations, including current latest ones.
	if _, err := s.Prune(ctx, Retention{KeepLast: 5}, t0.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	checkMatchesLegacy(t, s, "after keep-last prune")
	if _, err := s.Prune(ctx, Retention{OlderThan: time.Hour}, t0.Add(10*time.Hour+30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	checkMatchesLegacy(t, s, "after age prune")
}

// TestLatestObservationsBackfill checks that the migration's backfill
// statement rebuilds the table to the same content the triggers maintain.
func TestLatestObservationsBackfill(t *testing.T) {
	s, _ := openTest(t)
	storeScan(t, s, "a", t0, portObs(t0, 22, "closed"), portObs(t0.Add(time.Minute), 80, "open"))
	storeScan(t, s, "b", t0.Add(time.Hour), portObs(t0.Add(time.Hour), 22, "open"), serviceObs(t0.Add(time.Hour), 22, "ssh", "OpenSSH"))
	maintained, err := s.Assets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backfill := migrations[10] // latest_observations
	if _, err := s.db.ExecContext(ctx, `DROP TRIGGER observations_latest_insert; DROP TRIGGER observations_latest_delete; DROP TABLE latest_observations;`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, backfill); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := s.Assets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rebuilt, maintained) || len(rebuilt) != 1 || len(rebuilt[0].Ports) != 2 || rebuilt[0].Ports[0].Service != "ssh" {
		t.Fatalf("backfill %+v, maintained %+v", rebuilt, maintained)
	}
}
