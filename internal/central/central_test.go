package central

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// testStores returns a fresh SQLite store and, when NYXR_TEST_POSTGRES_DSN
// is set, a fresh PostgreSQL store in its own schema.
func testStores(t *testing.T) map[string]*DB {
	t.Helper()
	ctx := context.Background()
	out := map[string]*DB{}
	sq, err := Open(ctx, filepath.Join(t.TempDir(), "central.db"), &DirObjects{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sq.Close() })
	out["sqlite"] = sq
	if dsn := os.Getenv("NYXR_TEST_POSTGRES_DSN"); dsn != "" {
		out["postgres"] = openPostgres(t, dsn)
	}
	return out
}

func openPostgres(t *testing.T, dsn string) *DB {
	t.Helper()
	ctx := context.Background()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	var r [6]byte
	_, _ = rand.Read(r[:])
	name := "t_" + hex.EncodeToString(r[:])
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), `DROP SCHEMA `+name+` CASCADE`)
		admin.Close()
	})
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	pg, err := Open(ctx, dsn+sep+"search_path="+name, &DirObjects{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })
	return pg
}

const lineageA, lineageB, lineageC = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccc"

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

var seq int

// sealed builds a sealed observation the way a lineage stores it.
func sealed(t *testing.T, lineage, addr string, at time.Time, mutate func(*observe.Observation)) ObservationRecord {
	t.Helper()
	seq++
	o := observe.Observation{Target: netip.MustParseAddr(addr), Timestamp: at, ID: fmt.Sprintf("store:%s/%d", lineage, seq)}
	mutate(&o)
	o.Stamp("scan-" + lineage[:4])
	src, err := o.Seal()
	if err != nil {
		t.Fatal(err)
	}
	return ObservationRecord{ArtifactID: observe.ArtifactID(src), Source: src}
}

func cloudID(kind, scope, value string) func(*observe.Observation) {
	return func(o *observe.Observation) {
		o.Kind, o.Transport, o.State, o.Confidence, o.Probe = observe.KindHost, "inventory", "observed", 100, "inventory-import"
		o.Fields = map[string]string{"external.kind": kind, "external.scope": scope, "external.value": value}
	}
}

func sshKey(key, hostname string) func(*observe.Observation) {
	return func(o *observe.Observation) {
		o.Kind, o.Transport, o.Port, o.State, o.Confidence, o.Probe, o.Service = observe.KindService, "tcp", 22, "open", 95, "ssh", "ssh"
		o.Attributes = map[string]string{"ssh.host_key_type": "ssh-ed25519", "ssh.host_key_sha256": key, "nmap.hostname": hostname}
	}
}

func key(b byte) string { return strings.Repeat(hex.EncodeToString([]byte{b}), 32) }

// partitionOf renders entity membership independent of entity IDs.
func partitionOf(t *testing.T, s *DB) []string {
	t.Helper()
	entities, err := s.Entities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entities {
		var nodes []string
		for _, n := range e.Nodes {
			nodes = append(nodes, n.Key)
		}
		sort.Strings(nodes)
		out = append(out, strings.Join(nodes, "+"))
	}
	sort.Strings(out)
	return out
}

func entityOfNode(t *testing.T, s *DB, node string) Entity {
	t.Helper()
	entities, err := s.Entities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entities {
		for _, n := range e.Nodes {
			if n.Key == node {
				return e
			}
		}
	}
	t.Fatalf("node %s has no entity", node)
	return Entity{}
}

func node(lineage, addr string) string { return provisionalNode(lineage, netip.MustParseAddr(addr)) }

// fixture: A and B observe the same scoped AWS instance from two lineages;
// C sees a host with A's SSH host key (a cloned image, say).
func fixture(t *testing.T) []Batch {
	aws := cloudID("cloud.aws.instance_id", "123456789012", "i-0abc")
	return []Batch{
		{Lineage: lineageA, Observations: []ObservationRecord{
			sealed(t, lineageA, "10.0.0.1", t0, aws),
			sealed(t, lineageA, "10.0.0.1", t0.Add(time.Minute), sshKey(key(0xaa), "web1.example")),
		}},
		{Lineage: lineageB, Kind: LineageController, Observations: []ObservationRecord{
			sealed(t, lineageB, "172.16.0.9", t0.Add(2*time.Minute), aws),
		}},
		{Lineage: lineageC, Observations: []ObservationRecord{
			sealed(t, lineageC, "192.168.1.5", t0.Add(3*time.Minute), sshKey(key(0xaa), "web1.example")),
		}},
	}
}

func TestIngestIsIdempotentAndOrderIndependent(t *testing.T) {
	ctx := context.Background()
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			batches := fixture(t)
			for _, b := range batches {
				res, err := s.Ingest(ctx, b)
				if err != nil {
					t.Fatal(err)
				}
				if res.Observations != len(b.Observations) || res.Duplicates != 0 {
					t.Fatalf("first delivery: %+v", res)
				}
			}
			want := partitionOf(t, s)
			if len(want) != 2 {
				t.Fatalf("want A+B joined and C apart, got %v", want)
			}
			joined := entityOfNode(t, s, node(lineageA, "10.0.0.1"))
			if joined.Link != "scoped_signal" || len(joined.Nodes) != 2 || len(joined.PortableIDs) != 1 {
				t.Fatalf("joined entity: %+v", joined)
			}
			// Redeliver everything: nothing changes, revisions included.
			for _, b := range batches {
				res, err := s.Ingest(ctx, b)
				if err != nil {
					t.Fatal(err)
				}
				if res.Observations != 0 || res.Duplicates != len(b.Observations) || res.Moved != 0 {
					t.Fatalf("redelivery: %+v", res)
				}
			}
			if again := entityOfNode(t, s, node(lineageA, "10.0.0.1")); again.Revision != joined.Revision || again.ID != joined.ID {
				t.Fatalf("redelivery changed the entity: %+v -> %+v", joined, again)
			}

			// Another store receives the records reversed, one per batch.
			other := testStores(t)[name]
			for i := len(batches) - 1; i >= 0; i-- {
				for j := len(batches[i].Observations) - 1; j >= 0; j-- {
					b := batches[i]
					b.Observations = []ObservationRecord{b.Observations[j]}
					if _, err := other.Ingest(ctx, b); err != nil {
						t.Fatal(err)
					}
				}
			}
			if got := partitionOf(t, other); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("order changed the partition:\n%v\n%v", want, got)
			}
		})
	}
}

func TestWeakAndDeviceCluesNeverMerge(t *testing.T) {
	ctx := context.Background()
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			for _, b := range fixture(t) {
				if _, err := s.Ingest(ctx, b); err != nil {
					t.Fatal(err)
				}
			}
			if a, c := entityOfNode(t, s, node(lineageA, "10.0.0.1")), entityOfNode(t, s, node(lineageC, "192.168.1.5")); a.ID == c.ID {
				t.Fatal("a shared SSH host key joined lineages")
			}
			rel, err := s.Relations(ctx)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]Relation{}
			for _, r := range rel {
				got[r.Strength+"/"+r.Kind] = r
			}
			if r := got["device/ssh.host_key_sha256"]; len(r.Entities) != 2 {
				t.Fatalf("device relation missing: %+v", rel)
			}
			if r := got["weak/hostname"]; len(r.Entities) != 2 || r.Value != "web1.example" {
				t.Fatalf("weak relation missing: %+v", rel)
			}
		})
	}
}

func TestScopedValueConflictIsKeptNotMerged(t *testing.T) {
	ctx := context.Background()
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			aws := cloudID("cloud.aws.instance_id", "123456789012", "i-0abc")
			batches := []Batch{
				{Lineage: lineageA, Observations: []ObservationRecord{
					sealed(t, lineageA, "10.0.0.1", t0, aws),
					sealed(t, lineageA, "10.0.0.1", t0, cloudID("kubernetes.node_uid", "prod", "uid-1")),
				}},
				{Lineage: lineageB, Observations: []ObservationRecord{
					sealed(t, lineageB, "10.9.0.1", t0, aws),
					sealed(t, lineageB, "10.9.0.1", t0, cloudID("kubernetes.node_uid", "prod", "uid-2")),
				}},
			}
			for _, b := range batches {
				if _, err := s.Ingest(ctx, b); err != nil {
					t.Fatal(err)
				}
			}
			if len(partitionOf(t, s)) != 2 {
				t.Fatal("conflicting scoped values were merged")
			}
			conflicts, err := s.Conflicts(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(conflicts) != 1 || conflicts[0].Reason != "scoped_value_conflict" || conflicts[0].Kind != "kubernetes.node_uid" {
				t.Fatalf("conflicts: %+v", conflicts)
			}
		})
	}
}

func TestConflictingRecordUnderStoredIDIsRejected(t *testing.T) {
	ctx := context.Background()
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			rec := sealed(t, lineageA, "10.0.0.1", t0, cloudID("cloud.gcp.instance_id", "proj-1", "42"))
			if _, err := s.Ingest(ctx, Batch{Lineage: lineageA, Observations: []ObservationRecord{rec}}); err != nil {
				t.Fatal(err)
			}
			o, err := observe.ReadSource(rec.Source, rec.ArtifactID)
			if err != nil {
				t.Fatal(err)
			}
			o.Source, o.Reason = nil, "rewritten"
			src, err := o.Seal()
			if err != nil {
				t.Fatal(err)
			}
			res, err := s.Ingest(ctx, Batch{Lineage: lineageA, Observations: []ObservationRecord{{ArtifactID: observe.ArtifactID(src), Source: src}}})
			if err != nil {
				t.Fatal(err)
			}
			if res.Conflicts != 1 || res.Observations != 0 {
				t.Fatalf("rewritten record: %+v", res)
			}
			bad := rec
			bad.ArtifactID = "sha256:" + strings.Repeat("0", 64)
			if _, err := s.Ingest(ctx, Batch{Lineage: lineageA, Observations: []ObservationRecord{bad}}); err == nil {
				t.Fatal("a source not matching its artifact ID was accepted")
			}
		})
	}
}

func TestTimeQualityAndProvenance(t *testing.T) {
	ctx := context.Background()
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			skewed := sealed(t, lineageB, "10.0.0.7", t0, sshKey(key(1), "a.example"))
			skewed.Fleet, skewed.ClockOffset, skewed.AgentID, skewed.LeaseID, skewed.JobID, skewed.Attempt = true, 10*time.Second, "agent-1", "lease-1", "job-1", 2
			fine := sealed(t, lineageB, "10.0.0.7", t0, sshKey(key(1), "a.example"))
			fine.Fleet, fine.ClockOffset = true, -time.Second
			local := sealed(t, lineageB, "10.0.0.7", t0, sshKey(key(1), "a.example"))
			if _, err := s.Ingest(ctx, Batch{Lineage: lineageB, Kind: LineageController, Observations: []ObservationRecord{skewed, fine, local}}); err != nil {
				t.Fatal(err)
			}
			got, err := s.Observations(ctx, lineageB, netip.MustParseAddr("10.0.0.7"), 0)
			if err != nil {
				t.Fatal(err)
			}
			byID := map[string]StoredObservation{}
			for _, o := range got {
				byID[o.ArtifactID] = o
			}
			if o := byID[skewed.ArtifactID]; o.TimeQuality != TimeAgentSkewed || !o.ObservedAt.Equal(t0.Add(-10*time.Second)) ||
				o.AgentID != "agent-1" || o.LeaseID != "lease-1" || o.Attempt != 2 || !o.ReportedAt.Equal(t0) {
				t.Fatalf("skewed: %+v", o)
			}
			if o := byID[fine.ArtifactID]; o.TimeQuality != TimeAgentCorrected || !o.ObservedAt.Equal(t0.Add(time.Second)) {
				t.Fatalf("corrected: %+v", o)
			}
			if o := byID[local.ArtifactID]; o.TimeQuality != TimeLocalClock || !o.ObservedAt.Equal(t0) {
				t.Fatalf("local: %+v", o)
			}
		})
	}
}

func TestScanSummaryNeverRegresses(t *testing.T) {
	ctx := context.Background()
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			done := observe.Scan{ID: "s1", Profile: "default", Started: t0, Finished: t0.Add(time.Minute), Status: "completed"}
			running := observe.Scan{ID: "s1", Profile: "default", Started: t0, Status: "running"}
			for _, sc := range []observe.Scan{done, running} {
				if _, err := s.Ingest(ctx, Batch{Lineage: lineageA, Scans: []ScanRecord{{Scan: sc}}}); err != nil {
					t.Fatal(err)
				}
			}
			var status string
			if err := s.db.QueryRowContext(ctx, s.q(`SELECT status FROM scans WHERE lineage = ? AND scan_id = ?`), lineageA, "s1").Scan(&status); err != nil {
				t.Fatal(err)
			}
			if status != "completed" {
				t.Fatalf("a late running summary regressed the scan to %s", status)
			}
		})
	}
}

func TestMembershipSnapshotsAndCursor(t *testing.T) {
	ctx := context.Background()
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			a1, a2 := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
			obs := []ObservationRecord{sealed(t, lineageA, "10.0.0.1", t0, sshKey(key(3), "x.example")), sealed(t, lineageA, "10.0.0.2", t0, sshKey(key(4), "y.example"))}
			if _, err := s.Ingest(ctx, Batch{Lineage: lineageA, Observations: obs, Cursor: 7}); err != nil {
				t.Fatal(err)
			}
			before := entityOfNode(t, s, node(lineageA, "10.0.0.1"))
			local := "urn:nyxr:" + lineageA + ":NYXR-000000000001"
			newer := &MemberSnapshot{Revision: 5, Members: map[netip.Addr]string{a1: local, a2: local}}
			older := &MemberSnapshot{Revision: 3, Members: map[netip.Addr]string{a1: local}}
			if res, err := s.Ingest(ctx, Batch{Lineage: lineageA, Members: newer, Cursor: 3}); err != nil || !res.MembersApplied {
				t.Fatalf("newer snapshot: %+v %v", res, err)
			}
			if res, err := s.Ingest(ctx, Batch{Lineage: lineageA, Members: older}); err != nil || res.MembersApplied {
				t.Fatalf("older snapshot applied: %+v %v", res, err)
			}
			if p := partitionOf(t, s); len(p) != 1 || p[0] != local {
				t.Fatalf("local identity not used as the node: %v", p)
			}
			if after := entityOfNode(t, s, local); after.ID != before.ID {
				t.Fatalf("the entity ID should follow the addresses to the local identity: %s -> %s", before.ID, after.ID)
			}
			lin, err := s.Lineages(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(lin) != 1 || lin[0].Cursor != 7 || lin[0].MemberRevision != 5 || lin[0].Observations != 2 {
				t.Fatalf("lineage: %+v", lin)
			}
			// Provisional nodes were retired with an audit event.
			hist, err := s.History(ctx, node(lineageA, "10.0.0.2"))
			if err != nil {
				t.Fatal(err)
			}
			if len(hist) != 2 || hist[1].ToEntity != "" || !strings.HasSuffix(hist[1].Cause, ":node_retired") {
				t.Fatalf("history: %+v", hist)
			}
			bad := &MemberSnapshot{Revision: 9, Members: map[netip.Addr]string{a1: "urn:nyxr:" + lineageB + ":NYXR-000000000001"}}
			if _, err := s.Ingest(ctx, Batch{Lineage: lineageA, Members: bad}); err == nil {
				t.Fatal("a membership naming another lineage was accepted")
			}
		})
	}
}

func TestManualDecisionsAreReversibleAndAudited(t *testing.T) {
	ctx := context.Background()
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			for _, b := range fixture(t) {
				if _, err := s.Ingest(ctx, b); err != nil {
					t.Fatal(err)
				}
			}
			a, b, c := node(lineageA, "10.0.0.1"), node(lineageB, "172.16.0.9"), node(lineageC, "192.168.1.5")
			joined := entityOfNode(t, s, a)

			// A mistaken automatic link: separate it.
			sep, err := s.Decide(ctx, Decision{Action: DecisionSeparate, NodeA: a, NodeB: b, Note: "instance ID reused after restore", Actor: "op",
				Expect: []EntityVersion{{joined.ID, joined.Revision}}})
			if err != nil {
				t.Fatal(err)
			}
			if sep.Moved != 1 || entityOfNode(t, s, a).ID == entityOfNode(t, s, b).ID {
				t.Fatalf("separation did not split: %+v", sep)
			}
			if entityOfNode(t, s, a).ID != joined.ID {
				t.Fatal("on a tie the part with the lowest node key keeps the entity ID")
			}
			conflicts, err := s.Conflicts(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(conflicts) != 1 || !strings.HasPrefix(conflicts[0].Reason, "separated_by_decision_") {
				t.Fatalf("the refused signal edge should be kept: %+v", conflicts)
			}
			// A stale revision is refused with nothing changed.
			_, err = s.Decide(ctx, Decision{Action: DecisionJoin, NodeA: a, NodeB: b, Note: "x", Expect: []EntityVersion{{joined.ID, joined.Revision}}})
			if !errors.Is(err, ErrStaleRevision) {
				t.Fatalf("stale expect: %v", err)
			}
			// A manual join cannot bridge an active separation through C.
			if _, err := s.Decide(ctx, Decision{Action: DecisionJoin, NodeA: a, NodeB: c, Note: "same rack"}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Decide(ctx, Decision{Action: DecisionJoin, NodeA: b, NodeB: c, Note: "bridge"}); err == nil {
				t.Fatal("a join bridging a separation was accepted")
			}
			if e := entityOfNode(t, s, c); e.Link != "manual" || e.ID != entityOfNode(t, s, a).ID {
				t.Fatalf("manual join: %+v", e)
			}
			// Revert the separation: the automatic link returns.
			if _, err := s.Revert(ctx, sep.ID, "separation was a mistake", "op", nil); err != nil {
				t.Fatal(err)
			}
			if e := entityOfNode(t, s, b); e.ID != entityOfNode(t, s, a).ID || e.Link != "scoped_signal+manual" {
				t.Fatalf("revert did not rejoin: %+v", e)
			}
			if _, err := s.Revert(ctx, sep.ID, "again", "op", nil); err == nil {
				t.Fatal("a double revert was accepted")
			}
			decisions, err := s.Decisions(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(decisions) != 3 || decisions[0].RevertedBy != decisions[2].ID || decisions[2].Target != sep.ID {
				t.Fatalf("decisions: %+v", decisions)
			}
			hist, err := s.History(ctx, b)
			if err != nil {
				t.Fatal(err)
			}
			var causes []string
			for _, e := range hist {
				causes = append(causes, e.Cause)
			}
			if len(hist) != 3 || causes[1] != "decision:separate" || !strings.HasPrefix(causes[2], "revert:") {
				t.Fatalf("history of b: %v", causes)
			}
		})
	}
}

func TestConcurrentRevisionsConflict(t *testing.T) {
	ctx := context.Background()
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			for _, b := range fixture(t) {
				if _, err := s.Ingest(ctx, b); err != nil {
					t.Fatal(err)
				}
			}
			a, b := node(lineageA, "10.0.0.1"), node(lineageB, "172.16.0.9")
			e := entityOfNode(t, s, a)
			const n = 6
			var wg sync.WaitGroup
			errs := make([]error, n)
			for i := range n {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, errs[i] = s.Decide(ctx, Decision{Action: DecisionSeparate, NodeA: a, NodeB: b, Note: fmt.Sprint("reviewer ", i),
						Expect: []EntityVersion{{e.ID, e.Revision}}})
				}()
			}
			// Ingest concurrently too: it must serialize with decisions.
			if _, err := s.Ingest(ctx, Batch{Lineage: lineageC, Observations: []ObservationRecord{sealed(t, lineageC, "192.168.1.6", t0, sshKey(key(9), "z.example"))}}); err != nil {
				t.Fatal(err)
			}
			wg.Wait()
			ok, stale := 0, 0
			for _, err := range errs {
				switch {
				case err == nil:
					ok++
				case errors.Is(err, ErrStaleRevision):
					stale++
				default:
					t.Fatalf("unexpected error: %v", err)
				}
			}
			// Exactly one reviewer applies its split; the others saw a
			// revision that no longer exists.
			if ok != 1 || stale != n-1 {
				t.Fatalf("ok=%d stale=%d", ok, stale)
			}
			decisions, err := s.Decisions(ctx)
			if err != nil || len(decisions) != 1 {
				t.Fatalf("decisions after the race: %+v %v", decisions, err)
			}
		})
	}
}

func TestArtifactsLifecycle(t *testing.T) {
	ctx := context.Background()
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			data := bytes.Repeat([]byte("pcapng"), 1000)
			sum := sha256.Sum256(data)
			id := "sha256:" + hex.EncodeToString(sum[:])

			// Referenced before upload: unavailable, not an error elsewhere.
			if _, err := s.Ingest(ctx, Batch{Lineage: lineageB, Artifacts: []ArtifactRef{{ID: id, Kind: "pcapng", ScanID: "s1", AgentID: "agent-1", RetainUntil: t0}}}); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.OpenArtifact(ctx, id, Grant{Restricted: true}); !errors.Is(err, ErrArtifactUnavailable) {
				t.Fatalf("pending artifact: %v", err)
			}
			if _, err := s.PutArtifact(ctx, ArtifactRef{ID: id, Kind: "pcapng"}, bytes.NewReader(append(data, 'x'))); err == nil {
				t.Fatal("bytes not matching the artifact ID were stored")
			}
			s.MaxArtifact = 10
			if _, err := s.PutArtifact(ctx, ArtifactRef{Kind: "pcapng"}, bytes.NewReader(data)); err == nil {
				t.Fatal("an oversized artifact was stored")
			}
			s.MaxArtifact = DefaultMaxArtifact
			a, err := s.PutArtifact(ctx, ArtifactRef{ID: id, Kind: "pcapng", RetainUntil: t0}, bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if a.State != ArtifactAvailable || a.Access != AccessRestricted || a.AgentID != "agent-1" || a.Size != int64(len(data)) {
				t.Fatalf("stored artifact: %+v", a)
			}
			if _, _, err := s.OpenArtifact(ctx, id, Grant{}); !errors.Is(err, ErrAccessDenied) {
				t.Fatalf("restricted read without grant: %v", err)
			}
			rc, _, err := s.OpenArtifact(ctx, id, Grant{Restricted: true})
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(rc)
			rc.Close()
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("read back: %v", err)
			}
			// Tampered object: the reader fails at EOF.
			path := filepath.Join(s.objects.(*DirObjects).Dir, filepath.FromSlash(a.ObjectKey))
			tampered := append([]byte(nil), data...)
			tampered[0] ^= 1
			if err := os.WriteFile(path, tampered, 0o600); err != nil {
				t.Fatal(err)
			}
			rc, _, err = s.OpenArtifact(ctx, id, Grant{Restricted: true})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadAll(rc); err == nil {
				t.Fatal("a tampered object read without error")
			}
			rc.Close()
			// Vanished object: marked missing; re-upload restores it.
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if _, a, err := s.OpenArtifact(ctx, id, Grant{Restricted: true}); !errors.Is(err, ErrArtifactUnavailable) || a.State != ArtifactMissing {
				t.Fatalf("missing object: %v %+v", err, a)
			}
			if _, err := s.PutArtifact(ctx, ArtifactRef{Kind: "pcapng"}, bytes.NewReader(data)); err != nil {
				t.Fatal(err)
			}
			// Retention: expired bytes are deleted, metadata stays.
			n, err := s.PruneArtifacts(ctx, t0.Add(time.Hour))
			if err != nil || n != 1 {
				t.Fatalf("prune: %d %v", n, err)
			}
			if _, a, err := s.OpenArtifact(ctx, id, Grant{Restricted: true}); !errors.Is(err, ErrArtifactUnavailable) || a.State != ArtifactExpired {
				t.Fatalf("expired: %v %+v", err, a)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("expired object still on disk")
			}
			pub, err := s.PutArtifact(ctx, ArtifactRef{Kind: "horizon-report", Access: AccessInternal}, strings.NewReader(`{"run":1}`))
			if err != nil {
				t.Fatal(err)
			}
			if rc, _, err := s.OpenArtifact(ctx, pub.ID, Grant{}); err != nil {
				t.Fatalf("internal artifact: %v", err)
			} else {
				rc.Close()
			}
		})
	}
}

func TestExportRestoreKeepsIDsAcrossDialects(t *testing.T) {
	ctx := context.Background()
	for name, s := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			for _, b := range fixture(t) {
				if _, err := s.Ingest(ctx, b); err != nil {
					t.Fatal(err)
				}
			}
			a, b := node(lineageA, "10.0.0.1"), node(lineageB, "172.16.0.9")
			sep, err := s.Decide(ctx, Decision{Action: DecisionSeparate, NodeA: a, NodeB: b, Note: "split"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.PutArtifact(ctx, ArtifactRef{Kind: "note", Access: AccessInternal}, strings.NewReader("x")); err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := s.Export(ctx, &buf); err != nil {
				t.Fatal(err)
			}
			wantEntities, _ := s.Entities(ctx)
			wantHistory, _ := s.History(ctx, "")
			for target, dst := range testStores(t) {
				if err := dst.Restore(ctx, bytes.NewReader(buf.Bytes())); err != nil {
					t.Fatalf("restore %s into %s: %v", name, target, err)
				}
				gotEntities, _ := dst.Entities(ctx)
				if fmt.Sprint(entitySummary(gotEntities)) != fmt.Sprint(entitySummary(wantEntities)) {
					t.Fatalf("%s -> %s entities:\n%v\n%v", name, target, entitySummary(wantEntities), entitySummary(gotEntities))
				}
				gotHistory, _ := dst.History(ctx, "")
				if len(gotHistory) != len(wantHistory) {
					t.Fatalf("%s -> %s restore changed the audit: %d -> %d events", name, target, len(wantHistory), len(gotHistory))
				}
				if _, err := dst.Revert(ctx, sep.ID, "undo after restore", "", nil); err != nil {
					t.Fatalf("decision IDs did not survive restore: %v", err)
				}
				if err := dst.Restore(ctx, bytes.NewReader(buf.Bytes())); !errors.Is(err, ErrNotEmpty) {
					t.Fatalf("restore into a used store: %v", err)
				}
			}
			truncated := buf.Bytes()[:bytes.LastIndexByte(buf.Bytes()[:buf.Len()-1], '\n')+1]
			if err := testStores(t)["sqlite"].Restore(ctx, bytes.NewReader(truncated)); err == nil {
				t.Fatal("a truncated export restored")
			}
		})
	}
}

func entitySummary(entities []Entity) []string {
	var out []string
	for _, e := range entities {
		var nodes []string
		for _, n := range e.Nodes {
			nodes = append(nodes, n.Key)
		}
		out = append(out, fmt.Sprintf("%s@%d:%s:%s", e.ID, e.Revision, e.Link, strings.Join(nodes, "+")))
	}
	return out
}

func FuzzRestore(f *testing.F) {
	ctx := context.Background()
	dir := f.TempDir()
	src, err := Open(ctx, filepath.Join(dir, "src.db"), nil)
	if err != nil {
		f.Fatal(err)
	}
	defer src.Close()
	var buf bytes.Buffer
	if err := src.Export(ctx, &buf); err != nil {
		f.Fatal(err)
	}
	f.Add(buf.Bytes())
	f.Add([]byte(`{"schema":"nyxr-central-export/v1","schema_version":1,"namespace":"x","next_entity":1,"next_decision":1,"next_event":1}` + "\n" + `{"t":"nodes","r":[1,2,3]}`))
	n := 0
	var dst *DB
	reopen := func() {
		if dst != nil {
			dst.Close()
		}
		n++
		if dst, err = Open(ctx, filepath.Join(dir, fmt.Sprintf("dst-%d.db", n)), nil); err != nil {
			f.Fatal(err)
		}
	}
	reopen()
	defer func() { dst.Close() }()
	f.Fuzz(func(t *testing.T, data []byte) {
		// A failed restore rolls back, so the store stays empty and reusable.
		if err := dst.Restore(ctx, bytes.NewReader(data)); err == nil {
			if _, err := dst.Entities(ctx); err != nil {
				t.Fatal(err)
			}
			reopen()
		}
	})
}
