package central

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/storage"
)

func validNamespace(ns string) bool {
	if len(ns) == 0 || len(ns) > 64 {
		return false
	}
	for _, c := range ns {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// timeQuality classifies a timestamp and returns it in the controller's
// timebase. A fleet agent's offset is agent minus controller clock.
func timeQuality(rec ObservationRecord, reported time.Time) (time.Time, string) {
	if !rec.Fleet {
		return reported, TimeLocalClock
	}
	corrected := reported.Add(-rec.ClockOffset)
	if rec.ClockOffset > MaxClockSkew || rec.ClockOffset < -MaxClockSkew {
		return corrected, TimeAgentSkewed
	}
	return corrected, TimeAgentCorrected
}

// Ingest applies a batch in one transaction and then reconciles. Every part
// is idempotent and order-independent:
//   - an observation is keyed by the hash of its sealed source, so a replay
//     is a duplicate; a different source under a stored observation ID is a
//     conflict, recorded and never overwriting;
//   - signal and clue rows keep first and last seen, which commute;
//   - a scan summary only advances from running to finished;
//   - a membership snapshot applies only if newer than the applied one;
//   - the lineage cursor only moves forward.
func (s *DB) Ingest(ctx context.Context, b Batch) (IngestResult, error) {
	var out IngestResult
	if !validNamespace(b.Lineage) {
		return out, errors.New("batch lineage must be a nyxr identity namespace")
	}
	if b.Kind == "" {
		b.Kind = LineageStandalone
	}
	if b.Kind != LineageStandalone && b.Kind != LineageController {
		return out, fmt.Errorf("lineage kind must be %s or %s", LineageStandalone, LineageController)
	}
	if len(b.Label) > 128 {
		return out, errors.New("lineage label is at most 128 bytes")
	}
	if len(b.Observations)+len(b.Scans)+len(b.Artifacts) > MaxBatchRecords {
		return out, fmt.Errorf("batch holds more than %d records", MaxBatchRecords)
	}
	if b.Members != nil && len(b.Members.Members) > 10_000_000 {
		return out, errors.New("membership snapshot is too large")
	}
	// Parse and verify outside the transaction.
	type parsed struct {
		rec      ObservationRecord
		o        observe.Observation
		observed time.Time
		quality  string
	}
	obs := make([]parsed, 0, len(b.Observations))
	for i, rec := range b.Observations {
		if len(rec.Source) == 0 || len(rec.Source) > MaxSourceBytes {
			return out, fmt.Errorf("observation %d: source must be 1 to %d bytes", i, MaxSourceBytes)
		}
		if _, err := parseArtifactID(rec.ArtifactID); err != nil {
			return out, fmt.Errorf("observation %d: %w", i, err)
		}
		o, err := observe.ReadSource(rec.Source, rec.ArtifactID)
		if err != nil {
			return out, fmt.Errorf("observation %d: %w", i, err)
		}
		if !o.Target.IsValid() {
			return out, fmt.Errorf("observation %d: no target address", i)
		}
		if len(rec.AgentID) > 128 || len(rec.LeaseID) > 128 || len(rec.JobID) > 128 || len(o.ID) > 256 {
			return out, fmt.Errorf("observation %d: provenance field too long", i)
		}
		observed, quality := timeQuality(rec, o.Timestamp)
		obs = append(obs, parsed{rec, o, observed, quality})
	}
	for i := range b.Artifacts {
		b.Artifacts[i].Lineage = b.Lineage
	}
	now := s.now().UTC()
	err := s.write(ctx, func(t tx, revision int64) error {
		out.Revision = revision
		if _, err := t.exec(ctx, `INSERT INTO lineages(namespace, kind, label, first_ingested, last_ingested) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (namespace) DO UPDATE SET last_ingested = excluded.last_ingested,
				kind = CASE WHEN excluded.kind = 'controller' THEN excluded.kind ELSE lineages.kind END,
				label = CASE WHEN excluded.label <> '' THEN excluded.label ELSE lineages.label END`,
			b.Lineage, b.Kind, b.Label, ts(now), ts(now)); err != nil {
			return err
		}
		for _, sr := range b.Scans {
			n, err := upsertScan(ctx, t, b.Lineage, sr)
			if err != nil {
				return err
			}
			out.Scans += n
		}
		dirty := false
		for _, p := range obs {
			inserted, conflict, err := insertObservation(ctx, t, b.Lineage, p.rec, p.o, p.observed, p.quality, now)
			if err != nil {
				return err
			}
			switch {
			case conflict:
				out.Conflicts++
				continue
			case !inserted:
				out.Duplicates++
				continue
			}
			out.Observations++
			addr := p.o.Target.String()
			if _, err := t.exec(ctx, `INSERT INTO addresses(lineage, address, node, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)
				ON CONFLICT (lineage, address) DO UPDATE SET
					first_seen = CASE WHEN excluded.first_seen < addresses.first_seen THEN excluded.first_seen ELSE addresses.first_seen END,
					last_seen = CASE WHEN excluded.last_seen > addresses.last_seen THEN excluded.last_seen ELSE addresses.last_seen END`,
				b.Lineage, addr, provisionalNode(b.Lineage, p.o.Target), ts(p.observed), ts(p.observed)); err != nil {
				return err
			}
			for _, v := range storage.StrongIdentityValues(p.o) {
				if err := upsertValue(ctx, t, "signals", b.Lineage, addr, v, p.observed); err != nil {
					return err
				}
				dirty = true
			}
			for _, v := range storage.IdentityClueValues(p.o) {
				if err := upsertValue(ctx, t, "clues", b.Lineage, addr, v, p.observed); err != nil {
					return err
				}
			}
			dirty = true // a new address is a new node
		}
		for _, ref := range b.Artifacts {
			added, err := registerArtifact(ctx, t, ref, now)
			if err != nil {
				return err
			}
			if added {
				out.Artifacts++
			}
		}
		if b.Members != nil {
			applied, err := applyMembers(ctx, t, b.Lineage, *b.Members)
			if err != nil {
				return err
			}
			out.MembersApplied, dirty = applied, dirty || applied
		}
		if b.Cursor > 0 {
			if _, err := t.exec(ctx, `UPDATE lineages SET cursor = ? WHERE namespace = ? AND cursor < ?`, b.Cursor, b.Lineage, b.Cursor); err != nil {
				return err
			}
		}
		if !dirty {
			return nil
		}
		moved, err := reconcile(ctx, t, revision, "ingest:"+b.Lineage, 0, now)
		out.Moved = moved
		return err
	})
	return out, err
}

func provisionalNode(lineage string, addr netip.Addr) string {
	return "urn:nyxr:" + lineage + ":address:" + addr.String()
}

func insertObservation(ctx context.Context, t tx, lineage string, rec ObservationRecord, o observe.Observation, observed time.Time, quality string, now time.Time) (inserted, conflict bool, err error) {
	res, err := t.exec(ctx, `INSERT INTO observations(artifact_id, lineage, observation_id, scan_id, agent_id, lease_id, job_id, attempt,
			address, kind, reported_at, observed_at, clock_offset_ns, time_quality, ingested_at, source)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
		rec.ArtifactID, lineage, o.ID, o.ScanID, rec.AgentID, rec.LeaseID, rec.JobID, rec.Attempt,
		o.Target.String(), o.Kind, ts(o.Timestamp), ts(observed), int64(rec.ClockOffset), quality, ts(now), rec.Source)
	if err != nil {
		return false, false, err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return true, false, nil
	}
	var stored string
	err = t.row(ctx, `SELECT artifact_id FROM observations WHERE lineage = ? AND observation_id = ?`, lineage, o.ID).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && stored == rec.ArtifactID) {
		// The same bytes under this ID, or already ingested through another
		// lineage (a database pushed twice under different names): the
		// sealed bytes are stored once either way.
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	_, err = t.exec(ctx, `INSERT INTO ingest_conflicts(rejected_artifact_id, lineage, observation_id, stored_artifact_id, detected_at)
		VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`, rec.ArtifactID, lineage, o.ID, stored, ts(now))
	return false, true, err
}

func upsertValue(ctx context.Context, t tx, table, lineage, addr string, v storage.IdentityValue, seen time.Time) error {
	if table == "signals" {
		scoped := 0
		if v.Scoped {
			scoped = 1
		}
		_, err := t.exec(ctx, `INSERT INTO signals(lineage, address, kind, value, scoped, first_seen, last_seen, observations) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
			ON CONFLICT (lineage, address, kind, value) DO UPDATE SET observations = signals.observations + 1,
				first_seen = CASE WHEN excluded.first_seen < signals.first_seen THEN excluded.first_seen ELSE signals.first_seen END,
				last_seen = CASE WHEN excluded.last_seen > signals.last_seen THEN excluded.last_seen ELSE signals.last_seen END`,
			lineage, addr, v.Kind, v.Value, scoped, ts(seen), ts(seen))
		return err
	}
	_, err := t.exec(ctx, `INSERT INTO clues(lineage, address, kind, value, first_seen, last_seen, observations) VALUES (?, ?, ?, ?, ?, ?, 1)
		ON CONFLICT (lineage, address, kind, value) DO UPDATE SET observations = clues.observations + 1,
			first_seen = CASE WHEN excluded.first_seen < clues.first_seen THEN excluded.first_seen ELSE clues.first_seen END,
			last_seen = CASE WHEN excluded.last_seen > clues.last_seen THEN excluded.last_seen ELSE clues.last_seen END`,
		lineage, addr, v.Kind, v.Value, ts(seen), ts(seen))
	return err
}

func upsertScan(ctx context.Context, t tx, lineage string, sr ScanRecord) (int, error) {
	sc := sr.Scan
	if sc.ID == "" || len(sc.ID) > 128 || len(sr.AgentID) > 128 {
		return 0, errors.New("scan record needs an ID of at most 128 bytes")
	}
	record, err := json.Marshal(sc)
	if err != nil {
		return 0, err
	}
	res, err := t.exec(ctx, `INSERT INTO scans(lineage, scan_id, agent_id, profile, status, started_at, finished_at, record) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (lineage, scan_id) DO UPDATE SET status = excluded.status, finished_at = excluded.finished_at, record = excluded.record,
			agent_id = CASE WHEN excluded.agent_id <> '' THEN excluded.agent_id ELSE scans.agent_id END
		WHERE scans.status = 'running' AND excluded.status <> 'running'`,
		lineage, sc.ID, sr.AgentID, sc.Profile, sc.Status, ts(sc.Started), ts(sc.Finished), string(record))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func applyMembers(ctx context.Context, t tx, lineage string, snap MemberSnapshot) (bool, error) {
	res, err := t.exec(ctx, `UPDATE lineages SET member_revision = ? WHERE namespace = ? AND member_revision < ?`, snap.Revision, lineage, snap.Revision)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil // an equal or newer snapshot is already applied
	}
	if _, err := t.exec(ctx, `DELETE FROM members WHERE lineage = ?`, lineage); err != nil {
		return false, err
	}
	prefix := "urn:nyxr:" + lineage + ":"
	for addr, node := range snap.Members {
		if !addr.IsValid() || len(node) <= len(prefix) || node[:len(prefix)] != prefix || len(node) > 256 {
			return false, fmt.Errorf("member %s: identity %q is not in lineage %s", addr, node, lineage)
		}
		if _, err := t.exec(ctx, `INSERT INTO members(lineage, address, node) VALUES (?, ?, ?)`, lineage, addr.String(), node); err != nil {
			return false, err
		}
	}
	return true, nil
}

// Lineages lists the known source databases.
func (s *DB) Lineages(ctx context.Context) ([]Lineage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT l.namespace, l.kind, l.label, l.first_ingested, l.last_ingested, l.cursor, l.member_revision,
		(SELECT COUNT(*) FROM observations o WHERE o.lineage = l.namespace) FROM lineages l ORDER BY l.first_ingested, l.namespace`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Lineage{}
	for rows.Next() {
		var l Lineage
		var first, last string
		if err := rows.Scan(&l.Namespace, &l.Kind, &l.Label, &first, &last, &l.Cursor, &l.MemberRevision, &l.Observations); err != nil {
			return nil, err
		}
		l.FirstIngested, l.LastIngested = parseTS(first), parseTS(last)
		out = append(out, l)
	}
	return out, rows.Err()
}

// Observations returns the sealed sources ingested from one lineage for one
// address, in corrected time order, for evidence drill-down.
func (s *DB) Observations(ctx context.Context, lineage string, addr netip.Addr, limit int) ([]StoredObservation, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT artifact_id, observation_id, scan_id, agent_id, lease_id, job_id, attempt,
		reported_at, observed_at, clock_offset_ns, time_quality, source FROM observations
		WHERE lineage = ? AND address = ? ORDER BY observed_at, artifact_id LIMIT ?`), lineage, addr.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StoredObservation{}
	for rows.Next() {
		var so StoredObservation
		var reported, observed string
		var offset int64
		if err := rows.Scan(&so.ArtifactID, &so.ObservationID, &so.ScanID, &so.AgentID, &so.LeaseID, &so.JobID, &so.Attempt,
			&reported, &observed, &offset, &so.TimeQuality, &so.Source); err != nil {
			return nil, err
		}
		so.Lineage, so.ReportedAt, so.ObservedAt, so.ClockOffset = lineage, parseTS(reported), parseTS(observed), time.Duration(offset)
		out = append(out, so)
	}
	return out, rows.Err()
}

// StoredObservation is one ingested observation with its provenance.
type StoredObservation struct {
	ArtifactID    string        `json:"artifact_id"`
	Lineage       string        `json:"lineage"`
	ObservationID string        `json:"observation_id"`
	ScanID        string        `json:"scan_id"`
	AgentID       string        `json:"agent_id,omitempty"`
	LeaseID       string        `json:"lease_id,omitempty"`
	JobID         string        `json:"job_id,omitempty"`
	Attempt       int           `json:"attempt,omitempty"`
	ReportedAt    time.Time     `json:"reported_at"`
	ObservedAt    time.Time     `json:"observed_at"`
	ClockOffset   time.Duration `json:"clock_offset_ns"`
	TimeQuality   string        `json:"time_quality"`
	Source        []byte        `json:"-"`
}
