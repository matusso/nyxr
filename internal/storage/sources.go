package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/tlsrecord"
)

func setStoredObservationID(ctx context.Context, tx *sql.Tx, id int64, o *observe.Observation) error {
	var namespace string
	if err := tx.QueryRowContext(ctx, `SELECT value FROM identity_namespace WHERE id = 1`).Scan(&namespace); err != nil {
		return err
	}
	o.ID = fmt.Sprintf("store:%s/%d", namespace, id)
	return nil
}

// Backfill adds a mapping without rewriting observations, asset IDs or evidence.
// Historical parser/completeness are unknown; missing raw bytes stay missing.
// Keyset batches bound memory even for a large inventory upgrade.
func backfillSources(ctx context.Context, tx *sql.Tx) error {
	var after int64
	for {
		rows, err := tx.QueryContext(ctx, `SELECT id, scan_id, record FROM observations WHERE id > ? ORDER BY id LIMIT 256`, after)
		if err != nil {
			return err
		}
		type row struct {
			id     int64
			scanID string
			body   string
		}
		var batch []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.scanID, &r.body); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		for _, r := range batch {
			var o observe.Observation
			if err := json.Unmarshal([]byte(r.body), &o); err != nil {
				return err
			}
			o.Stamp(r.scanID)
			if err := setStoredObservationID(ctx, tx, r.id, &o); err != nil {
				return err
			}
			evidence, err := tx.QueryContext(ctx, `SELECT probe, layer, started_at, duration_ns, request, response, truncated, matched, error FROM evidence WHERE observation_id = ? ORDER BY seq`, r.id)
			if err != nil {
				return err
			}
			o.Evidence = nil
			for evidence.Next() {
				var ev observe.Evidence
				var started string
				var duration int64
				if err := evidence.Scan(&ev.Probe, &ev.Layer, &started, &duration, &ev.Request, &ev.Response, &ev.Truncated, &ev.Matched, &ev.Error); err != nil {
					evidence.Close()
					return err
				}
				ev.Started, ev.Duration = parseTS(started), time.Duration(duration)
				ev.ParserVersion = "unknown"
				ev.Decoded = tlsrecord.Decode(ev.Response)
				o.Evidence = append(o.Evidence, ev)
			}
			evidence.Close()
			if err := evidence.Err(); err != nil {
				return err
			}
			source, err := o.Seal()
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO observation_sources(observation_id, artifact_id, source) VALUES (?, ?, ?)`, r.id, o.Source.ArtifactID, source); err != nil {
				return err
			}
			after = r.id
		}
	}
}

// SourceResult keeps provenance even after retention removes its container.
// Artifact contains exact source bytes, not the referenced value re-encoded.
type SourceResult struct {
	Reference observe.SourceRef `json:"reference"`
	Status    string            `json:"status"`
	Reason    string            `json:"reason,omitempty"`
	Artifact  []byte            `json:"artifact,omitempty"` // base64 preserves exact bytes
}

// ResolveSource only reads this store. It never opens caller-supplied filenames
// or retrieves external artifacts. HORIZON refs resolve against their retained
// envelope through the HORIZON adapter, not through a duplicate scan store.
func (s *Store) ResolveSource(ctx context.Context, ref observe.SourceRef) (SourceResult, error) {
	r := SourceResult{Reference: ref, Status: "unavailable"}
	if err := ref.Validate(); err != nil {
		return r, err
	}
	if ref.Owner != "next-gen" || ref.SourceSchema != observe.SchemaVersion {
		r.Reason = "source is owned by an external artifact provider"
		return r, nil
	}
	var source []byte
	err := s.db.QueryRowContext(ctx, `SELECT source FROM observation_sources WHERE artifact_id = ? LIMIT 1`, ref.ArtifactID).Scan(&source)
	if errors.Is(err, sql.ErrNoRows) {
		r.Reason = "source artifact is pruned or not retained in this store"
		return r, nil
	}
	if err != nil {
		return r, err
	}
	var o observe.Observation
	if err := json.Unmarshal(source, &o); err != nil {
		return r, err
	}
	if ref.RunID != "" && ref.RunID != o.ScanID {
		r.Reason = "source run provenance mismatch"
		return r, nil
	}
	if _, err := observe.ResolveSource(source, ref); err != nil {
		r.Reason = err.Error()
		return r, nil
	}
	r.Status, r.Artifact = "available", source
	return r, nil
}
