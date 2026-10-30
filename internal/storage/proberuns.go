package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// maxProbeRuns bounds the replays listed for one source exchange set.
const maxProbeRuns = 200

// AddProbeRun records a replay without touching the source observation. A
// live run also becomes its own one-observation scan (profile probe-replay)
// so history shows the traffic it sent; its result is a probe-replay record,
// not a service claim, and does not change asset service identity. The run's
// ScanID and Result are updated to the stored, sealed values.
func (s *Store) AddProbeRun(ctx context.Context, run *observe.ProbeRun, sourceScanID string, definition []byte) error {
	if run.Schema != observe.ProbeRunSchema || run.ID == "" || run.Source.Validate() != nil {
		return errors.New("probe run requires a schema, ID and valid source reference")
	}
	var scanID sql.NullString
	if run.Mode == observe.ProbeRunLive {
		scan := observe.Scan{ID: run.ID, Profile: "probe-replay", Started: run.CreatedAt, Status: "running", Targets: 1}
		if err := s.BeginScan(ctx, scan); err != nil {
			return err
		}
		result := run.Result
		result.Stamp(run.ID)
		addErr := s.AddObservations(ctx, []observe.Observation{result})
		scan.Finished, scan.Status, scan.Observations = time.Now().UTC(), "completed", 1
		if addErr != nil {
			scan.Status, scan.Error, scan.Observations = "failed", addErr.Error(), 0
		} else if run.Status == observe.ProbeRunFailed {
			scan.Error = run.Error
		}
		if err := s.FinishScan(ctx, scan); err != nil {
			return err
		}
		if addErr != nil {
			return addErr
		}
		stored, err := s.Observations(ctx, Filter{ScanID: run.ID, Limit: 1})
		if err != nil {
			return err
		}
		if len(stored) == 1 {
			run.Result = stored[0]
		}
		run.ScanID = run.ID
		scanID = sql.NullString{String: run.ID, Valid: true}
	}
	record, err := json.Marshal(run)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO probe_runs(id, mode, created_at, source_artifact_id, source_pointer, source_scan_id,
		definition_sha256, definition, status, scan_id, record) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.ID, run.Mode, ts(run.CreatedAt), run.Source.ArtifactID, run.Source.Pointer, sourceScanID,
		run.DefinitionSHA256, definition, run.Status, scanID, record)
	return err
}

// ProbeRuns lists replays of exchanges from one source artifact, oldest first.
func (s *Store) ProbeRuns(ctx context.Context, sourceArtifactID string) ([]observe.ProbeRun, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT record FROM probe_runs WHERE source_artifact_id = ? ORDER BY created_at, id LIMIT ?`,
		sourceArtifactID, maxProbeRuns)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []observe.ProbeRun{}
	for rows.Next() {
		var record []byte
		if err := rows.Scan(&record); err != nil {
			return nil, err
		}
		var run observe.ProbeRun
		if err := json.Unmarshal(record, &run); err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}
