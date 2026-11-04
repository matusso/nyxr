package central

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// ExportSchema versions the export format.
const ExportSchema = "nyxr-central-export/v1"

// exportTables lists every table in restore order. Column types: s text,
// i integer, b bytes. Object bytes are not exported; artifact rows restore
// as they were, and a missing object is detected on first read.
var exportTables = []struct {
	name, columns, types, order string
}{
	{"lineages", "namespace, kind, label, first_ingested, last_ingested, cursor, member_revision", "sssssii", "namespace"},
	{"scans", "lineage, scan_id, agent_id, profile, status, started_at, finished_at, record", "ssssssss", "lineage, scan_id"},
	{"observations", "artifact_id, lineage, observation_id, scan_id, agent_id, lease_id, job_id, attempt, address, kind, reported_at, observed_at, clock_offset_ns, time_quality, ingested_at, source",
		"sssssssissssissb", "artifact_id"},
	{"ingest_conflicts", "rejected_artifact_id, lineage, observation_id, stored_artifact_id, detected_at", "sssss", "rejected_artifact_id"},
	{"addresses", "lineage, address, node, first_seen, last_seen", "sssss", "lineage, address"},
	{"members", "lineage, address, node", "sss", "lineage, address"},
	{"signals", "lineage, address, kind, value, scoped, first_seen, last_seen, observations", "ssssissi", "lineage, address, kind, value"},
	{"clues", "lineage, address, kind, value, first_seen, last_seen, observations", "ssssssi", "lineage, address, kind, value"},
	{"entities", "id, revision, created_at, updated_at", "iiss", "id"},
	{"nodes", "node, lineage, entity", "ssi", "node"},
	{"decisions", "id, action, node_a, node_b, target, note, actor, decided_at, reverted_by", "isssisssi", "id"},
	{"events", "id, node, from_entity, to_entity, cause, decision, revision, at", "isiisiis", "id"},
	{"conflicts", "reason, kind, node_a, node_b, value_a, value_b", "ssssss", "node_a, node_b, reason, kind, value_a, value_b"},
	{"artifacts", "id, kind, media_type, size, state, object_key, access, retain_until, lineage, scan_id, agent_id, registered_at, stored_at", "sssisssssssss", "id"},
}

type exportHeader struct {
	Schema        string    `json:"schema"`
	SchemaVersion int       `json:"schema_version"`
	Namespace     string    `json:"namespace"`
	Revision      int64     `json:"revision"`
	NextEntity    int64     `json:"next_entity"`
	NextDecision  int64     `json:"next_decision"`
	NextEvent     int64     `json:"next_event"`
	ExportedAt    time.Time `json:"exported_at"`
}

type exportRow struct {
	Table string            `json:"t,omitempty"`
	Row   []json.RawMessage `json:"r,omitempty"`
	End   bool              `json:"end,omitempty"`
	Rows  int64             `json:"rows,omitempty"`
}

// Export writes a consistent snapshot as JSON lines: a header, one line per
// row, and a trailer with the row count so a truncated file is rejected.
func (s *DB) Export(ctx context.Context, w io.Writer) error {
	return s.read(ctx, func(t tx) error {
		bw := bufio.NewWriter(w)
		enc := json.NewEncoder(bw)
		h := exportHeader{Schema: ExportSchema, SchemaVersion: len(schema), ExportedAt: s.now().UTC()}
		if err := t.row(ctx, `SELECT namespace, revision, next_entity, next_decision, next_event FROM central_meta WHERE id = 1`).
			Scan(&h.Namespace, &h.Revision, &h.NextEntity, &h.NextDecision, &h.NextEvent); err != nil {
			return err
		}
		if err := enc.Encode(h); err != nil {
			return err
		}
		var total int64
		for _, tbl := range exportTables {
			rows, err := t.query(ctx, `SELECT `+tbl.columns+` FROM `+tbl.name+` ORDER BY `+tbl.order)
			if err != nil {
				return err
			}
			for rows.Next() {
				dest := make([]any, len(tbl.types))
				for i, c := range tbl.types {
					switch c {
					case 's':
						dest[i] = new(string)
					case 'i':
						dest[i] = new(int64)
					case 'b':
						dest[i] = new([]byte)
					}
				}
				if err := rows.Scan(dest...); err != nil {
					rows.Close()
					return err
				}
				out := exportRow{Table: tbl.name, Row: make([]json.RawMessage, len(dest))}
				for i, d := range dest {
					b, err := json.Marshal(d)
					if err != nil {
						rows.Close()
						return err
					}
					out.Row[i] = b
				}
				if err := enc.Encode(out); err != nil {
					rows.Close()
					return err
				}
				total++
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
		}
		if err := enc.Encode(exportRow{End: true, Rows: total}); err != nil {
			return err
		}
		return bw.Flush()
	})
}

// Restore loads an export into an empty store in one transaction, keeping
// entity, decision and event IDs and the central namespace, so entity URNs
// survive a move between SQLite and PostgreSQL. It then reconciles; a
// consistent export moves nothing.
func (s *DB) Restore(ctx context.Context, r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4*MaxSourceBytes)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return err
		}
		return errors.New("empty export")
	}
	var h exportHeader
	if err := json.Unmarshal(sc.Bytes(), &h); err != nil {
		return fmt.Errorf("export header: %w", err)
	}
	if h.Schema != ExportSchema {
		return fmt.Errorf("unsupported export schema %q", h.Schema)
	}
	if h.SchemaVersion != len(schema) {
		return fmt.Errorf("export is central schema %d; this nyxr restores schema %d", h.SchemaVersion, len(schema))
	}
	if !validNamespace(h.Namespace) || h.NextEntity < 1 || h.NextDecision < 1 || h.NextEvent < 1 {
		return errors.New("export header has invalid counters or namespace")
	}
	tables := map[string]int{}
	for i, tbl := range exportTables {
		tables[tbl.name] = i
	}
	now := s.now().UTC()
	return s.write(ctx, func(t tx, _ int64) error {
		var used int
		if err := t.row(ctx, `SELECT (SELECT COUNT(*) FROM lineages) + (SELECT COUNT(*) FROM decisions)
			+ (SELECT COUNT(*) FROM events) + (SELECT COUNT(*) FROM artifacts)`).Scan(&used); err != nil {
			return err
		}
		if used > 0 {
			return ErrNotEmpty
		}
		if _, err := t.exec(ctx, `UPDATE central_meta SET namespace = ?, revision = ?, next_entity = ?, next_decision = ?, next_event = ? WHERE id = 1`,
			h.Namespace, h.Revision, h.NextEntity, h.NextDecision, h.NextEvent); err != nil {
			return err
		}
		var total int64
		last := -1
		ended := false
		for sc.Scan() {
			if ended {
				return errors.New("export has data after its trailer")
			}
			var row exportRow
			if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
				return fmt.Errorf("export line %d: %w", total+2, err)
			}
			if row.End {
				if row.Rows != total {
					return fmt.Errorf("export trailer counts %d rows, read %d", row.Rows, total)
				}
				ended = true
				continue
			}
			idx, ok := tables[row.Table]
			if !ok {
				return fmt.Errorf("export line %d: unknown table %q", total+2, row.Table)
			}
			if idx < last {
				return fmt.Errorf("export line %d: table %s out of order", total+2, row.Table)
			}
			last = idx
			tbl := exportTables[idx]
			if len(row.Row) != len(tbl.types) {
				return fmt.Errorf("export line %d: %s row has %d values, want %d", total+2, tbl.name, len(row.Row), len(tbl.types))
			}
			args := make([]any, len(row.Row))
			for i, c := range tbl.types {
				var err error
				switch c {
				case 's':
					var v string
					err = json.Unmarshal(row.Row[i], &v)
					args[i] = v
				case 'i':
					var v int64
					err = json.Unmarshal(row.Row[i], &v)
					args[i] = v
				case 'b':
					var v []byte
					err = json.Unmarshal(row.Row[i], &v)
					args[i] = v
				}
				if err != nil {
					return fmt.Errorf("export line %d: %s column %d: %w", total+2, tbl.name, i, err)
				}
			}
			marks := strings.TrimSuffix(strings.Repeat("?, ", len(args)), ", ")
			if _, err := t.exec(ctx, `INSERT INTO `+tbl.name+`(`+tbl.columns+`) VALUES (`+marks+`)`, args...); err != nil {
				return fmt.Errorf("export line %d: %s: %w", total+2, tbl.name, err)
			}
			total++
		}
		if err := sc.Err(); err != nil {
			return err
		}
		if !ended {
			return errors.New("export is truncated: no trailer")
		}
		var revision int64
		if err := t.row(ctx, `UPDATE central_meta SET revision = revision + 1 WHERE id = 1 RETURNING revision`).Scan(&revision); err != nil {
			return err
		}
		_, err := reconcile(ctx, t, revision, "restore", 0, now)
		return err
	})
}
