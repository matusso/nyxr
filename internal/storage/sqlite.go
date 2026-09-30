// Package storage keeps scans, observations, evidence and packet references
// in a standalone SQLite database. It uses a cgo-free driver so every release
// target can open the same file. Writes happen on the pipeline's consumer,
// never on a packet receive worker.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// timeFormat is fixed-width so text comparison orders timestamps.
const timeFormat = "2006-01-02T15:04:05.000000000Z"

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeFormat)
}

func parseTS(s string) time.Time {
	t, _ := time.Parse(timeFormat, s)
	return t
}

// migrations are applied in order, each in its own transaction. Never edit a
// released entry; append a new one.
var migrations = []string{
	`CREATE TABLE scans (
		id           TEXT PRIMARY KEY,
		schema       TEXT NOT NULL,
		profile      TEXT NOT NULL,
		started_at   TEXT NOT NULL,
		finished_at  TEXT NOT NULL DEFAULT '',
		status       TEXT NOT NULL,
		error        TEXT NOT NULL DEFAULT '',
		targets      INTEGER NOT NULL DEFAULT 0,
		observations INTEGER NOT NULL DEFAULT 0,
		services     INTEGER NOT NULL DEFAULT 0,
		capture      TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX scans_started ON scans(started_at);
	CREATE TABLE assets (
		id         INTEGER PRIMARY KEY,
		address    TEXT NOT NULL UNIQUE,
		first_seen TEXT NOT NULL,
		last_seen  TEXT NOT NULL
	);
	CREATE TABLE observations (
		id          INTEGER PRIMARY KEY,
		scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
		asset_id    INTEGER NOT NULL REFERENCES assets(id),
		kind        TEXT NOT NULL,
		observed_at TEXT NOT NULL,
		transport   TEXT NOT NULL,
		port        INTEGER NOT NULL,
		state       TEXT NOT NULL,
		confidence  INTEGER NOT NULL,
		reason      TEXT NOT NULL,
		probe       TEXT NOT NULL,
		service     TEXT NOT NULL,
		product     TEXT NOT NULL,
		version     TEXT NOT NULL,
		fingerprint TEXT NOT NULL,
		record      TEXT NOT NULL
	);
	CREATE INDEX observations_scan ON observations(scan_id);
	CREATE INDEX observations_asset_port ON observations(asset_id, transport, port, observed_at);
	CREATE TABLE evidence (
		id             INTEGER PRIMARY KEY,
		observation_id INTEGER NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
		seq            INTEGER NOT NULL,
		probe          TEXT NOT NULL,
		layer          TEXT NOT NULL,
		started_at     TEXT NOT NULL,
		duration_ns    INTEGER NOT NULL,
		request        BLOB,
		response       BLOB,
		truncated      INTEGER NOT NULL,
		matched        TEXT NOT NULL,
		error          TEXT NOT NULL
	);
	CREATE INDEX evidence_observation ON evidence(observation_id, seq);
	CREATE INDEX evidence_unmatched ON evidence(matched) WHERE matched = '';
	CREATE TABLE packet_flows (
		id        INTEGER PRIMARY KEY,
		scan_id   TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
		asset_id  INTEGER NOT NULL REFERENCES assets(id),
		transport TEXT NOT NULL,
		port      INTEGER NOT NULL,
		capture   TEXT NOT NULL,
		truncated INTEGER NOT NULL,
		UNIQUE (scan_id, asset_id, transport, port)
	);
	CREATE TABLE packets (
		flow_id     INTEGER NOT NULL REFERENCES packet_flows(id) ON DELETE CASCADE,
		packet_id   INTEGER NOT NULL,
		captured_at TEXT NOT NULL,
		direction   TEXT NOT NULL,
		length      INTEGER NOT NULL,
		summary     TEXT NOT NULL,
		PRIMARY KEY (flow_id, packet_id)
	);`,
}

// Store is safe for concurrent use.
type Store struct{ db *sql.DB }

// Open creates or upgrades the database at path.
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" || strings.ContainsAny(path, "?#") {
		return nil, errors.New("database path is required and must not contain '?' or '#'")
	}
	q := url.Values{}
	for _, p := range []string{"foreign_keys(1)", "busy_timeout(5000)", "journal_mode(WAL)", "synchronous(NORMAL)"} {
		q.Add("_pragma", p)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// SchemaVersion is the number of applied migrations.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	return v, err
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	current, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if current > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this nyxr (%d)", current, len(migrations))
	}
	for v := current + 1; v <= len(migrations); v++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[v-1]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: %w", v, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, v, ts(time.Now())); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// BeginScan records a running scan.
func (s *Store) BeginScan(ctx context.Context, scan observe.Scan) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO scans(id, schema, profile, started_at, status, targets) VALUES (?, ?, ?, ?, ?, ?)`,
		scan.ID, observe.SchemaVersion, scan.Profile, ts(scan.Started), scan.Status, scan.Targets)
	return err
}

// FinishScan stores the final summary.
func (s *Store) FinishScan(ctx context.Context, scan observe.Scan) error {
	var capture string
	if scan.Capture != nil {
		b, err := json.Marshal(scan.Capture)
		if err != nil {
			return err
		}
		capture = string(b)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE scans SET finished_at = ?, status = ?, error = ?, observations = ?, services = ?, capture = ? WHERE id = ?`,
		ts(scan.Finished), scan.Status, scan.Error, scan.Observations, scan.Services, capture, scan.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("scan %s not found", scan.ID)
	}
	return nil
}

// AddObservations stores a batch in one transaction. Evidence goes to its own
// table so unmatched responses can be queried for signature work.
func (s *Store) AddObservations(ctx context.Context, batch []observe.Observation) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	obsStmt, err := tx.PrepareContext(ctx, `INSERT INTO observations(scan_id, asset_id, kind, observed_at, transport, port, state, confidence, reason, probe, service, product, version, fingerprint, record)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer obsStmt.Close()
	evStmt, err := tx.PrepareContext(ctx, `INSERT INTO evidence(observation_id, seq, probe, layer, started_at, duration_ns, request, response, truncated, matched, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer evStmt.Close()
	for _, o := range batch {
		if o.ScanID == "" {
			return errors.New("observation has no scan ID")
		}
		assetID, err := upsertAsset(ctx, tx, o.Target, o.Timestamp)
		if err != nil {
			return err
		}
		record := o
		record.Evidence = nil
		body, err := json.Marshal(record)
		if err != nil {
			return err
		}
		res, err := obsStmt.ExecContext(ctx, o.ScanID, assetID, o.Kind, ts(o.Timestamp), o.Transport, o.Port, o.State, o.Confidence,
			o.Reason, o.Probe, o.Service, o.Product, o.Version, o.Fingerprint, string(body))
		if err != nil {
			return err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		for i, ev := range o.Evidence {
			if _, err := evStmt.ExecContext(ctx, id, i, ev.Probe, ev.Layer, ts(ev.Started), int64(ev.Duration), ev.Request, ev.Response,
				ev.Truncated, ev.Matched, ev.Error); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func upsertAsset(ctx context.Context, tx *sql.Tx, addr netip.Addr, seen time.Time) (int64, error) {
	var id int64
	err := tx.QueryRowContext(ctx, `INSERT INTO assets(address, first_seen, last_seen) VALUES (?, ?, ?)
		ON CONFLICT(address) DO UPDATE SET
			first_seen = min(first_seen, excluded.first_seen),
			last_seen = max(last_seen, excluded.last_seen)
		RETURNING id`, addr.String(), ts(seen), ts(seen)).Scan(&id)
	return id, err
}

// AddPacketEvidence stores the capture index for a scan.
func (s *Store) AddPacketEvidence(ctx context.Context, batch []observe.PacketEvidence) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, pe := range batch {
		seen := time.Now()
		if len(pe.Packets) > 0 {
			seen = pe.Packets[0].Timestamp
		}
		assetID, err := upsertAsset(ctx, tx, pe.Target, seen)
		if err != nil {
			return err
		}
		var flowID int64
		if err := tx.QueryRowContext(ctx, `INSERT INTO packet_flows(scan_id, asset_id, transport, port, capture, truncated) VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
			pe.ScanID, assetID, pe.Transport, pe.Port, pe.Capture, pe.Truncated).Scan(&flowID); err != nil {
			return err
		}
		for _, p := range pe.Packets {
			if _, err := tx.ExecContext(ctx, `INSERT INTO packets(flow_id, packet_id, captured_at, direction, length, summary) VALUES (?, ?, ?, ?, ?, ?)`,
				flowID, p.ID, ts(p.Timestamp), p.Direction, p.Length, p.Summary); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// Scans lists the newest scans first.
func (s *Store) Scans(ctx context.Context, limit int) ([]observe.Scan, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, schema, profile, started_at, finished_at, status, error, targets, observations, services, capture
		FROM scans ORDER BY started_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []observe.Scan
	for rows.Next() {
		var sc observe.Scan
		var started, finished, capture string
		if err := rows.Scan(&sc.ID, &sc.Schema, &sc.Profile, &started, &finished, &sc.Status, &sc.Error, &sc.Targets, &sc.Observations, &sc.Services, &capture); err != nil {
			return nil, err
		}
		sc.Kind, sc.Started, sc.Finished = observe.KindScan, parseTS(started), parseTS(finished)
		if capture != "" {
			sc.Capture = new(observe.CaptureStats)
			if err := json.Unmarshal([]byte(capture), sc.Capture); err != nil {
				return nil, err
			}
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// Filter selects observations. Zero fields match everything.
type Filter struct {
	ScanID    string
	Address   netip.Addr
	Kind      string
	Transport string
	Port      uint16
	Service   string
	// Unknown selects observations with an unknown fingerprint.
	Unknown bool
	Limit   int
}

// Observations returns matching records, oldest first, with evidence.
func (s *Store) Observations(ctx context.Context, f Filter) ([]observe.Observation, error) {
	var where []string
	var args []any
	add := func(clause string, v any) { where = append(where, clause); args = append(args, v) }
	if f.ScanID != "" {
		add("o.scan_id = ?", f.ScanID)
	}
	if f.Address.IsValid() {
		add("a.address = ?", f.Address.String())
	}
	if f.Kind != "" {
		add("o.kind = ?", f.Kind)
	}
	if f.Transport != "" {
		add("o.transport = ?", f.Transport)
	}
	if f.Port != 0 {
		add("o.port = ?", f.Port)
	}
	if f.Service != "" {
		add("o.service = ?", f.Service)
	}
	if f.Unknown {
		add("o.fingerprint = ?", observe.FingerprintUnknown)
	}
	query := `SELECT o.id, o.record FROM observations o JOIN assets a ON a.id = o.asset_id`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 10000
	}
	query += " ORDER BY o.observed_at, o.id LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	var ids []int64
	var out []observe.Observation
	for rows.Next() {
		var id int64
		var body string
		if err := rows.Scan(&id, &body); err != nil {
			rows.Close()
			return nil, err
		}
		var o observe.Observation
		if err := json.Unmarshal([]byte(body), &o); err != nil {
			rows.Close()
			return nil, fmt.Errorf("observation %d: %w", id, err)
		}
		ids = append(ids, id)
		out = append(out, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, id := range ids {
		ev, err := s.evidence(ctx, id)
		if err != nil {
			return nil, err
		}
		out[i].Evidence = ev
	}
	return out, nil
}

func (s *Store) evidence(ctx context.Context, observationID int64) ([]observe.Evidence, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT probe, layer, started_at, duration_ns, request, response, truncated, matched, error
		FROM evidence WHERE observation_id = ? ORDER BY seq`, observationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []observe.Evidence
	for rows.Next() {
		var ev observe.Evidence
		var started string
		var duration int64
		if err := rows.Scan(&ev.Probe, &ev.Layer, &started, &duration, &ev.Request, &ev.Response, &ev.Truncated, &ev.Matched, &ev.Error); err != nil {
			return nil, err
		}
		ev.Started, ev.Duration = parseTS(started), time.Duration(duration)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// PacketEvidence returns the capture index for one scan, optionally narrowed
// to one address.
func (s *Store) PacketEvidence(ctx context.Context, scanID string, addr netip.Addr) ([]observe.PacketEvidence, error) {
	query := `SELECT f.id, a.address, f.transport, f.port, f.capture, f.truncated FROM packet_flows f JOIN assets a ON a.id = f.asset_id WHERE f.scan_id = ?`
	args := []any{scanID}
	if addr.IsValid() {
		query += " AND a.address = ?"
		args = append(args, addr.String())
	}
	query += " ORDER BY f.id"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	var flows []int64
	var out []observe.PacketEvidence
	for rows.Next() {
		var id int64
		var address string
		pe := observe.PacketEvidence{Schema: observe.SchemaVersion, Kind: observe.KindPacketEvidence, ScanID: scanID}
		if err := rows.Scan(&id, &address, &pe.Transport, &pe.Port, &pe.Capture, &pe.Truncated); err != nil {
			rows.Close()
			return nil, err
		}
		pe.Target, _ = netip.ParseAddr(address)
		flows = append(flows, id)
		out = append(out, pe)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, id := range flows {
		prow, err := s.db.QueryContext(ctx, `SELECT packet_id, captured_at, direction, length, summary FROM packets WHERE flow_id = ? ORDER BY packet_id`, id)
		if err != nil {
			return nil, err
		}
		for prow.Next() {
			var p observe.Packet
			var at string
			if err := prow.Scan(&p.ID, &at, &p.Direction, &p.Length, &p.Summary); err != nil {
				prow.Close()
				return nil, err
			}
			p.Timestamp = parseTS(at)
			out[i].Packets = append(out[i].Packets, p)
		}
		prow.Close()
		if err := prow.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// PortSummary is the latest known state of one port of an asset.
type PortSummary struct {
	Transport  string    `json:"transport"`
	Port       uint16    `json:"port"`
	State      string    `json:"state"`
	Service    string    `json:"service,omitempty"`
	Product    string    `json:"product,omitempty"`
	Version    string    `json:"version,omitempty"`
	ScanID     string    `json:"scan_id"`
	ObservedAt time.Time `json:"observed_at"`
}

// Asset is the durable view of one address across scans.
type Asset struct {
	Address   netip.Addr    `json:"address"`
	FirstSeen time.Time     `json:"first_seen"`
	LastSeen  time.Time     `json:"last_seen"`
	Ports     []PortSummary `json:"ports,omitempty"`
}

// Assets returns every address with the latest discovery state of each port,
// merged with the latest service identity for that port.
func (s *Store) Assets(ctx context.Context) ([]Asset, error) {
	rows, err := s.db.QueryContext(ctx, `
		WITH ranked AS (
			SELECT o.*, ROW_NUMBER() OVER (PARTITION BY o.asset_id, o.transport, o.port, o.kind ORDER BY o.observed_at DESC, o.id DESC) AS rn
			FROM observations o WHERE o.kind IN ('port', 'service')
		)
		SELECT a.address, a.first_seen, a.last_seen, p.transport, p.port, p.state, p.scan_id, p.observed_at,
			COALESCE(s.service, ''), COALESCE(s.product, ''), COALESCE(s.version, '')
		FROM assets a
		LEFT JOIN ranked p ON p.asset_id = a.id AND p.kind = 'port' AND p.rn = 1
		LEFT JOIN ranked s ON s.asset_id = a.id AND s.kind = 'service' AND s.rn = 1 AND s.transport = p.transport AND s.port = p.port
			AND s.observed_at >= p.observed_at
		ORDER BY a.address, p.transport, p.port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		var address, first, last string
		var transport, state, scanID, observed sql.NullString
		var port sql.NullInt64
		var ps PortSummary
		if err := rows.Scan(&address, &first, &last, &transport, &port, &state, &scanID, &observed, &ps.Service, &ps.Product, &ps.Version); err != nil {
			return nil, err
		}
		addr, _ := netip.ParseAddr(address)
		if len(out) == 0 || out[len(out)-1].Address != addr {
			out = append(out, Asset{Address: addr, FirstSeen: parseTS(first), LastSeen: parseTS(last)})
		}
		if transport.Valid {
			ps.Transport, ps.Port, ps.State, ps.ScanID, ps.ObservedAt = transport.String, uint16(port.Int64), state.String, scanID.String, parseTS(observed.String)
			out[len(out)-1].Ports = append(out[len(out)-1].Ports, ps)
		}
	}
	return out, rows.Err()
}

// Retention selects scans to delete. Zero fields keep everything.
type Retention struct {
	OlderThan time.Duration // delete scans started before now minus this
	KeepLast  int           // always keep at most this many newest scans
}

// Prune deletes scans (and, by cascade, their observations, evidence and
// packet index) according to r, then removes assets nothing refers to. The
// pcapng files themselves are left on disk for the operator to manage.
func (s *Store) Prune(ctx context.Context, r Retention, now time.Time) (int, error) {
	if r.OlderThan < 0 || r.KeepLast < 0 {
		return 0, errors.New("retention values must be nonnegative")
	}
	if r.OlderThan == 0 && r.KeepLast == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	deleted := 0
	if r.OlderThan > 0 {
		res, err := tx.ExecContext(ctx, `DELETE FROM scans WHERE started_at < ?`, ts(now.Add(-r.OlderThan)))
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		deleted += int(n)
	}
	if r.KeepLast > 0 {
		res, err := tx.ExecContext(ctx, `DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY started_at DESC, id DESC LIMIT ?)`, r.KeepLast)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		deleted += int(n)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM assets WHERE id NOT IN (SELECT asset_id FROM observations) AND id NOT IN (SELECT asset_id FROM packet_flows)`); err != nil {
		return 0, err
	}
	return deleted, tx.Commit()
}
