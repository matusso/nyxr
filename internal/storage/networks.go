package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// networksMigration adds the registry of named networks. Only the default
// database uses it: each row points at the database file that holds one
// network's scans, so networks reusing an address range never share assets.
const networksMigration = `CREATE TABLE networks (
	name         TEXT PRIMARY KEY,
	path         TEXT NOT NULL UNIQUE,
	created_at   TEXT NOT NULL,
	last_scan_id TEXT NOT NULL DEFAULT '',
	last_scan_at TEXT NOT NULL DEFAULT '',
	scans        INTEGER NOT NULL DEFAULT 0,
	sha256       TEXT NOT NULL DEFAULT ''
);`

// Network is one registry row. SHA256 is the database file's digest after
// its last recorded scan; a different digest means the file changed since.
type Network struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Created    time.Time `json:"created"`
	LastScanID string    `json:"last_scan_id,omitempty"`
	LastScan   time.Time `json:"last_scan,omitempty"`
	Scans      int       `json:"scans"`
	SHA256     string    `json:"sha256,omitempty"`
	// Integrity is filled by the caller that rehashes the file: unchanged,
	// changed or missing.
	Integrity string `json:"integrity,omitempty"`
}

const networkColumns = `name, path, created_at, last_scan_id, last_scan_at, scans, sha256`

func networkRow(row interface{ Scan(...any) error }) (Network, error) {
	var n Network
	var created, last string
	err := row.Scan(&n.Name, &n.Path, &created, &n.LastScanID, &last, &n.Scans, &n.SHA256)
	n.Created, n.LastScan = parseTS(created), parseTS(last)
	return n, err
}

// Network returns one registered network; ok is false when name is unknown.
func (s *Store) Network(ctx context.Context, name string) (Network, bool, error) {
	n, err := networkRow(s.db.QueryRowContext(ctx, `SELECT `+networkColumns+` FROM networks WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return Network{}, false, nil
	}
	return n, err == nil, err
}

// Networks lists the registry by name.
func (s *Store) Networks(ctx context.Context) ([]Network, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+networkColumns+` FROM networks ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Network{}
	for rows.Next() {
		n, err := networkRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// SaveNetwork registers a network or updates its last-scan metadata. The
// path of a registered name never changes.
func (s *Store) SaveNetwork(ctx context.Context, n Network) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO networks(name, path, created_at, last_scan_id, last_scan_at, scans, sha256)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET last_scan_id = excluded.last_scan_id, last_scan_at = excluded.last_scan_at,
			scans = excluded.scans, sha256 = excluded.sha256`,
		n.Name, n.Path, ts(time.Now()), n.LastScanID, ts(n.LastScan), n.Scans, n.SHA256)
	return err
}

// Checkpoint moves the write-ahead log into the database file, so the file
// alone holds everything committed so far.
func (s *Store) Checkpoint(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}
