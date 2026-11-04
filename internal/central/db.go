package central

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver
	_ "modernc.org/sqlite"             // registers the "sqlite" driver
)

// timeFormat matches the scanner store: fixed width, so text order is time
// order on both dialects.
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

type dialect int

const (
	sqliteDialect dialect = iota
	postgresDialect
)

// DB is the SQL implementation of Store.
type DB struct {
	db      *sql.DB
	dialect dialect
	objects ObjectStore
	// MaxArtifact bounds one stored artifact in bytes.
	MaxArtifact int64
	now         func() time.Time
}

var _ Store = (*DB)(nil)

// Open connects to dsn and applies pending migrations. A postgres:// or
// postgresql:// DSN selects PostgreSQL; sqlite:<path> or a plain path selects
// SQLite. objects may be nil when artifacts are only registered, not stored.
func Open(ctx context.Context, dsn string, objects ObjectStore) (*DB, error) {
	var (
		db  *sql.DB
		d   dialect
		err error
	)
	switch {
	case strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://"):
		d = postgresDialect
		db, err = sql.Open("pgx", dsn)
		if err == nil {
			db.SetMaxOpenConns(16)
		}
	default:
		path := strings.TrimPrefix(strings.TrimPrefix(dsn, "sqlite://"), "sqlite:")
		if path == "" || strings.ContainsAny(path, "?#") {
			return nil, errors.New("central SQLite path is required and must not contain '?' or '#'")
		}
		q := url.Values{}
		for _, p := range []string{"foreign_keys(1)", "busy_timeout(30000)", "journal_mode(WAL)", "synchronous(NORMAL)"} {
			q.Add("_pragma", p)
		}
		db, err = sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	}
	if err != nil {
		return nil, err
	}
	s := &DB{db: db, dialect: d, objects: objects, MaxArtifact: DefaultMaxArtifact, now: time.Now}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *DB) Close() error { return s.db.Close() }

// Dialect names the backend, "sqlite" or "postgres".
func (s *DB) Dialect() string {
	if s.dialect == postgresDialect {
		return "postgres"
	}
	return "sqlite"
}

// q rewrites ? placeholders to $n for PostgreSQL. No statement in this
// package has a literal question mark.
func (s *DB) q(query string) string {
	if s.dialect != postgresDialect {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// tx wraps *sql.Tx so every statement is rebound for the dialect.
type tx struct {
	*sql.Tx
	s *DB
}

func (t tx) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.ExecContext(ctx, t.s.q(query), args...)
}

func (t tx) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.QueryContext(ctx, t.s.q(query), args...)
}

func (t tx) row(ctx context.Context, query string, args ...any) *sql.Row {
	return t.QueryRowContext(ctx, t.s.q(query), args...)
}

// write runs fn in a transaction that first takes the store's write lock by
// bumping the global revision. Both dialects then serialize writers on that
// row, so reconciliation always sees every committed change.
func (s *DB) write(ctx context.Context, fn func(t tx, revision int64) error) error {
	sqlTx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	t := tx{sqlTx, s}
	defer func() { _ = sqlTx.Rollback() }()
	var revision int64
	if err := t.row(ctx, `UPDATE central_meta SET revision = revision + 1 WHERE id = 1 RETURNING revision`).Scan(&revision); err != nil {
		return err
	}
	if err := fn(t, revision); err != nil {
		return err
	}
	return sqlTx.Commit()
}

// read runs fn in a read-only snapshot.
func (s *DB) read(ctx context.Context, fn func(t tx) error) error {
	opts := &sql.TxOptions{ReadOnly: true}
	if s.dialect == postgresDialect {
		opts.Isolation = sql.LevelRepeatableRead
	}
	sqlTx, err := s.db.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	defer func() { _ = sqlTx.Rollback() }()
	return fn(tx{sqlTx, s})
}

// nextID allocates from a counter in central_meta. Writers hold the meta row
// lock, so IDs are dense and portable between dialects and through restore.
func (t tx) nextID(ctx context.Context, counter string) (int64, error) {
	switch counter {
	case "next_entity", "next_decision", "next_event":
	default:
		return 0, fmt.Errorf("unknown counter %q", counter)
	}
	var id int64
	err := t.row(ctx, `UPDATE central_meta SET `+counter+` = `+counter+` + 1 WHERE id = 1 RETURNING `+counter+` - 1`).Scan(&id)
	return id, err
}

// schema is applied in order. Never edit a released entry; append one.
// {{blob}} is the dialect's byte string type.
var schema = []string{
	`CREATE TABLE central_meta (
		id            INTEGER PRIMARY KEY CHECK (id = 1),
		namespace     TEXT NOT NULL,
		revision      BIGINT NOT NULL DEFAULT 0,
		next_entity   BIGINT NOT NULL DEFAULT 1,
		next_decision BIGINT NOT NULL DEFAULT 1,
		next_event    BIGINT NOT NULL DEFAULT 1
	);
	CREATE TABLE lineages (
		namespace       TEXT PRIMARY KEY,
		kind            TEXT NOT NULL,
		label           TEXT NOT NULL DEFAULT '',
		first_ingested  TEXT NOT NULL,
		last_ingested   TEXT NOT NULL,
		cursor          BIGINT NOT NULL DEFAULT 0,
		member_revision BIGINT NOT NULL DEFAULT -1
	);
	CREATE TABLE scans (
		lineage     TEXT NOT NULL,
		scan_id     TEXT NOT NULL,
		agent_id    TEXT NOT NULL DEFAULT '',
		profile     TEXT NOT NULL,
		status      TEXT NOT NULL,
		started_at  TEXT NOT NULL,
		finished_at TEXT NOT NULL DEFAULT '',
		record      TEXT NOT NULL,
		PRIMARY KEY (lineage, scan_id)
	);
	CREATE TABLE observations (
		artifact_id     TEXT PRIMARY KEY,
		lineage         TEXT NOT NULL,
		observation_id  TEXT NOT NULL,
		scan_id         TEXT NOT NULL,
		agent_id        TEXT NOT NULL DEFAULT '',
		lease_id        TEXT NOT NULL DEFAULT '',
		job_id          TEXT NOT NULL DEFAULT '',
		attempt         INTEGER NOT NULL DEFAULT 0,
		address         TEXT NOT NULL,
		kind            TEXT NOT NULL,
		reported_at     TEXT NOT NULL,
		observed_at     TEXT NOT NULL,
		clock_offset_ns BIGINT NOT NULL DEFAULT 0,
		time_quality    TEXT NOT NULL,
		ingested_at     TEXT NOT NULL,
		source          {{blob}} NOT NULL,
		UNIQUE (lineage, observation_id)
	);
	CREATE INDEX observations_address ON observations(lineage, address, observed_at);
	CREATE INDEX observations_scan ON observations(lineage, scan_id);
	CREATE TABLE ingest_conflicts (
		rejected_artifact_id TEXT PRIMARY KEY,
		lineage              TEXT NOT NULL,
		observation_id       TEXT NOT NULL,
		stored_artifact_id   TEXT NOT NULL,
		detected_at          TEXT NOT NULL
	);
	CREATE TABLE addresses (
		lineage    TEXT NOT NULL,
		address    TEXT NOT NULL,
		node       TEXT NOT NULL,
		first_seen TEXT NOT NULL,
		last_seen  TEXT NOT NULL,
		PRIMARY KEY (lineage, address)
	);
	CREATE INDEX addresses_node ON addresses(node);
	CREATE TABLE members (
		lineage TEXT NOT NULL,
		address TEXT NOT NULL,
		node    TEXT NOT NULL,
		PRIMARY KEY (lineage, address)
	);
	CREATE TABLE signals (
		lineage      TEXT NOT NULL,
		address      TEXT NOT NULL,
		kind         TEXT NOT NULL,
		value        TEXT NOT NULL,
		scoped       INTEGER NOT NULL,
		first_seen   TEXT NOT NULL,
		last_seen    TEXT NOT NULL,
		observations BIGINT NOT NULL,
		PRIMARY KEY (lineage, address, kind, value)
	);
	CREATE INDEX signals_value ON signals(kind, value);
	CREATE TABLE clues (
		lineage      TEXT NOT NULL,
		address      TEXT NOT NULL,
		kind         TEXT NOT NULL,
		value        TEXT NOT NULL,
		first_seen   TEXT NOT NULL,
		last_seen    TEXT NOT NULL,
		observations BIGINT NOT NULL,
		PRIMARY KEY (lineage, address, kind, value)
	);
	CREATE INDEX clues_value ON clues(kind, value);
	CREATE TABLE entities (
		id         BIGINT PRIMARY KEY,
		revision   BIGINT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);
	CREATE TABLE nodes (
		node    TEXT PRIMARY KEY,
		lineage TEXT NOT NULL,
		entity  BIGINT NOT NULL
	);
	CREATE INDEX nodes_entity ON nodes(entity);
	CREATE TABLE decisions (
		id          BIGINT PRIMARY KEY,
		action      TEXT NOT NULL CHECK (action IN ('join', 'separate', 'revert')),
		node_a      TEXT NOT NULL DEFAULT '',
		node_b      TEXT NOT NULL DEFAULT '',
		target      BIGINT NOT NULL DEFAULT 0,
		note        TEXT NOT NULL,
		actor       TEXT NOT NULL DEFAULT '',
		decided_at  TEXT NOT NULL,
		reverted_by BIGINT NOT NULL DEFAULT 0
	);
	CREATE TABLE events (
		id          BIGINT PRIMARY KEY,
		node        TEXT NOT NULL,
		from_entity BIGINT NOT NULL,
		to_entity   BIGINT NOT NULL,
		cause       TEXT NOT NULL,
		decision    BIGINT NOT NULL DEFAULT 0,
		revision    BIGINT NOT NULL,
		at          TEXT NOT NULL
	);
	CREATE INDEX events_node ON events(node, id);
	CREATE TABLE conflicts (
		reason  TEXT NOT NULL,
		kind    TEXT NOT NULL,
		node_a  TEXT NOT NULL,
		node_b  TEXT NOT NULL,
		value_a TEXT NOT NULL,
		value_b TEXT NOT NULL
	);
	CREATE TABLE artifacts (
		id            TEXT PRIMARY KEY,
		kind          TEXT NOT NULL,
		media_type    TEXT NOT NULL DEFAULT '',
		size          BIGINT NOT NULL DEFAULT 0,
		state         TEXT NOT NULL,
		object_key    TEXT NOT NULL DEFAULT '',
		access        TEXT NOT NULL CHECK (access IN ('internal', 'restricted')),
		retain_until  TEXT NOT NULL DEFAULT '',
		lineage       TEXT NOT NULL DEFAULT '',
		scan_id       TEXT NOT NULL DEFAULT '',
		agent_id      TEXT NOT NULL DEFAULT '',
		registered_at TEXT NOT NULL,
		stored_at     TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX artifacts_state ON artifacts(state, retain_until);`,
}

func (s *DB) migrate(ctx context.Context) error {
	blob := "BLOB"
	if s.dialect == postgresDialect {
		blob = "BYTEA"
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS central_schema (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("open central store: %w", err)
	}
	for {
		applied, err := s.migrateOne(ctx, blob)
		if err != nil || !applied {
			return err
		}
	}
}

// migrateOne applies the next pending migration, if any. On PostgreSQL an
// advisory lock keeps two controllers from migrating the same schema at once.
func (s *DB) migrateOne(ctx context.Context, blob string) (bool, error) {
	sqlTx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	t := tx{sqlTx, s}
	defer func() { _ = sqlTx.Rollback() }()
	if s.dialect == postgresDialect {
		if _, err := t.exec(ctx, `SELECT pg_advisory_xact_lock(7239001)`); err != nil {
			return false, err
		}
	} else if _, err := t.exec(ctx, `DELETE FROM central_schema WHERE version < 0`); err != nil {
		return false, err // takes SQLite's write lock before reading the version
	}
	var current int
	if err := t.row(ctx, `SELECT COALESCE(MAX(version), 0) FROM central_schema`).Scan(&current); err != nil {
		return false, err
	}
	if current > len(schema) {
		return false, fmt.Errorf("central schema version %d is newer than this nyxr (%d)", current, len(schema))
	}
	if current == len(schema) {
		return false, nil
	}
	stmt := strings.ReplaceAll(schema[current], "{{blob}}", blob)
	if s.dialect == postgresDialect {
		_, err = t.exec(ctx, stmt)
	} else {
		_, err = sqlTx.ExecContext(ctx, stmt) // multi-statement; nothing to rebind
	}
	if err != nil {
		return false, fmt.Errorf("central migration %d: %w", current+1, err)
	}
	if current == 0 {
		var ns [16]byte
		if _, err := rand.Read(ns[:]); err != nil {
			return false, err
		}
		if _, err := t.exec(ctx, `INSERT INTO central_meta(id, namespace) VALUES (1, ?)`, hex.EncodeToString(ns[:])); err != nil {
			return false, err
		}
	}
	if _, err := t.exec(ctx, `INSERT INTO central_schema(version, applied_at) VALUES (?, ?)`, current+1, ts(time.Now())); err != nil {
		return false, err
	}
	return true, sqlTx.Commit()
}

// SchemaVersion is the number of applied central migrations.
func (s *DB) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM central_schema`).Scan(&v)
	return v, err
}

// Namespace is this central store's random namespace, part of entity URNs.
func (s *DB) Namespace(ctx context.Context) (string, error) {
	var ns string
	err := s.db.QueryRowContext(ctx, `SELECT namespace FROM central_meta WHERE id = 1`).Scan(&ns)
	return ns, err
}

func entityName(id int64) string { return fmt.Sprintf("NYXC-%012X", id) }

func parseEntityName(name string) (int64, bool) {
	hexID, ok := strings.CutPrefix(name, "NYXC-")
	if !ok {
		return 0, false
	}
	id, err := strconv.ParseInt(hexID, 16, 64)
	return id, err == nil && id > 0
}
