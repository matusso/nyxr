package storage

import (
	"context"
	"database/sql"
	"net/netip"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// A lineage is the history one database recorded under its identity
// namespace. A central store ingests lineages without re-deriving what the
// local resolver decided: it receives the sealed observation sources, the
// resolver's own signal and clue extraction, and the local membership.

// IdentityValue is one normalized identity value extracted by this resolver.
// Scoped marks a portable identifier qualified by its owning account,
// subscription, project or cluster; only those are safe to join across
// lineages. Device-scoped values such as SSH host keys can be cloned with an
// image, so outside their own lineage they are clues, not merge keys.
type IdentityValue struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Scoped bool   `json:"scoped,omitempty"`
}

// StrongIdentityValues returns the values that may join addresses inside one
// lineage, exactly as the local resolver uses them.
func StrongIdentityValues(o observe.Observation) []IdentityValue {
	values := strongIdentityValues(o)
	out := make([]IdentityValue, 0, len(values))
	for _, v := range values {
		out = append(out, IdentityValue{Kind: v.kind, Value: v.value, Scoped: externalKinds[v.kind]})
	}
	return out
}

// IdentityClueValues returns the weak clues the local resolver keeps without
// ever merging on them.
func IdentityClueValues(o observe.Observation) []IdentityValue {
	values := identityClues(o)
	out := make([]IdentityValue, 0, len(values))
	for _, v := range values {
		out = append(out, IdentityValue{Kind: v.kind, Value: v.value})
	}
	return out
}

// PortableIdentityID is the database-independent URN of a scoped value, the
// same one IdentityGraph reports as a portable ID.
func PortableIdentityID(v IdentityValue) string {
	return portableIdentityID(identityValue{v.Kind, v.Value})
}

// Namespace is this database's random identity namespace, the lineage name.
func (s *Store) Namespace(ctx context.Context) (string, error) {
	var namespace string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM identity_namespace WHERE id = 1`).Scan(&namespace)
	return namespace, err
}

// LineageObservation is one stored observation with its sealed source and,
// for a fleet result, the attempt that delivered it.
type LineageObservation struct {
	RowID      int64
	ArtifactID string
	Source     []byte
	ScanID     string
	// Fleet is set when a fleet attempt delivered the observation; then
	// ClockOffset is the agent clock minus the controller clock measured
	// when the unit was leased.
	Fleet       bool
	AgentID     string
	LeaseID     string
	JobID       string
	Attempt     int
	ClockOffset time.Duration
}

// LineageObservations returns up to limit observations with a row number
// above after, in row order, for an incremental export.
func (s *Store) LineageObservations(ctx context.Context, after int64, limit int) ([]LineageObservation, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	rows, err := s.db.QueryContext(ctx, `SELECT o.id, src.artifact_id, src.source, o.scan_id,
			fa.lease_id IS NOT NULL, COALESCE(fa.agent_id, ''), COALESCE(fa.lease_id, ''), COALESCE(fa.job_id, ''),
			COALESCE(fa.attempt, 0), COALESCE(fa.clock_offset_ns, 0)
		FROM observations o JOIN observation_sources src ON src.observation_id = o.id
		LEFT JOIN fleet_attempts fa ON fa.scan_id = o.scan_id AND fa.scan_id <> ''
		WHERE o.id > ? ORDER BY o.id LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LineageObservation
	for rows.Next() {
		var lo LineageObservation
		var offset int64
		if err := rows.Scan(&lo.RowID, &lo.ArtifactID, &lo.Source, &lo.ScanID, &lo.Fleet, &lo.AgentID, &lo.LeaseID, &lo.JobID,
			&lo.Attempt, &offset); err != nil {
			return nil, err
		}
		lo.ClockOffset = time.Duration(offset)
		out = append(out, lo)
	}
	return out, rows.Err()
}

// LineageScan is a stored scan summary with the fleet agent that ran it.
type LineageScan struct {
	Scan    observe.Scan
	AgentID string
}

// LineageScans returns every stored scan, oldest first.
func (s *Store) LineageScans(ctx context.Context) ([]LineageScan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+scanColumns+`, COALESCE((SELECT agent_id FROM fleet_attempts fa WHERE fa.scan_id = scans.id), '')
		FROM scans ORDER BY started_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LineageScan
	for rows.Next() {
		var agent string
		sc, err := scanRow(scanAndAgent{rows, &agent})
		if err != nil {
			return nil, err
		}
		out = append(out, LineageScan{Scan: sc, AgentID: agent})
	}
	return out, rows.Err()
}

type scanAndAgent struct {
	rows  *sql.Rows
	agent *string
}

func (s scanAndAgent) Scan(dest ...any) error { return s.rows.Scan(append(dest, s.agent)...) }

// LineageMembership is a consistent snapshot of which local identity each
// address belongs to. Revision grows with every membership change, so a
// receiver can drop a snapshot older than one it already applied.
type LineageMembership struct {
	Revision int64
	// Members maps an address to its local global identity ID.
	Members map[netip.Addr]string
}

// LineageMembers reads the current membership in one transaction.
func (s *Store) LineageMembers(ctx context.Context) (LineageMembership, error) {
	out := LineageMembership{Members: map[netip.Addr]string{}}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()
	var namespace string
	if err := tx.QueryRowContext(ctx, `SELECT value FROM identity_namespace WHERE id = 1`).Scan(&namespace); err != nil {
		return out, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM identity_membership_events`).Scan(&out.Revision); err != nil {
		return out, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT a.address, m.identity_id FROM assets a JOIN identity_members m ON m.asset_id = a.id`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var address string
		var id int64
		if err := rows.Scan(&address, &id); err != nil {
			return out, err
		}
		addr, err := netip.ParseAddr(address)
		if err != nil {
			continue
		}
		out.Members[addr] = "urn:nyxr:" + namespace + ":" + identityName(id)
	}
	return out, rows.Err()
}
