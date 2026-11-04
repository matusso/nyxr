package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// fleetMigration stores distributed scan jobs. A job is split into units; each
// lease of a unit to an agent is an attempt. An attempt's results are applied
// exactly once by (lease_id, seq), and job totals count only the attempt that
// completed its unit, so a retried unit never double-counts evidence. Partial
// results of an expired or failed attempt remain stored under their own
// (failed) scan, like a partial CLI scan.
const fleetMigration = `CREATE TABLE fleet_agents (
		id              TEXT PRIMARY KEY,
		name            TEXT NOT NULL,
		secret_hash     TEXT NOT NULL,
		enrolled_at     TEXT NOT NULL,
		last_seen       TEXT NOT NULL DEFAULT '',
		clock_offset_ns INTEGER NOT NULL DEFAULT 0,
		capabilities    TEXT NOT NULL DEFAULT '{}',
		revoked_at      TEXT NOT NULL DEFAULT ''
	);
	CREATE TABLE fleet_jobs (
		id           TEXT PRIMARY KEY,
		created_at   TEXT NOT NULL,
		finished_at  TEXT NOT NULL DEFAULT '',
		status       TEXT NOT NULL,
		error        TEXT NOT NULL DEFAULT '',
		request      TEXT NOT NULL,
		options      TEXT NOT NULL,
		max_attempts INTEGER NOT NULL,
		units        INTEGER NOT NULL,
		targets      INTEGER NOT NULL
	);
	CREATE INDEX fleet_jobs_created ON fleet_jobs(created_at);
	CREATE TABLE fleet_units (
		job_id       TEXT NOT NULL REFERENCES fleet_jobs(id) ON DELETE CASCADE,
		idx          INTEGER NOT NULL,
		targets      TEXT NOT NULL,
		target_count INTEGER NOT NULL,
		subnet_share INTEGER NOT NULL DEFAULT 1,
		status       TEXT NOT NULL,
		attempts     INTEGER NOT NULL DEFAULT 0,
		not_before   TEXT NOT NULL DEFAULT '',
		lease_id     TEXT NOT NULL DEFAULT '',
		agent_id     TEXT NOT NULL DEFAULT '',
		scan_id      TEXT NOT NULL DEFAULT '',
		error        TEXT NOT NULL DEFAULT '',
		observations INTEGER NOT NULL DEFAULT 0,
		services     INTEGER NOT NULL DEFAULT 0,
		updated_at   TEXT NOT NULL,
		PRIMARY KEY (job_id, idx)
	);
	CREATE INDEX fleet_units_status ON fleet_units(status, job_id, idx);
	CREATE TABLE fleet_attempts (
		lease_id        TEXT PRIMARY KEY,
		job_id          TEXT NOT NULL,
		idx             INTEGER NOT NULL,
		attempt         INTEGER NOT NULL,
		agent_id        TEXT NOT NULL,
		scan_id         TEXT NOT NULL DEFAULT '',
		started_at      TEXT NOT NULL,
		expires_at      TEXT NOT NULL,
		finished_at     TEXT NOT NULL DEFAULT '',
		status          TEXT NOT NULL,
		error           TEXT NOT NULL DEFAULT '',
		last_seq        INTEGER NOT NULL DEFAULT 0,
		clock_offset_ns INTEGER NOT NULL DEFAULT 0,
		FOREIGN KEY (job_id, idx) REFERENCES fleet_units(job_id, idx) ON DELETE CASCADE
	);
	CREATE INDEX fleet_attempts_unit ON fleet_attempts(job_id, idx, attempt);
	CREATE INDEX fleet_attempts_open ON fleet_attempts(status, expires_at);`

// Fleet job, unit and attempt states.
const (
	FleetRunning   = "running"
	FleetCompleted = "completed"
	FleetFailed    = "failed"
	FleetCanceled  = "canceled"
	FleetPending   = "pending"
	FleetLeased    = "leased"
	FleetExpired   = "expired"
	FleetRejected  = "rejected"
)

// ErrLeaseGone means a lease is no longer active on the controller: it
// expired, was canceled, or never existed. The agent must stop the work.
var ErrLeaseGone = errors.New("lease is no longer active")

// ErrSequenceGap means a result batch skipped a sequence number.
var ErrSequenceGap = errors.New("result batch out of sequence")

// ErrInvalidBatch marks a batch the agent got wrong, as opposed to a storage
// failure that a resend can fix.
var ErrInvalidBatch = errors.New("invalid result batch")

// FleetAgent is an enrolled agent. Capabilities are the JSON of its last Hello.
type FleetAgent struct {
	ID           string          `json:"agent_id"`
	Name         string          `json:"name"`
	EnrolledAt   time.Time       `json:"enrolled_at"`
	LastSeen     time.Time       `json:"last_seen,omitempty"`
	ClockOffset  time.Duration   `json:"clock_offset_ns"`
	Capabilities json.RawMessage `json:"capabilities"`
	Revoked      bool            `json:"revoked"`
}

// FleetJob is a distributed scan. Observations and Services sum only the
// accepted (completed) attempt of each unit.
type FleetJob struct {
	ID           string          `json:"job_id"`
	Created      time.Time       `json:"created"`
	Finished     time.Time       `json:"finished,omitempty"`
	Status       string          `json:"status"`
	Error        string          `json:"error,omitempty"`
	Request      json.RawMessage `json:"request"`
	Options      json.RawMessage `json:"options"`
	MaxAttempts  int             `json:"max_attempts"`
	Units        int             `json:"units"`
	Targets      int             `json:"targets"`
	UnitStatus   map[string]int  `json:"unit_status"`
	Observations int             `json:"observations"`
	Services     int             `json:"services"`
}

// FleetUnit is one partition of a job.
type FleetUnit struct {
	JobID       string   `json:"job_id"`
	Index       int      `json:"unit"`
	Targets     []string `json:"targets"`
	TargetCount int      `json:"target_count"`
	// SubnetShare is how many units split the busiest IPv4 /24 or IPv6 /64
	// of this unit; the per-subnet rate is divided by it.
	SubnetShare  int       `json:"subnet_share"`
	Status       string    `json:"status"`
	Attempts     int       `json:"attempts"`
	NotBefore    time.Time `json:"not_before,omitempty"`
	LeaseID      string    `json:"lease_id,omitempty"`
	AgentID      string    `json:"agent_id,omitempty"`
	ScanID       string    `json:"scan_id,omitempty"`
	Error        string    `json:"error,omitempty"`
	Observations int       `json:"observations"`
	Services     int       `json:"services"`
	Updated      time.Time `json:"updated"`
}

// FleetAttempt is one lease of a unit to an agent.
type FleetAttempt struct {
	LeaseID     string        `json:"lease_id"`
	JobID       string        `json:"job_id"`
	Index       int           `json:"unit"`
	Attempt     int           `json:"attempt"`
	AgentID     string        `json:"agent_id"`
	ScanID      string        `json:"scan_id,omitempty"`
	Started     time.Time     `json:"started"`
	Expires     time.Time     `json:"expires"`
	Finished    time.Time     `json:"finished,omitempty"`
	Status      string        `json:"status"`
	Error       string        `json:"error,omitempty"`
	LastSeq     uint64        `json:"last_seq"`
	ClockOffset time.Duration `json:"clock_offset_ns"`
}

// FleetRecordKind mirrors the wire record kinds.
type FleetRecordKind int

const (
	FleetBegin FleetRecordKind = iota + 1
	FleetObservation
	FleetPacketEvidence
	FleetFinish
)

// FleetRecord is one decoded result record. Exactly one field is set.
type FleetRecord struct {
	Kind        FleetRecordKind
	Scan        observe.Scan
	Observation observe.Observation
	Packets     observe.PacketEvidence
}

// FleetApplied reports the outcome of one batch.
type FleetApplied struct {
	// Duplicate means seq was already applied; nothing changed.
	Duplicate bool
	// Done means the attempt finished (completed or failed) in this or an
	// earlier batch.
	Done bool
	// UnitStatus is the unit state after the batch.
	UnitStatus string
	// JobFinished is set when this batch finished the whole job.
	JobFinished bool
}

// fleetBackoff delays a retried unit so a failing agent or target does not
// spin. It grows with the attempt count up to one minute.
func fleetBackoff(attempts int) time.Duration {
	if attempts < 1 {
		return 0
	}
	d := time.Second << min(attempts-1, 6)
	return min(d, time.Minute)
}

// CreateFleetAgent stores a new enrollment.
func (s *Store) CreateFleetAgent(ctx context.Context, id, name, secretHash string, caps json.RawMessage, now time.Time) error {
	if len(caps) == 0 {
		caps = json.RawMessage("{}")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO fleet_agents(id, name, secret_hash, enrolled_at, capabilities) VALUES (?, ?, ?, ?, ?)`,
		id, name, secretHash, ts(now), string(caps))
	return err
}

// FleetAgentSecret returns an agent's stored secret hash; ok is false for an
// unknown or revoked agent.
func (s *Store) FleetAgentSecret(ctx context.Context, id string) (hash string, ok bool, err error) {
	var revoked string
	err = s.db.QueryRowContext(ctx, `SELECT secret_hash, revoked_at FROM fleet_agents WHERE id = ?`, id).Scan(&hash, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return hash, revoked == "", nil
}

// TouchFleetAgent records a Hello or heartbeat. Nil caps keeps the stored
// capabilities.
func (s *Store) TouchFleetAgent(ctx context.Context, id string, seen time.Time, offset time.Duration, caps json.RawMessage) error {
	if caps == nil {
		_, err := s.db.ExecContext(ctx, `UPDATE fleet_agents SET last_seen = ?, clock_offset_ns = ? WHERE id = ?`, ts(seen), int64(offset), id)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE fleet_agents SET last_seen = ?, clock_offset_ns = ?, capabilities = ? WHERE id = ?`,
		ts(seen), int64(offset), string(caps), id)
	return err
}

// RevokeFleetAgent disables an agent credential; ok is false when the agent
// is unknown or already revoked.
func (s *Store) RevokeFleetAgent(ctx context.Context, id string, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE fleet_agents SET revoked_at = ? WHERE id = ? AND revoked_at = ''`, ts(now), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// FleetAgents lists enrolled agents, newest first.
func (s *Store) FleetAgents(ctx context.Context) ([]FleetAgent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, enrolled_at, last_seen, clock_offset_ns, capabilities, revoked_at FROM fleet_agents ORDER BY enrolled_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FleetAgent{}
	for rows.Next() {
		var a FleetAgent
		var enrolled, seen, caps, revoked string
		var offset int64
		if err := rows.Scan(&a.ID, &a.Name, &enrolled, &seen, &offset, &caps, &revoked); err != nil {
			return nil, err
		}
		a.EnrolledAt, a.LastSeen, a.ClockOffset = parseTS(enrolled), parseTS(seen), time.Duration(offset)
		a.Capabilities, a.Revoked = json.RawMessage(caps), revoked != ""
		out = append(out, a)
	}
	return out, rows.Err()
}

// CreateFleetJob stores a job and all of its units in one transaction.
func (s *Store) CreateFleetJob(ctx context.Context, job FleetJob, units []FleetUnit) error {
	if len(units) == 0 {
		return errors.New("fleet job has no units")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO fleet_jobs(id, created_at, status, request, options, max_attempts, units, targets) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		job.ID, ts(job.Created), FleetRunning, string(job.Request), string(job.Options), job.MaxAttempts, len(units), job.Targets); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO fleet_units(job_id, idx, targets, target_count, subnet_share, status, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i, u := range units {
		targets, err := json.Marshal(u.Targets)
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx, job.ID, i, string(targets), u.TargetCount, max(u.SubnetShare, 1), FleetPending, ts(job.Created)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const fleetJobColumns = `j.id, j.created_at, j.finished_at, j.status, j.error, j.request, j.options, j.max_attempts, j.units, j.targets,
	COALESCE((SELECT SUM(observations) FROM fleet_units WHERE job_id = j.id AND status = 'completed'), 0),
	COALESCE((SELECT SUM(services) FROM fleet_units WHERE job_id = j.id AND status = 'completed'), 0)`

func fleetJobRow(row interface{ Scan(...any) error }) (FleetJob, error) {
	var j FleetJob
	var created, finished, req, opts string
	err := row.Scan(&j.ID, &created, &finished, &j.Status, &j.Error, &req, &opts, &j.MaxAttempts, &j.Units, &j.Targets, &j.Observations, &j.Services)
	j.Created, j.Finished, j.Request, j.Options = parseTS(created), parseTS(finished), json.RawMessage(req), json.RawMessage(opts)
	return j, err
}

func (s *Store) fleetUnitStatus(ctx context.Context, j *FleetJob) error {
	rows, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM fleet_units WHERE job_id = ? GROUP BY status`, j.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	j.UnitStatus = map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return err
		}
		j.UnitStatus[st] = n
	}
	return rows.Err()
}

// FleetJobs lists jobs, newest first.
func (s *Store) FleetJobs(ctx context.Context, limit int) ([]FleetJob, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+fleetJobColumns+` FROM fleet_jobs j ORDER BY j.created_at DESC, j.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	out := []FleetJob{}
	for rows.Next() {
		j, err := fleetJobRow(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, j)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := s.fleetUnitStatus(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// FleetJob returns one job; ok is false when it does not exist.
func (s *Store) FleetJob(ctx context.Context, id string) (FleetJob, bool, error) {
	j, err := fleetJobRow(s.db.QueryRowContext(ctx, `SELECT `+fleetJobColumns+` FROM fleet_jobs j WHERE j.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return FleetJob{}, false, nil
	}
	if err != nil {
		return FleetJob{}, false, err
	}
	return j, true, s.fleetUnitStatus(ctx, &j)
}

const fleetUnitColumns = `job_id, idx, targets, target_count, subnet_share, status, attempts, not_before, lease_id, agent_id, scan_id, error, observations, services, updated_at`

func fleetUnitRow(row interface{ Scan(...any) error }) (FleetUnit, error) {
	var u FleetUnit
	var targets, notBefore, updated string
	if err := row.Scan(&u.JobID, &u.Index, &targets, &u.TargetCount, &u.SubnetShare, &u.Status, &u.Attempts, &notBefore, &u.LeaseID, &u.AgentID, &u.ScanID,
		&u.Error, &u.Observations, &u.Services, &updated); err != nil {
		return u, err
	}
	u.NotBefore, u.Updated = parseTS(notBefore), parseTS(updated)
	return u, json.Unmarshal([]byte(targets), &u.Targets)
}

// FleetUnits lists a job's units in order.
func (s *Store) FleetUnits(ctx context.Context, jobID string) ([]FleetUnit, error) {
	return s.queryFleetUnits(ctx, `SELECT `+fleetUnitColumns+` FROM fleet_units WHERE job_id = ? ORDER BY idx`, jobID)
}

// FleetUnit returns one unit.
func (s *Store) FleetUnit(ctx context.Context, jobID string, idx int) (FleetUnit, error) {
	return fleetUnitRow(s.db.QueryRowContext(ctx, `SELECT `+fleetUnitColumns+` FROM fleet_units WHERE job_id = ? AND idx = ?`, jobID, idx))
}

func (s *Store) queryFleetUnits(ctx context.Context, q string, args ...any) ([]FleetUnit, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FleetUnit{}
	for rows.Next() {
		u, err := fleetUnitRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// PendingFleetUnits returns schedulable units of running jobs, oldest job
// first. Units still in retry backoff are skipped.
func (s *Store) PendingFleetUnits(ctx context.Context, now time.Time, limit int) ([]FleetUnit, error) {
	// At most perJob units per job, so one large or unschedulable job cannot
	// hide every later job from the scheduler.
	const perJob = 64
	return s.queryFleetUnits(ctx, `SELECT `+fleetUnitColumns+` FROM (
			SELECT u.*, ROW_NUMBER() OVER (PARTITION BY u.job_id ORDER BY u.idx) AS rn, j.created_at AS job_created
			FROM fleet_units u JOIN fleet_jobs j ON j.id = u.job_id
			WHERE u.status = 'pending' AND u.not_before <= ? AND j.status = 'running')
		WHERE rn <= ? ORDER BY job_created, job_id, idx LIMIT ?`, ts(now), perJob, limit)
}

// FleetAttempts lists a job's attempts in order.
func (s *Store) FleetAttempts(ctx context.Context, jobID string) ([]FleetAttempt, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT lease_id, job_id, idx, attempt, agent_id, scan_id, started_at, expires_at, finished_at, status, error, last_seq, clock_offset_ns
		FROM fleet_attempts WHERE job_id = ? ORDER BY idx, attempt`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FleetAttempt{}
	for rows.Next() {
		var a FleetAttempt
		var started, expires, finished string
		var offset int64
		if err := rows.Scan(&a.LeaseID, &a.JobID, &a.Index, &a.Attempt, &a.AgentID, &a.ScanID, &started, &expires, &finished, &a.Status, &a.Error, &a.LastSeq, &offset); err != nil {
			return nil, err
		}
		a.Started, a.Expires, a.Finished, a.ClockOffset = parseTS(started), parseTS(expires), parseTS(finished), time.Duration(offset)
		out = append(out, a)
	}
	return out, rows.Err()
}

// FleetAttempt returns one attempt by lease; ok is false when unknown.
func (s *Store) FleetAttempt(ctx context.Context, leaseID string) (FleetAttempt, bool, error) {
	var a FleetAttempt
	var started, expires, finished string
	var offset int64
	err := s.db.QueryRowContext(ctx, `SELECT lease_id, job_id, idx, attempt, agent_id, scan_id, started_at, expires_at, finished_at, status, error, last_seq, clock_offset_ns
		FROM fleet_attempts WHERE lease_id = ?`, leaseID).Scan(&a.LeaseID, &a.JobID, &a.Index, &a.Attempt, &a.AgentID, &a.ScanID, &started, &expires, &finished, &a.Status, &a.Error, &a.LastSeq, &offset)
	if errors.Is(err, sql.ErrNoRows) {
		return a, false, nil
	}
	a.Started, a.Expires, a.Finished, a.ClockOffset = parseTS(started), parseTS(expires), parseTS(finished), time.Duration(offset)
	return a, err == nil, err
}

// ActiveFleetLeases returns the open attempts, optionally of one agent.
func (s *Store) ActiveFleetLeases(ctx context.Context, agentID string) ([]FleetAttempt, error) {
	q := `SELECT lease_id, job_id, idx, attempt, agent_id, expires_at FROM fleet_attempts WHERE status = 'leased'`
	var args []any
	if agentID != "" {
		q += ` AND agent_id = ?`
		args = append(args, agentID)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY started_at`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FleetAttempt
	for rows.Next() {
		var a FleetAttempt
		var expires string
		if err := rows.Scan(&a.LeaseID, &a.JobID, &a.Index, &a.Attempt, &a.AgentID, &expires); err != nil {
			return nil, err
		}
		a.Expires, a.Status = parseTS(expires), FleetLeased
		out = append(out, a)
	}
	return out, rows.Err()
}

// LeaseFleetUnit atomically moves a pending unit to leased and records the
// attempt. ok is false when another scheduler pass took the unit first.
func (s *Store) LeaseFleetUnit(ctx context.Context, jobID string, idx int, leaseID, agentID string, now, expires time.Time, offset time.Duration) (attempt int, ok bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = tx.Rollback() }()
	err = tx.QueryRowContext(ctx, `UPDATE fleet_units SET status = 'leased', attempts = attempts + 1, lease_id = ?, agent_id = ?, scan_id = '', error = '', updated_at = ?
		WHERE job_id = ? AND idx = ? AND status = 'pending' AND job_id IN (SELECT id FROM fleet_jobs WHERE status = 'running')
		RETURNING attempts`, leaseID, agentID, ts(now), jobID, idx).Scan(&attempt)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO fleet_attempts(lease_id, job_id, idx, attempt, agent_id, started_at, expires_at, status, clock_offset_ns) VALUES (?, ?, ?, ?, ?, ?, ?, 'leased', ?)`,
		leaseID, jobID, idx, attempt, agentID, ts(now), ts(expires), int64(offset)); err != nil {
		return 0, false, err
	}
	return attempt, true, tx.Commit()
}

// RenewFleetLeases extends the named open leases held by agentID and returns
// the ones that are no longer active, which the agent must stop.
func (s *Store) RenewFleetLeases(ctx context.Context, agentID string, leaseIDs []string, expires time.Time) (gone []string, err error) {
	for _, id := range leaseIDs {
		res, err := s.db.ExecContext(ctx, `UPDATE fleet_attempts SET expires_at = ? WHERE lease_id = ? AND agent_id = ? AND status = 'leased'`, ts(expires), id, agentID)
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			gone = append(gone, id)
		}
	}
	return gone, nil
}

// ExtendAllFleetLeases gives every open lease at least until expires. A
// restarted controller calls it so agents can reconnect and resume their
// streams instead of losing work to expiry while the controller was down.
func (s *Store) ExtendAllFleetLeases(ctx context.Context, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE fleet_attempts SET expires_at = max(expires_at, ?) WHERE status = 'leased'`, ts(expires))
	return err
}

// EndFleetLease closes an open attempt that will deliver no Finish record:
// it expired, the agent rejected it, or the agent lost it. Its partial scan,
// if any, is finished as failed. The unit is retried with backoff until the
// job's attempt limit, then fails. ok is false when the lease was not open.
func (s *Store) EndFleetLease(ctx context.Context, leaseID, status, reason string, now time.Time) (ok bool, jobFinished bool, err error) {
	return s.endFleetLease(ctx, leaseID, status, reason, now, false)
}

// ExpireFleetLease ends a lease only if it is still past its expiry, so a
// heartbeat that renewed it after the expiry scan wins.
func (s *Store) ExpireFleetLease(ctx context.Context, leaseID, reason string, now time.Time) (ok bool, jobFinished bool, err error) {
	return s.endFleetLease(ctx, leaseID, FleetExpired, reason, now, true)
}

func (s *Store) endFleetLease(ctx context.Context, leaseID, status, reason string, now time.Time, onlyExpired bool) (ok bool, jobFinished bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var jobID, scanID string
	var idx int
	expiredBefore := "9999"
	if onlyExpired {
		expiredBefore = ts(now)
	}
	err = tx.QueryRowContext(ctx, `UPDATE fleet_attempts SET status = ?, error = ?, finished_at = ? WHERE lease_id = ? AND status = 'leased' AND expires_at < ? RETURNING job_id, idx, scan_id`,
		status, reason, ts(now), leaseID, expiredBefore).Scan(&jobID, &idx, &scanID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if scanID != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE scans SET status = 'failed', error = ?, finished_at = ? WHERE id = ? AND status = 'running'`,
			"fleet lease "+status+": "+reason, ts(now), scanID); err != nil {
			return false, false, err
		}
	}
	if err := retryOrFailUnit(ctx, tx, jobID, idx, leaseID, reason, now); err != nil {
		return false, false, err
	}
	finished, err := finishJobIfDone(ctx, tx, jobID, now)
	if err != nil {
		return false, false, err
	}
	return true, finished, tx.Commit()
}

// retryOrFailUnit returns a unit whose lease ended without success to the
// queue, or fails it once its attempts are exhausted. A canceled job's unit
// ends canceled.
func retryOrFailUnit(ctx context.Context, tx *sql.Tx, jobID string, idx int, leaseID, reason string, now time.Time) error {
	var attempts, maxAttempts int
	var jobStatus string
	if err := tx.QueryRowContext(ctx, `SELECT u.attempts, j.max_attempts, j.status FROM fleet_units u JOIN fleet_jobs j ON j.id = u.job_id WHERE u.job_id = ? AND u.idx = ? AND u.lease_id = ?`,
		jobID, idx, leaseID).Scan(&attempts, &maxAttempts, &jobStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil // the unit already moved on
		}
		return err
	}
	status, notBefore := FleetPending, ts(now.Add(fleetBackoff(attempts)))
	switch {
	case jobStatus == FleetCanceled:
		status, notBefore = FleetCanceled, ""
	case attempts >= maxAttempts:
		status, notBefore = FleetFailed, ""
		reason = fmt.Sprintf("%s (attempt %d of %d)", reason, attempts, maxAttempts)
	}
	_, err := tx.ExecContext(ctx, `UPDATE fleet_units SET status = ?, not_before = ?, lease_id = '', error = ?, updated_at = ? WHERE job_id = ? AND idx = ?`,
		status, notBefore, reason, ts(now), jobID, idx)
	return err
}

// finishJobIfDone closes a job once no unit can make progress.
func finishJobIfDone(ctx context.Context, tx *sql.Tx, jobID string, now time.Time) (bool, error) {
	var open, failed int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FILTER (WHERE status IN ('pending', 'leased')), COUNT(*) FILTER (WHERE status = 'failed') FROM fleet_units WHERE job_id = ?`,
		jobID).Scan(&open, &failed); err != nil {
		return false, err
	}
	if open > 0 {
		return false, nil
	}
	status, msg := FleetCompleted, ""
	if failed > 0 {
		status, msg = FleetFailed, fmt.Sprintf("%d unit(s) failed", failed)
	}
	res, err := tx.ExecContext(ctx, `UPDATE fleet_jobs SET status = CASE WHEN status = 'canceled' THEN status ELSE ? END,
		error = CASE WHEN status = 'canceled' THEN error ELSE ? END, finished_at = ? WHERE id = ? AND finished_at = ''`, status, msg, ts(now), jobID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ApplyFleetBatch stores one result batch and advances the lease checkpoint
// in the same transaction, so a crash or a resent batch can neither lose nor
// duplicate records. A seq at or below the checkpoint is a duplicate and is
// acknowledged without changes. Records must belong to the attempt's scan;
// the caller validates targets against the unit.
func (s *Store) ApplyFleetBatch(ctx context.Context, leaseID string, seq uint64, records []FleetRecord, now time.Time) (FleetApplied, error) {
	var out FleetApplied
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer func() { _ = tx.Rollback() }()
	var jobID, scanID, status string
	var idx int
	var last uint64
	// A no-op UPDATE takes the write lock before reading: a read-then-write
	// transaction cannot wait for a concurrent writer and fails with
	// SQLITE_BUSY instead.
	err = tx.QueryRowContext(ctx, `UPDATE fleet_attempts SET last_seq = last_seq WHERE lease_id = ? RETURNING job_id, idx, scan_id, status, last_seq`,
		leaseID).Scan(&jobID, &idx, &scanID, &status, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrLeaseGone
	}
	if err != nil {
		return out, err
	}
	if seq <= last {
		out.Duplicate, out.Done = true, status != FleetLeased
		return out, nil
	}
	if status != FleetLeased {
		return out, ErrLeaseGone
	}
	if seq != last+1 {
		return out, fmt.Errorf("%w: %w: got %d, want %d", ErrInvalidBatch, ErrSequenceGap, seq, last+1)
	}
	var obs []observe.Observation
	var packets []observe.PacketEvidence
	var finish *observe.Scan
	for i, r := range records {
		if finish != nil {
			return out, fmt.Errorf("%w: records after scan finish", ErrInvalidBatch)
		}
		switch r.Kind {
		case FleetBegin:
			if scanID != "" {
				return out, fmt.Errorf("%w: scan already begun for this lease", ErrInvalidBatch)
			}
			if r.Scan.ID == "" {
				return out, fmt.Errorf("%w: begin record has no scan ID", ErrInvalidBatch)
			}
			scanID = r.Scan.ID
			var exists int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans WHERE id = ?`, r.Scan.ID).Scan(&exists); err != nil {
				return out, err
			}
			if exists > 0 {
				return out, fmt.Errorf("%w: scan ID %s already exists", ErrInvalidBatch, r.Scan.ID)
			}
			if err := beginScan(ctx, tx, r.Scan); err != nil {
				return out, fmt.Errorf("begin scan: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE fleet_attempts SET scan_id = ? WHERE lease_id = ?`, scanID, leaseID); err != nil {
				return out, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE fleet_units SET scan_id = ? WHERE job_id = ? AND idx = ? AND lease_id = ?`, scanID, jobID, idx, leaseID); err != nil {
				return out, err
			}
		case FleetObservation:
			if scanID == "" || r.Observation.ScanID != scanID {
				return out, fmt.Errorf("%w: record %d: observation does not belong to this lease's scan", ErrInvalidBatch, i)
			}
			obs = append(obs, r.Observation)
		case FleetPacketEvidence:
			if scanID == "" || r.Packets.ScanID != scanID {
				return out, fmt.Errorf("%w: record %d: packet evidence does not belong to this lease's scan", ErrInvalidBatch, i)
			}
			packets = append(packets, r.Packets)
		case FleetFinish:
			if scanID == "" || r.Scan.ID != scanID {
				return out, fmt.Errorf("%w: record %d: finish does not belong to this lease's scan", ErrInvalidBatch, i)
			}
			sc := r.Scan
			finish = &sc
		default:
			return out, fmt.Errorf("%w: record %d: unknown kind %d", ErrInvalidBatch, i, r.Kind)
		}
	}
	if len(obs) > 0 {
		if err := addObservationsTx(ctx, tx, obs); err != nil {
			return out, err
		}
	}
	if len(packets) > 0 {
		if err := addPacketEvidenceTx(ctx, tx, packets); err != nil {
			return out, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE fleet_attempts SET last_seq = ? WHERE lease_id = ?`, seq, leaseID); err != nil {
		return out, err
	}
	out.UnitStatus = FleetLeased
	if finish != nil {
		if err := finishScan(ctx, tx, *finish); err != nil {
			return out, fmt.Errorf("finish scan: %w", err)
		}
		out.Done = true
		if finish.Status == "completed" {
			if _, err := tx.ExecContext(ctx, `UPDATE fleet_attempts SET status = 'completed', finished_at = ? WHERE lease_id = ?`, ts(now), leaseID); err != nil {
				return out, err
			}
			// Totals come from what was stored, not from the agent's claim.
			var nObs, nSvc int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE kind = 'service') FROM observations WHERE scan_id = ?`, scanID).Scan(&nObs, &nSvc); err != nil {
				return out, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE fleet_units SET status = 'completed', lease_id = '', error = '', observations = ?, services = ?, updated_at = ?
				WHERE job_id = ? AND idx = ? AND lease_id = ?`, nObs, nSvc, ts(now), jobID, idx, leaseID); err != nil {
				return out, err
			}
		} else {
			reason := finish.Error
			if reason == "" {
				reason = "scan " + finish.Status
			}
			if _, err := tx.ExecContext(ctx, `UPDATE fleet_attempts SET status = 'failed', error = ?, finished_at = ? WHERE lease_id = ?`, reason, ts(now), leaseID); err != nil {
				return out, err
			}
			if err := retryOrFailUnit(ctx, tx, jobID, idx, leaseID, reason, now); err != nil {
				return out, err
			}
		}
		if err := tx.QueryRowContext(ctx, `SELECT status FROM fleet_units WHERE job_id = ? AND idx = ?`, jobID, idx).Scan(&out.UnitStatus); err != nil {
			return out, err
		}
		if out.JobFinished, err = finishJobIfDone(ctx, tx, jobID, now); err != nil {
			return out, err
		}
	}
	return out, tx.Commit()
}

// CancelFleetJob stops a running job: pending units are canceled at once and
// the returned open leases must be canceled on their agents. Their Finish
// records still arrive and are stored, and those units end canceled.
func (s *Store) CancelFleetJob(ctx context.Context, id string, now time.Time) (leases []FleetAttempt, ok bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE fleet_jobs SET status = 'canceled', error = 'canceled by operator' WHERE id = ? AND status = 'running'`, id)
	if err != nil {
		return nil, false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, false, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE fleet_units SET status = 'canceled', updated_at = ? WHERE job_id = ? AND status = 'pending'`, ts(now), id); err != nil {
		return nil, false, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT lease_id, agent_id FROM fleet_attempts WHERE job_id = ? AND status = 'leased'`, id)
	if err != nil {
		return nil, false, err
	}
	for rows.Next() {
		var a FleetAttempt
		if err := rows.Scan(&a.LeaseID, &a.AgentID); err != nil {
			rows.Close()
			return nil, false, err
		}
		a.JobID, a.Status = id, FleetLeased
		leases = append(leases, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if _, err := finishJobIfDone(ctx, tx, id, now); err != nil {
		return nil, false, err
	}
	return leases, true, tx.Commit()
}

// ExpiredFleetLeases lists open leases whose expiry is before now.
func (s *Store) ExpiredFleetLeases(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT lease_id FROM fleet_attempts WHERE status = 'leased' AND expires_at < ?`, ts(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
