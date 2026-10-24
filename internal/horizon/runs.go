package horizon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/matusso/nyxr/internal/horizon/model"
)

// Modes order HORIZON work by how much target state an experiment touches.
// The operator enables modes; every request names one, and it must match.
const (
	ModeRecognize   = "recognize"   // A/A observation: identical baseline arms
	ModeResolve     = "resolve"     // one controlled variable on one flow (HZ-001, sequences)
	ModeReconstruct = "reconstruct" // precondition flows and cross-port state (HZ-003/HZ-004)
)

var Modes = []string{ModeRecognize, ModeResolve, ModeReconstruct}

// DefaultModes never includes reconstruct: deeper modes are explicit opt-in.
var DefaultModes = []string{ModeRecognize, ModeResolve}

var (
	ErrModeDisabled = errors.New("HORIZON mode is not enabled by the operator")
	ErrModeMismatch = errors.New("experiment does not match the requested HORIZON mode")
	ErrNoRun        = errors.New("no such HORIZON run")
	ErrRunActive    = errors.New("HORIZON run is still active")
	ErrRunFinished  = errors.New("HORIZON run already finished")
	ErrNoReport     = errors.New("HORIZON run produced no report")
)

// ModeOf classifies an experiment by the deepest state it manipulates. Any
// arm that sends more than one probe can set up flow state before measuring,
// so it is reconstruct whatever its declared changed variable.
func ModeOf(e model.Experiment) string {
	switch {
	case e.Spec.CrossPort || e.Spec.ChangedVariable == "precondition" || sends(e.Spec.Control.Steps) > 1 || sends(e.Spec.Treatment.Steps) > 1:
		return ModeReconstruct
	case e.Spec.ChangedVariable == "none":
		return ModeRecognize
	}
	return ModeResolve
}

// sends counts probes in a sequence, expanding bounded repeats.
func sends(steps []model.Step) int {
	n := 0
	for _, s := range steps {
		switch {
		case s.Send != nil:
			n++
		case s.Repeat != nil:
			n += min(max(s.Repeat.Count, 0), 64) * sends(s.Repeat.Steps)
		}
		if n > 1 {
			return n
		}
	}
	return n
}

// MaxRetainedRuns bounds in-memory reports (each at most its capture budget,
// 8 MiB, plus encoding overhead): roughly 200 MiB in the worst case.
const MaxRetainedRuns = 16

// deniedPerMinute rate-limits refusal entries in the audit trail; the metric
// still counts every refusal, and the next entry states how many were skipped.
const deniedPerMinute = 30

// RunsConfig bounds the run service. Audit is mandatory.
type RunsConfig struct {
	Modes     []string
	Audit     *Audit
	Metrics   *Metrics
	MaxRuns   int           // retained runs, 1..MaxRetainedRuns (default 8)
	Retention time.Duration // finished runs older than this are dropped (default 24h)
	Now       func() time.Time
}

// Runs executes HORIZON experiments for the API: one at a time through the
// controller, each audited before any traffic, with bounded retention.
type Runs struct {
	ctrl  *Controller
	cfg   RunsConfig
	modes map[string]bool
	mu    sync.Mutex
	runs  map[string]*runEntry
	order []string
	wg    sync.WaitGroup

	deniedWindow     time.Time
	deniedInWindow   int
	deniedSuppressed int
}

type runEntry struct {
	status   model.RunStatus
	envelope *model.Envelope
	exec     *Execution
}

func NewRuns(ctrl *Controller, cfg RunsConfig) (*Runs, error) {
	if ctrl == nil || cfg.Audit == nil {
		return nil, errors.New("HORIZON runs need a controller and an audit trail")
	}
	if cfg.MaxRuns == 0 {
		cfg.MaxRuns = 8
	}
	if cfg.Retention == 0 {
		cfg.Retention = 24 * time.Hour
	}
	if cfg.MaxRuns < 1 || cfg.MaxRuns > MaxRetainedRuns || cfg.Retention < time.Minute {
		return nil, fmt.Errorf("HORIZON run retention needs 1..%d runs and at least one minute", MaxRetainedRuns)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Modes == nil {
		cfg.Modes = DefaultModes
	}
	s := &Runs{ctrl: ctrl, cfg: cfg, modes: map[string]bool{}, runs: map[string]*runEntry{}}
	for _, m := range cfg.Modes {
		if !slices.Contains(Modes, m) {
			return nil, fmt.Errorf("unknown HORIZON mode %q", m)
		}
		s.modes[m] = true
	}
	return s, nil
}

// EnabledModes lists the operator-enabled modes in canonical order.
func (s *Runs) EnabledModes() []string {
	var out []string
	for _, m := range Modes {
		if s.modes[m] {
			out = append(out, m)
		}
	}
	return out
}

func (s *Runs) Metrics() *Metrics { return s.cfg.Metrics }

// Plan compiles under the operator policy without opening a transport.
func (s *Runs) Plan(e model.Experiment) (model.Plan, error) { return s.ctrl.Plan(e) }

// record writes an audit entry, counting failures. After a failed write the
// trail refuses all further entries, so no later run can start.
func (s *Runs) record(a AuditEntry) error {
	if err := s.cfg.Audit.Record(a); err != nil {
		s.cfg.Metrics.AuditFailure()
		return ErrAuditUnavailable
	}
	return nil
}

func newRunID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func auditFor(actor, action, mode string, e model.Experiment, hash string) AuditEntry {
	a := AuditEntry{Actor: actor, Action: action, Mode: mode, ExperimentHash: hash, Ports: slices.Clone(e.Spec.Scope.TCPPorts)}
	if len(e.Spec.Scope.Targets) > 0 {
		a.Target = e.Spec.Scope.Targets[0]
	}
	return a
}

// admit checks mode and policy before any traffic and audits refusals.
func (s *Runs) admit(actor, mode string, e model.Experiment) (model.Plan, error) {
	deny := func(reason string, err error) (model.Plan, error) {
		s.cfg.Metrics.Denied(reason)
		s.mu.Lock()
		now := s.cfg.Now()
		if now.Sub(s.deniedWindow) >= time.Minute {
			s.deniedWindow, s.deniedInWindow = now, 0
		}
		s.deniedInWindow++
		record := s.deniedInWindow <= deniedPerMinute
		suppressed := 0
		if record {
			suppressed, s.deniedSuppressed = s.deniedSuppressed, 0
		} else {
			s.deniedSuppressed++
		}
		s.mu.Unlock()
		if record {
			a := auditFor(actor, "denied", mode, e, "")
			a.Outcome, a.Detail = reason, err.Error()
			if suppressed > 0 {
				a.Detail += fmt.Sprintf(" (%d earlier refusals not recorded: rate limit)", suppressed)
			}
			s.record(a)
		}
		return model.Plan{}, err
	}
	if !s.modes[mode] {
		return deny("mode-disabled", fmt.Errorf("%w: %q (enabled: %v)", ErrModeDisabled, mode, s.EnabledModes()))
	}
	if got := ModeOf(e); got != mode {
		return deny("mode-mismatch", fmt.Errorf("%w: experiment is %s, request is %s", ErrModeMismatch, got, mode))
	}
	p, err := s.ctrl.Plan(e)
	if errors.Is(err, ErrStopped) {
		return deny("stopped", err)
	}
	if err != nil {
		return deny("policy", err)
	}
	return p, nil
}

// Create admits, audits and starts a run in the background. Nothing is sent
// unless the audit entry for it was durably written.
func (s *Runs) Create(actor, mode string, e model.Experiment) (model.RunStatus, error) {
	p, err := s.admit(actor, mode, e)
	if err != nil {
		return model.RunStatus{}, err
	}
	id := newRunID()
	a := auditFor(actor, "run.create", mode, e, p.Hash)
	a.RunID, a.Outcome = id, "accepted"
	if err := s.record(a); err != nil {
		s.cfg.Metrics.Denied("audit")
		return model.RunStatus{}, fmt.Errorf("%w; run refused", err)
	}
	x, err := s.ctrl.Start(context.Background(), e)
	if err != nil {
		reason := "busy"
		if errors.Is(err, ErrStopped) {
			reason = "stopped"
		}
		s.cfg.Metrics.Denied(reason)
		a.Action, a.Outcome, a.Detail = "run.finish", "refused", err.Error()
		s.record(a)
		return model.RunStatus{}, err
	}
	s.cfg.Metrics.Started()
	st := model.RunStatus{APIVersion: model.RunVersion, Kind: "HorizonRun", ID: id, Mode: mode, State: "running", Experiment: e.Metadata.Name,
		ExperimentHash: p.Hash, Target: a.Target, Ports: a.Ports, CreatedAt: s.cfg.Now().UTC()}
	entry := &runEntry{status: st, exec: x}
	s.mu.Lock()
	s.evictLocked(true)
	s.runs[id] = entry
	s.order = append(s.order, id)
	s.mu.Unlock()
	s.wg.Add(1)
	go s.finish(actor, entry, e)
	return st, nil
}

func (s *Runs) finish(actor string, entry *runEntry, e model.Experiment) {
	defer s.wg.Done()
	report, err := entry.exec.Result()
	state := "completed"
	switch {
	case err == nil && report.Completed:
	case s.ctrl.Stopped():
		state = "stopped"
	case errors.Is(err, context.Canceled):
		state = "cancelled"
	default:
		state = "failed"
	}
	var envelope *model.Envelope
	if report.APIVersion != "" {
		if sealed, sealErr := Seal(report); sealErr == nil {
			envelope = &sealed
		} else {
			err = errors.Join(err, sealErr)
			state = "failed"
		}
	}
	s.cfg.Metrics.Finished(entry.status.Mode, state, report)
	now := s.cfg.Now().UTC()
	s.mu.Lock()
	st := &entry.status
	st.State, st.FinishedAt, st.PacketsTX, st.Trials, st.StopReason = state, &now, report.PacketsTX, len(report.Trials), report.StopReason
	if err != nil {
		st.Error = err.Error()
	}
	if envelope != nil {
		c := report.Comparison
		st.Comparison, st.Curtailment, st.ReportSHA256 = &c, report.Curtailment, envelope.SHA256
		entry.envelope = envelope
	}
	entry.exec = nil
	a := auditFor(actor, "run.finish", st.Mode, e, st.ExperimentHash)
	a.RunID, a.Outcome, a.Detail = st.ID, state, fmt.Sprintf("packets=%d trials=%d report=%s", st.PacketsTX, st.Trials, st.ReportSHA256)
	s.mu.Unlock()
	// The run already happened; a failed write is counted and latches the
	// trail, so no further run starts.
	s.record(a)
}

// evictLocked drops finished runs past retention and, when making room for a
// new run, the oldest finished runs until a slot is free. Running runs are
// never dropped.
func (s *Runs) evictLocked(makeRoom bool) {
	now := s.cfg.Now()
	keep := s.order[:0]
	for _, id := range s.order {
		r := s.runs[id]
		if r.status.FinishedAt != nil && now.Sub(*r.status.FinishedAt) > s.cfg.Retention {
			delete(s.runs, id)
			continue
		}
		keep = append(keep, id)
	}
	s.order = keep
	for i := 0; makeRoom && len(s.order) >= s.cfg.MaxRuns && i < len(s.order); {
		if s.runs[s.order[i]].status.FinishedAt == nil {
			i++
			continue
		}
		delete(s.runs, s.order[i])
		s.order = slices.Delete(s.order, i, i+1)
	}
}

func (s *Runs) Get(id string) (model.RunStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictLocked(false)
	r, ok := s.runs[id]
	if !ok {
		return model.RunStatus{}, ErrNoRun
	}
	return r.status, nil
}

// List returns retained runs, newest first.
func (s *Runs) List() []model.RunStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictLocked(false)
	out := []model.RunStatus{}
	for i := len(s.order) - 1; i >= 0; i-- {
		out = append(out, s.runs[s.order[i]].status)
	}
	return out
}

// Cancel stops one active run; the controller and other runs are unaffected.
func (s *Runs) Cancel(actor, id string) (model.RunStatus, error) {
	s.mu.Lock()
	r, ok := s.runs[id]
	if !ok {
		s.mu.Unlock()
		return model.RunStatus{}, ErrNoRun
	}
	st, x := r.status, r.exec
	s.mu.Unlock()
	if x == nil {
		return st, ErrRunFinished
	}
	x.Cancel()
	a := AuditEntry{Actor: actor, Action: "run.cancel", RunID: id, Mode: st.Mode, ExperimentHash: st.ExperimentHash, Target: st.Target, Ports: st.Ports, Outcome: "requested"}
	return st, s.record(a)
}

// Report returns a finished run's sealed evidence.
func (s *Runs) Report(id string) (model.Envelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[id]
	switch {
	case !ok:
		return model.Envelope{}, ErrNoRun
	case r.exec != nil:
		return model.Envelope{}, ErrRunActive
	case r.envelope == nil:
		return model.Envelope{}, ErrNoReport
	}
	return *r.envelope, nil
}

// Graph projects one finished run into an evidence graph.
func (s *Runs) Graph(id string) (model.Graph, error) {
	e, err := s.Report(id)
	if err != nil {
		return model.Graph{}, err
	}
	return BuildGraph(GraphInput{Reports: []model.Envelope{e}, Now: s.cfg.Now().UTC(), TTL: 24 * time.Hour})
}

// Resolve runs synchronously (the original /resolve endpoint) under the same
// mode, policy and audit rules as Create.
func (s *Runs) Resolve(ctx context.Context, actor string, e model.Experiment) (model.Report, error) {
	mode := ModeOf(e)
	p, err := s.admit(actor, mode, e)
	if err != nil {
		return model.Report{}, err
	}
	a := auditFor(actor, "resolve", mode, e, p.Hash)
	a.Outcome = "accepted"
	if err := s.record(a); err != nil {
		s.cfg.Metrics.Denied("audit")
		return model.Report{}, fmt.Errorf("%w; run refused", err)
	}
	x, err := s.ctrl.Start(ctx, e)
	if err != nil {
		reason := "busy"
		if errors.Is(err, ErrStopped) {
			reason = "stopped"
		}
		s.cfg.Metrics.Denied(reason)
		a.Action, a.Outcome, a.Detail = "run.finish", "refused", err.Error()
		s.record(a)
		return model.Report{}, err
	}
	s.cfg.Metrics.Started()
	report, err := x.Result()
	state := "completed"
	switch {
	case err == nil && report.Completed:
	case s.ctrl.Stopped():
		state = "stopped"
	case errors.Is(err, context.Canceled):
		state = "cancelled"
	default:
		state = "failed"
	}
	s.cfg.Metrics.Finished(mode, state, report)
	a.Action, a.Outcome, a.Detail = "run.finish", state, fmt.Sprintf("packets=%d trials=%d", report.PacketsTX, len(report.Trials))
	s.record(a)
	return report, err
}

// Stop engages the controller's kill switch.
func (s *Runs) Stop(actor string) error {
	s.ctrl.Stop()
	s.cfg.Metrics.KillSwitch()
	return s.record(AuditEntry{Actor: actor, Action: "kill-switch", Outcome: "engaged"})
}

// Close cancels active runs and waits for their results to be recorded.
func (s *Runs) Close() {
	s.mu.Lock()
	for _, r := range s.runs {
		if r.exec != nil {
			r.exec.Cancel()
		}
	}
	s.mu.Unlock()
	s.wg.Wait()
}
