package horizon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/packetio"
)

func testAudit(t *testing.T) (*Audit, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := OpenAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a, path
}

func TestAuditChainDetectsTamperingAndResumes(t *testing.T) {
	t.Parallel()
	a, path := testAudit(t)
	for i := 0; i < 3; i++ {
		if err := a.Record(AuditEntry{Actor: "test", Action: "run.create", Outcome: "accepted"}); err != nil {
			t.Fatal(err)
		}
	}
	a.Close()
	if err := a.Record(AuditEntry{Action: "x"}); err == nil {
		t.Fatal("closed audit accepted an entry")
	}
	b, _ := os.ReadFile(path)
	if n, err := VerifyAudit(bytes.NewReader(b)); err != nil || n != 3 {
		t.Fatalf("verify: %d %v", n, err)
	}
	// Resuming continues the chain.
	again, err := OpenAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Record(AuditEntry{Actor: "test", Action: "kill-switch", Outcome: "engaged"}); err != nil {
		t.Fatal(err)
	}
	again.Close()
	b, _ = os.ReadFile(path)
	if n, err := VerifyAudit(bytes.NewReader(b)); err != nil || n != 4 {
		t.Fatalf("resumed chain: %d %v", n, err)
	}
	lines := strings.SplitAfter(string(b), "\n")
	for name, tampered := range map[string]string{
		"edited":   strings.Replace(string(b), `"accepted"`, `"refused"`, 1),
		"deleted":  lines[0] + strings.Join(lines[2:], ""),
		"reorder":  lines[1] + lines[0] + strings.Join(lines[2:], ""),
		"unknown":  strings.Replace(string(b), `"actor"`, `"extra":1,"actor"`, 1),
		"too long": string(b) + strings.Repeat("x", maxAuditLine+1) + "\n",
	} {
		if _, err := VerifyAudit(strings.NewReader(tampered)); err == nil {
			t.Fatalf("%s audit accepted", name)
		}
		bad := filepath.Join(t.TempDir(), "audit.jsonl")
		os.WriteFile(bad, []byte(tampered), 0o600)
		if _, err := OpenAudit(bad); err == nil {
			t.Fatalf("%s audit reopened", name)
		}
	}
	if runtime.GOOS != "windows" {
		loose := filepath.Join(t.TempDir(), "audit.jsonl")
		os.WriteFile(loose, nil, 0o600)
		os.Chmod(loose, 0o666)
		if _, err := OpenAudit(loose); err == nil {
			t.Fatal("world-writable audit file accepted")
		}
	}
}

func TestModeOf(t *testing.T) {
	t.Parallel()
	for file, want := range map[string]string{"hz-001.yaml": ModeResolve, "hz-002.yaml": ModeRecognize, "sequence-v1alpha2.yaml": ModeReconstruct, "cross-port/main.yaml": ModeReconstruct, "cross-port/same-port.yaml": ModeReconstruct} {
		if got := ModeOf(loadExperiment(t, "../../lab/horizon/"+file)); got != want {
			t.Errorf("%s: %s, want %s", file, got, want)
		}
	}
}

func syntheticController(scenario string, policy model.Policy) *Controller {
	return NewController(policy, testLink(), func() (packetio.PacketIO, error) { return NewSimulator(scenario) })
}

func newTestRuns(t *testing.T, scenario string, policy model.Policy, cfg RunsConfig) (*Runs, *Controller, string) {
	t.Helper()
	a, path := testAudit(t)
	ctrl := syntheticController(scenario, policy)
	cfg.Audit = a
	if cfg.Metrics == nil {
		cfg.Metrics = NewMetrics()
	}
	s, err := NewRuns(ctrl, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close(); ctrl.Close() })
	return s, ctrl, path
}

func waitRun(t *testing.T, s *Runs, id string) model.RunStatus {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.Get(id)
		if err != nil {
			t.Fatal(err)
		}
		if st.State != "running" {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("run did not finish")
	return model.RunStatus{}
}

func auditActions(t *testing.T, path string) []string {
	t.Helper()
	b, _ := os.ReadFile(path)
	if _, err := VerifyAudit(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		i := strings.Index(line, `"action":"`) + len(`"action":"`)
		out = append(out, line[i:i+strings.Index(line[i:], `"`)])
	}
	return out
}

func TestRunsModesAreExplicitOptIn(t *testing.T) {
	t.Parallel()
	s, _, path := newTestRuns(t, "shared-limit", crossPortPolicy(), RunsConfig{})
	main := fastRole(t, RoleMain)
	if _, err := s.Create("test", ModeReconstruct, main); !errors.Is(err, ErrModeDisabled) {
		t.Fatalf("reconstruct ran by default: %v", err)
	}
	if _, err := s.Create("test", ModeResolve, main); !errors.Is(err, ErrModeMismatch) {
		t.Fatalf("mode laundering accepted: %v", err)
	}
	if _, err := s.Resolve(context.Background(), "test", main); !errors.Is(err, ErrModeDisabled) {
		t.Fatalf("synchronous resolve bypassed modes: %v", err)
	}
	if got := auditActions(t, path); len(got) != 3 || got[0] != "denied" || got[2] != "denied" {
		t.Fatalf("audit %v", got)
	}
	if _, err := NewRuns(syntheticController("stable", crossPortPolicy()), RunsConfig{}); err == nil {
		t.Fatal("runs without an audit trail")
	}
	if _, err := NewRuns(syntheticController("stable", crossPortPolicy()), RunsConfig{Audit: &Audit{}, Modes: []string{"explore"}}); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

func TestRunsLifecycleExportAndMetrics(t *testing.T) {
	t.Parallel()
	s, _, path := newTestRuns(t, "shared-limit", crossPortPolicy(), RunsConfig{Modes: Modes})
	st, err := s.Create("test", ModeReconstruct, fastRole(t, RoleMain))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Report(st.ID); !errors.Is(err, ErrRunActive) {
		t.Fatalf("report of a running run: %v", err)
	}
	if _, err := s.Create("test", ModeReconstruct, fastRole(t, RoleMain)); !errors.Is(err, ErrBusy) {
		t.Fatalf("second concurrent run: %v", err)
	}
	done := waitRun(t, s, st.ID)
	if done.State != "completed" || done.Comparison == nil || done.ReportSHA256 == "" || done.PacketsTX == 0 {
		t.Fatalf("finished %+v", done)
	}
	env, err := s.Report(st.ID)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, env.Report)
	if _, err := s.Graph(st.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Cancel("test", st.ID); !errors.Is(err, ErrRunFinished) {
		t.Fatalf("cancel after finish: %v", err)
	}
	var b bytes.Buffer
	s.Metrics().WritePrometheus(&b)
	for _, want := range []string{`nyxr_horizon_runs_total{mode="reconstruct",state="completed"} 1`, `nyxr_horizon_admission_denied_total{reason="busy"} 1`, "nyxr_horizon_active_runs 0"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("metrics missing %q:\n%s", want, b.String())
		}
	}
	if got := auditActions(t, path); strings.Join(got, ",") != "run.create,run.create,run.finish,run.finish" {
		t.Fatalf("audit %v", got)
	}
}

func TestRunsFailClosedWithoutAudit(t *testing.T) {
	t.Parallel()
	s, ctrl, _ := newTestRuns(t, "stable", crossPortPolicy(), RunsConfig{Modes: Modes})
	s.cfg.Audit.Close()
	if _, err := s.Create("test", ModeReconstruct, fastRole(t, RoleMain)); err == nil {
		t.Fatal("run started without an audit entry")
	}
	ctrl.mu.Lock()
	running := ctrl.running
	ctrl.mu.Unlock()
	if running || len(s.List()) != 0 {
		t.Fatal("traffic started without audit")
	}
}

func TestRunsCancellationAndKillSwitchRaces(t *testing.T) {
	t.Parallel()
	s, ctrl, path := newTestRuns(t, "stable", crossPortPolicy(), RunsConfig{Modes: Modes})
	st, err := s.Create("test", ModeReconstruct, fastRole(t, RoleMain))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); s.Cancel("test", st.ID) }()
		go func() { defer wg.Done(); s.List(); s.Get(st.ID); s.Report(st.ID) }()
		go func() { defer wg.Done(); s.Create("test", ModeReconstruct, fastRole(t, RoleMain)) }()
	}
	wg.Wait()
	done := waitRun(t, s, st.ID)
	if done.State != "cancelled" {
		t.Fatalf("cancelled run state %s", done.State)
	}
	// A cancelled run keeps partial, replayable evidence.
	if env, err := s.Report(st.ID); err == nil {
		roundTrip(t, env.Report)
	} else if !errors.Is(err, ErrNoReport) {
		t.Fatal(err)
	}
	// A racing Create may have started once the slot was free: drain it.
	for _, r := range s.List() {
		if r.State == "running" {
			s.Cancel("test", r.ID)
			waitRun(t, s, r.ID)
		}
	}
	// Cancelling one run leaves the controller usable.
	next, err := s.Create("test", ModeReconstruct, fastRole(t, RoleMain))
	if err != nil {
		t.Fatal(err)
	}
	var kill sync.WaitGroup
	for i := 0; i < 4; i++ {
		kill.Add(1)
		go func() { defer kill.Done(); s.Stop("test") }()
	}
	kill.Wait()
	if st := waitRun(t, s, next.ID); st.State != "stopped" {
		t.Fatalf("kill switch state %s", st.State)
	}
	if _, err := s.Create("test", ModeReconstruct, fastRole(t, RoleMain)); !errors.Is(err, ErrStopped) {
		t.Fatalf("run after kill switch: %v", err)
	}
	if !ctrl.Stopped() {
		t.Fatal("kill switch not engaged")
	}
	auditActions(t, path) // the chain stays valid under concurrent writers
}

func TestRunsRetentionIsBounded(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	s, _, _ := newTestRuns(t, "stable", crossPortPolicy(), RunsConfig{Modes: Modes, MaxRuns: 2, Retention: time.Hour, Now: clock})
	var ids []string
	for i := 0; i < 3; i++ {
		st, err := s.Create("test", ModeReconstruct, fastRole(t, RoleMain))
		if err != nil {
			t.Fatal(err)
		}
		waitRun(t, s, st.ID)
		ids = append(ids, st.ID)
	}
	if got := s.List(); len(got) != 2 || got[0].ID != ids[2] || got[1].ID != ids[1] {
		t.Fatalf("retained %v", got)
	}
	mu.Lock()
	now = now.Add(2 * time.Hour)
	mu.Unlock()
	if got := s.List(); len(got) != 0 {
		t.Fatalf("expired runs retained: %d", len(got))
	}
	if _, err := s.Get(ids[2]); !errors.Is(err, ErrNoRun) {
		t.Fatal(err)
	}
	for _, bad := range []RunsConfig{{MaxRuns: 65}, {Retention: time.Second}} {
		bad.Audit = s.cfg.Audit
		if _, err := NewRuns(syntheticController("stable", crossPortPolicy()), bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

// Security review fixes.
func TestAuditFailureLatchesAndHidesDetails(t *testing.T) {
	t.Parallel()
	s, _, path := newTestRuns(t, "stable", crossPortPolicy(), RunsConfig{Modes: Modes})
	// Make the next write fail: swap in a read-only handle on the same file.
	ro, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.cfg.Audit.mu.Lock()
	rw := s.cfg.Audit.file
	s.cfg.Audit.file = ro
	s.cfg.Audit.mu.Unlock()
	defer rw.Close()
	_, err = s.Create("test", ModeReconstruct, fastRole(t, RoleMain))
	if !errors.Is(err, ErrAuditUnavailable) || strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "/") {
		t.Fatalf("audit failure leaked or was not reported: %v", err)
	}
	// Even with a working file again, the latched trail refuses runs.
	s.cfg.Audit.mu.Lock()
	s.cfg.Audit.file = rw
	s.cfg.Audit.mu.Unlock()
	if _, err := s.Create("test", ModeReconstruct, fastRole(t, RoleMain)); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("run after a failed audit write: %v", err)
	}
	var b bytes.Buffer
	s.Metrics().WritePrometheus(&b)
	if !strings.Contains(b.String(), "nyxr_horizon_audit_failures_total 2") {
		t.Fatal(b.String())
	}
	s.cfg.Audit.mu.Lock()
	s.cfg.Audit.file = ro
	s.cfg.Audit.mu.Unlock()
}

func TestDeniedAuditEntriesAreRateLimited(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	s, _, path := newTestRuns(t, "stable", crossPortPolicy(), RunsConfig{Now: clock})
	for i := 0; i < 100; i++ {
		s.Create("test", ModeReconstruct, fastRole(t, RoleMain))
	}
	if got := len(auditActions(t, path)); got != deniedPerMinute {
		t.Fatalf("%d denied entries recorded", got)
	}
	mu.Lock()
	now = now.Add(time.Minute)
	mu.Unlock()
	s.Create("test", ModeReconstruct, fastRole(t, RoleMain))
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "70 earlier refusals not recorded") {
		t.Fatal("suppressed refusals not summarized")
	}
	var m bytes.Buffer
	s.Metrics().WritePrometheus(&m)
	if !strings.Contains(m.String(), `nyxr_horizon_admission_denied_total{reason="mode-disabled"} 101`) {
		t.Fatal(m.String())
	}
}

func TestAuditFileHasOneWriter(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("advisory lock is Unix-only")
	}
	_, path := testAudit(t)
	if _, err := OpenAudit(path); err == nil {
		t.Fatal("a second writer opened the audit file")
	}
}

func TestMultiProbeSequencesAreReconstruct(t *testing.T) {
	t.Parallel()
	e := loadExperiment(t, "../../lab/horizon/hz-001.yaml")
	if ModeOf(e) != ModeResolve {
		t.Fatal("single-probe HZ-001 is not resolve")
	}
	general := loadExperiment(t, "../../lab/horizon/sequence-v1alpha2.yaml")
	general.Spec.CrossPort = false
	if ModeOf(general) != ModeReconstruct {
		t.Fatal("a multi-probe sequence is not reconstruct")
	}
	general.Spec.Treatment.Steps = []model.Step{{Repeat: &model.Repeat{Count: 3, Steps: general.Spec.Control.Steps[:1]}}}
	if sends(general.Spec.Treatment.Steps) < 2 || ModeOf(general) != ModeReconstruct {
		t.Fatal("repeated sends are not reconstruct")
	}
}
