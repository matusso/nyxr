package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/packetio"
	"github.com/matusso/nyxr/internal/pipeline"
	"github.com/matusso/nyxr/internal/storage"
)

// ErrBusy means the running-scan limit is reached.
var ErrBusy = errors.New("scan limit reached; wait for a running scan to finish")

// ManagerConfig configures scan execution for the API.
type ManagerConfig struct {
	Store *storage.Store
	// OpenLive is the packetd client opener. Nil means this process has no
	// raw packet access, and requests that need it are refused.
	OpenLive packetio.Opener
	// EvidenceDir holds pcapng files requested through the API. Empty
	// disables capture requests.
	EvidenceDir string
	// MaxRunning bounds concurrent scans (default 1) so scans do not
	// silently exceed each other's rate budgets.
	MaxRunning int
	// Pipeline adjusts pipeline options before a run; tests use it to
	// replace discovery.
	Pipeline func(*pipeline.Options)
}

// Manager runs scans through the same Request.Resolve and pipeline mapping
// as the CLI and keeps a live event hub for each running scan.
type Manager struct {
	cfg  ManagerConfig
	mu   sync.Mutex
	runs map[string]*run
	wg   sync.WaitGroup
	ctx  context.Context
	stop context.CancelFunc
}

type run struct {
	mu      sync.Mutex
	summary observe.Scan
	hub     *hub
	cancel  context.CancelFunc
	done    chan struct{}
}

func (r *run) snapshot() observe.Scan {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.summary
}

func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Store == nil {
		return nil, errors.New("API requires a store")
	}
	if cfg.MaxRunning <= 0 {
		cfg.MaxRunning = 1
	}
	ctx, stop := context.WithCancel(context.Background())
	return &Manager{cfg: cfg, runs: map[string]*run{}, ctx: ctx, stop: stop}, nil
}

// Resolve validates a remote request and applies this process's
// capabilities. The returned plan is exactly what Start would run.
func (m *Manager) Resolve(req config.Request) (config.Resolved, error) {
	r, err := req.Resolve(config.ResolveOptions{Remote: true, KnownOpen: func() ([]config.KnownPort, error) {
		return m.cfg.Store.KnownOpen(m.ctx)
	}})
	if err != nil {
		return r, err
	}
	c := r.Config
	if c.Profile == "research" {
		// Malformed and forged packets stay behind an operator at the CLI
		// until scan approvals exist (Phase 9).
		return r, errors.New("the research profile is CLI-only; the API does not send forged packets")
	}
	if m.cfg.OpenLive == nil && (c.TCPMode == "syn" || c.ARP || c.NDP || r.PCAPNG != "") {
		return r, errors.New("raw SYN, ARP/NDP and pcapng capture need nyxr-packetd (start the server with --packetd)")
	}
	if c.ICMP {
		// ICMP echo uses a raw IP socket in the calling process, which the
		// unprivileged API process does not have.
		return r, errors.New("ICMP echo is not available through the unprivileged API yet; use the CLI")
	}
	if r.PCAPNG != "" {
		if m.cfg.EvidenceDir == "" {
			return r, errors.New("pcapng capture needs a server evidence directory (--evidence-dir)")
		}
		r.PCAPNG = filepath.Join(m.cfg.EvidenceDir, r.PCAPNG)
	}
	return r, nil
}

// Start resolves and launches a scan, returning its initial summary.
func (m *Manager) Start(req config.Request) (observe.Scan, error) {
	r, err := m.Resolve(req)
	if err != nil {
		return observe.Scan{}, err
	}
	if r.PCAPNG != "" {
		if _, err := os.Lstat(r.PCAPNG); err == nil {
			return observe.Scan{}, fmt.Errorf("capture %s already exists", filepath.Base(r.PCAPNG))
		}
	}
	m.mu.Lock()
	if m.ctx.Err() != nil {
		m.mu.Unlock()
		return observe.Scan{}, errors.New("server is shutting down")
	}
	if len(m.runs) >= m.cfg.MaxRunning {
		m.mu.Unlock()
		return observe.Scan{}, ErrBusy
	}
	ctx, cancel := context.WithCancel(m.ctx)
	rn := &run{hub: newHub(), cancel: cancel, done: make(chan struct{})}
	opts := pipeline.FromResolved(r)
	opts.OpenLive = m.cfg.OpenLive
	opts.Sinks = []pipeline.Sink{pipeline.NewStoreSink(ctx, m.cfg.Store), &liveSink{run: rn}}
	if m.cfg.Pipeline != nil {
		m.cfg.Pipeline(&opts)
	}
	begun := make(chan observe.Scan, 1)
	opts.Sinks = append(opts.Sinks, beginSink(func(sc observe.Scan) {
		m.mu.Lock()
		m.runs[sc.ID] = rn
		m.mu.Unlock()
		begun <- sc
	}))
	// Reserve the slot until Begin registers the run under its ID.
	placeholder := fmt.Sprintf("\x00pending-%p", rn)
	m.runs[placeholder] = rn
	m.mu.Unlock()

	failed := make(chan error, 1)
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer cancel()
		sc, err := pipeline.Run(ctx, r.Config, opts)
		m.mu.Lock()
		delete(m.runs, placeholder)
		if sc.ID != "" {
			delete(m.runs, sc.ID)
		}
		m.mu.Unlock()
		rn.hub.close()
		close(rn.done)
		if sc.ID == "" {
			failed <- err
		}
	}()
	select {
	case sc := <-begun:
		m.mu.Lock()
		delete(m.runs, placeholder)
		m.mu.Unlock()
		return sc, nil
	case err := <-failed:
		if err == nil {
			err = errors.New("scan did not start")
		}
		return observe.Scan{}, err
	}
}

// Running lists live summaries, newest first.
func (m *Manager) Running() []observe.Scan {
	m.mu.Lock()
	var out []observe.Scan
	for id, r := range m.runs {
		if id[0] != 0 {
			out = append(out, r.snapshot())
		}
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

func (m *Manager) lookup(id string) *run {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runs[id]
}

// Cancel stops a running scan; partial results are kept.
func (m *Manager) Cancel(id string) bool {
	r := m.lookup(id)
	if r == nil {
		return false
	}
	r.cancel()
	return true
}

// Close cancels running scans and waits for them to record their results.
func (m *Manager) Close() {
	m.mu.Lock()
	m.stop()
	m.mu.Unlock()
	m.wg.Wait()
}

// liveSink keeps the running summary current and publishes every record.
type liveSink struct{ run *run }

func (s *liveSink) Begin(sc observe.Scan) error {
	s.run.mu.Lock()
	s.run.summary = sc
	s.run.mu.Unlock()
	s.run.hub.publish(observe.KindScan, publicScan(sc))
	return nil
}

func (s *liveSink) Observation(o observe.Observation) error {
	s.run.mu.Lock()
	s.run.summary.Observations++
	if o.Kind == observe.KindService && o.Fingerprint == observe.FingerprintMatched {
		s.run.summary.Services++
	}
	s.run.mu.Unlock()
	s.run.hub.publish("observation", o)
	return nil
}

func (s *liveSink) PacketEvidence(p observe.PacketEvidence) error {
	p.Capture = filepath.Base(p.Capture)
	s.run.hub.publish(observe.KindPacketEvidence, p)
	return nil
}

func (s *liveSink) Finish(sc observe.Scan) error {
	s.run.mu.Lock()
	s.run.summary = sc
	s.run.mu.Unlock()
	s.run.hub.publish(observe.KindScan, publicScan(sc))
	return nil
}

type beginSink func(observe.Scan)

func (f beginSink) Begin(sc observe.Scan) error               { f(sc); return nil }
func (beginSink) Observation(observe.Observation) error       { return nil }
func (beginSink) PacketEvidence(observe.PacketEvidence) error { return nil }
func (beginSink) Finish(observe.Scan) error                   { return nil }
