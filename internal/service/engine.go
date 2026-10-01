// Package service interrogates open TCP ports found by discovery. It is the
// deep path: a fixed worker pool drains a bounded queue, every exchange is
// kept as evidence, and every probe is an unauthenticated, read-only
// handshake. Nothing here runs on the packet receive path.
package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/matusso/nyxr/internal/nmapdb"
	"github.com/matusso/nyxr/internal/observe"
)

// Probe names accepted by Config.Probes.
const (
	ProbeBanner     = "banner"     // passive read; the server speaks first
	ProbeSSH        = "ssh"        // identification string from the banner
	ProbeTLS        = "tls"        // handshake and certificate chain, then the service inside
	ProbeHTTP       = "http"       // GET / over plain TCP or TLS
	ProbeDNS        = "dns"        // CHAOS version.bind TXT over TCP
	ProbeSOCKS      = "socks"      // SOCKS4/5 identity and SOCKS5 UDP relay allocation
	ProbeModbus     = "modbus"     // Read Device Identification (function 43/14)
	ProbeEtherNetIP = "ethernetip" // ListIdentity encapsulation request
	ProbeNmap       = "nmap"       // match a connect banner against an imported nmap-service-probes database
	ProbeDatabase   = "database"   // read-only SQL/NoSQL/graph/cache identity exchanges
)

// Names lists every probe in the order they are documented.
func Names() []string {
	return []string{ProbeBanner, ProbeSSH, ProbeTLS, ProbeHTTP, ProbeDNS, ProbeSOCKS, ProbeModbus, ProbeEtherNetIP, ProbeNmap, ProbeDatabase}
}

// Per-probe time budgets. Config.Timeout caps each of them.
var probeTimeouts = map[string]time.Duration{
	ProbeBanner:     2 * time.Second,
	ProbeTLS:        5 * time.Second,
	ProbeHTTP:       5 * time.Second,
	ProbeDNS:        3 * time.Second,
	ProbeSOCKS:      3 * time.Second,
	ProbeModbus:     3 * time.Second,
	ProbeEtherNetIP: 3 * time.Second,
	ProbeDatabase:   4 * time.Second,
}

// Config controls the deep-probe stage.
type Config struct {
	Probes []string
	// Fallback probes run, in order, on ports with no banner and no port
	// hint. An empty list interrogates only hinted ports beyond the banner.
	Fallback []string
	Timeout  time.Duration // upper bound for each probe
	Workers  int
	// QueueSize bounds pending ports (default 4 × Workers). Submit blocks
	// when it is full, which applies backpressure to the discovery consumer
	// rather than to the packet receive path.
	QueueSize int
	Rate      int // new connections per second across all workers; 0 = unlimited
	// MaxEvidence bounds retained bytes per direction per exchange (default 4096).
	MaxEvidence int
	// Dial is a test hook; nil uses net.Dialer.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// UserAgent is sent in HTTP requests.
	UserAgent string
	// Nmap is an optional imported nmap-service-probes database. When the
	// "nmap" probe is enabled and this is set, a connect banner that the
	// built-in matchers do not recognize is matched against the database's
	// NULL-probe rules. It sends no additional traffic.
	Nmap *nmapdb.Database
}

// Validate reports an unusable configuration.
func (c Config) Validate() error {
	if c.Workers < 1 || c.Workers > 1024 {
		return errors.New("service workers must be 1..1024")
	}
	if c.Timeout <= 0 {
		return errors.New("service timeout must be positive")
	}
	if c.Rate < 0 || c.QueueSize < 0 || c.MaxEvidence < 0 {
		return errors.New("service rate, queue size and evidence limit must be nonnegative")
	}
	if len(c.Probes) == 0 {
		return errors.New("at least one service probe is required")
	}
	known := make(map[string]bool)
	for _, n := range Names() {
		known[n] = true
	}
	for _, list := range [][]string{c.Probes, c.Fallback} {
		for _, p := range list {
			if !known[p] {
				return fmt.Errorf("unknown service probe %q (known: banner, ssh, tls, http, dns, socks, modbus, ethernetip, nmap, database)", p)
			}
		}
	}
	return nil
}

// Target is one open TCP port to interrogate.
type Target struct {
	Addr netip.Addr
	Port uint16
}

// Engine runs a fixed pool of interrogation workers.
type Engine struct {
	cfg     Config
	enabled map[string]bool
	queue   chan Target
	workers sync.WaitGroup
	pacer   *pacer
	closed  sync.Once
}

// Start launches the workers. emit receives one service observation per
// submitted target; it is called from worker goroutines concurrently.
func Start(ctx context.Context, cfg Config, emit func(observe.Observation)) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = cfg.Workers * 4
	}
	if cfg.MaxEvidence == 0 {
		cfg.MaxEvidence = 4096
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "nyxr"
	}
	if cfg.Dial == nil {
		d := &net.Dialer{}
		cfg.Dial = d.DialContext
	}
	e := &Engine{cfg: cfg, enabled: make(map[string]bool), queue: make(chan Target, cfg.QueueSize), pacer: newPacer(cfg.Rate)}
	for _, p := range cfg.Probes {
		e.enabled[p] = true
	}
	for i := 0; i < cfg.Workers; i++ {
		e.workers.Add(1)
		go func() {
			defer e.workers.Done()
			for t := range e.queue {
				emit(e.Interrogate(ctx, t))
			}
		}()
	}
	return e, nil
}

// Submit queues a target, blocking while the queue is full.
func (e *Engine) Submit(ctx context.Context, t Target) error {
	select {
	case e.queue <- t:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops accepting targets and waits for queued work to finish. A
// canceled context makes the remaining interrogations end quickly.
func (e *Engine) Close() {
	e.closed.Do(func() { close(e.queue) })
	e.workers.Wait()
}

func (e *Engine) timeout(probe string) time.Duration {
	d := probeTimeouts[probe]
	if d == 0 || d > e.cfg.Timeout {
		d = e.cfg.Timeout
	}
	return d
}

func (e *Engine) dial(ctx context.Context, t Target, timeout time.Duration) (net.Conn, error) {
	if err := e.pacer.wait(ctx); err != nil {
		return nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return e.cfg.Dial(dctx, "tcp", net.JoinHostPort(t.Addr.String(), fmt.Sprint(t.Port)))
}

// pacer spaces connection attempts evenly; nil means unlimited.
type pacer struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func newPacer(rate int) *pacer {
	if rate <= 0 {
		return nil
	}
	return &pacer{interval: time.Second / time.Duration(rate)}
}

func (p *pacer) wait(ctx context.Context) error {
	if p == nil {
		return ctx.Err()
	}
	p.mu.Lock()
	now := time.Now()
	if p.next.Before(now) {
		p.next = now
	}
	delay := p.next.Sub(now)
	p.next = p.next.Add(p.interval)
	p.mu.Unlock()
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
