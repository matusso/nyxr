// Package pipeline runs one complete scan: fast discovery, the deep-probe
// queue fed by its open ports, optional packet capture, and the sinks that
// print or store every record. Stages communicate through bounded queues;
// the packet receive path never waits for probing, disk or database work.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/matusso/nyxr/internal/capture"
	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/device"
	"github.com/matusso/nyxr/internal/nmapdb"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/packetio"
	"github.com/matusso/nyxr/internal/scan"
	"github.com/matusso/nyxr/internal/service"
)

// Sink consumes records in order: Begin, then observations (discovery and
// service records interleaved), then packet evidence, then Finish. Calls are
// never concurrent.
type Sink interface {
	Begin(observe.Scan) error
	Observation(observe.Observation) error
	PacketEvidence(observe.PacketEvidence) error
	Finish(observe.Scan) error
}

// CaptureOptions enable pcapng evidence.
type CaptureOptions struct {
	Path      string
	Interface string
	MaxBytes  int64
}

// Options configure the stages around discovery.
type Options struct {
	Service     config.Service
	Fingerprint bool
	Capture     *CaptureOptions
	Sinks       []Sink
	// OpenLive opens raw Ethernet I/O for SYN, ARP/NDP and capture; nil uses
	// the local privileged backend. A packetd client keeps the caller
	// unprivileged.
	OpenLive packetio.Opener
	// Nmap is the compiled database for Service.NmapProbesFile. Only a local
	// caller loads it; the pipeline never opens files named by a request.
	Nmap *nmapdb.Database

	// Test hooks; nil selects the real implementation.
	Discover    func(context.Context, config.Config, func(scan.Observation) error) error
	OpenCapture func(string) (packetio.PacketIO, error)
	ServiceDial func(ctx context.Context, network, address string) (net.Conn, error)
	// CaptureGrace is how long capture continues after the last probe so
	// late replies are recorded (default 300ms).
	CaptureGrace time.Duration
}

// FromResolved maps a resolved request onto pipeline stages. Every interface
// uses it, so equivalent requests run equivalent pipelines. Callers add sinks
// and the packet opener.
func FromResolved(r config.Resolved) Options {
	o := Options{Service: r.Service, Fingerprint: r.Fingerprint}
	if r.PCAPNG != "" {
		o.Capture = &CaptureOptions{Path: r.PCAPNG, Interface: r.Config.Interface, MaxBytes: r.PCAPNGMaxBytes}
	}
	return o
}

// Run executes the scan and returns its summary. The summary is also passed
// to every sink's Finish, including when the scan fails.
func Run(parent context.Context, cfg config.Config, opts Options) (observe.Scan, error) {
	if err := cfg.Validate(); err != nil {
		return observe.Scan{}, err
	}
	if err := opts.Service.ValidateFor(cfg); err != nil {
		return observe.Scan{}, err
	}
	discover := opts.Discover
	if discover == nil {
		discover = func(ctx context.Context, cfg config.Config, emit func(scan.Observation) error) error {
			return scan.RunWithIO(ctx, cfg, emit, opts.OpenLive)
		}
	}
	openCapture := opts.OpenCapture
	if openCapture == nil {
		openCapture = opts.OpenLive
	}
	now := time.Now()
	summary := observe.Scan{
		Schema: observe.SchemaVersion, Kind: observe.KindScan, ID: observe.NewScanID(now), Profile: cfg.Profile,
		Started: now.UTC(), Status: "running", Targets: cfg.TargetCount(),
	}
	for _, s := range opts.Sinks {
		if err := s.Begin(summary); err != nil {
			return summary, err
		}
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	var mu sync.Mutex
	var sinkErr error
	var devices *device.Collector
	if opts.Fingerprint {
		devices = device.New()
	}
	deliver := func(o observe.Observation) {
		mu.Lock()
		defer mu.Unlock()
		if sinkErr != nil {
			return
		}
		o.Stamp(summary.ID)
		if devices != nil {
			devices.Add(o)
		}
		for _, s := range opts.Sinks {
			if err := s.Observation(o); err != nil {
				sinkErr = err
				cancel()
				return
			}
		}
		summary.Observations++
		if o.Kind == observe.KindService && o.Fingerprint == observe.FingerprintMatched {
			summary.Services++
		}
	}

	var rec *capture.Recorder
	var runErr error
	if opts.Capture != nil {
		var err error
		rec, err = startCapture(parent, cfg, *opts.Capture, openCapture)
		if err != nil {
			runErr = err
		}
	}
	var engine *service.Engine
	startService := func() {
		if runErr != nil || !opts.Service.Enabled {
			return
		}
		ec := opts.Service.Engine()
		ec.Dial = opts.ServiceDial
		if opts.Service.NmapProbesFile != "" && opts.Nmap == nil {
			runErr = errors.New("nmap-service-probes: database not loaded by the caller")
			return
		}
		ec.Nmap = opts.Nmap
		var err error
		if engine, err = service.Start(ctx, ec, deliver); err != nil {
			runErr = err
		}
	}
	if cfg.Profile != "ot-safe" {
		startService()
	}
	var otOpen []service.Target
	if runErr == nil {
		runErr = discover(ctx, cfg, func(so scan.Observation) error {
			o := fromScan(so)
			deliver(o)
			if o.Transport == "tcp" && o.State == "open" {
				t := service.Target{Addr: o.Target, Port: o.Port}
				if cfg.Profile == "ot-safe" {
					otOpen = append(otOpen, t)
				} else if engine != nil {
					if err := engine.Submit(ctx, t); err != nil {
						return err
					}
				}
			}
			mu.Lock()
			defer mu.Unlock()
			return sinkErr
		})
	}
	if runErr == nil && cfg.Profile == "ot-safe" {
		startService()
		for _, t := range otOpen {
			if runErr != nil {
				break
			}
			if err := engine.Submit(ctx, t); err != nil {
				runErr = err
			}
		}
	}
	if engine != nil {
		engine.Close()
	}
	if devices != nil {
		for _, result := range devices.Results() {
			deliver(result)
		}
	}
	if rec != nil {
		grace := opts.CaptureGrace
		if grace == 0 {
			grace = 300 * time.Millisecond
		}
		if runErr == nil {
			sleep(parent, grace)
		}
		result, err := rec.Stop()
		if err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("capture: %w", err))
		}
		stats := result.Stats
		summary.Capture = &stats
		for _, f := range result.Flows {
			pe := observe.PacketEvidence{
				Schema: observe.SchemaVersion, Kind: observe.KindPacketEvidence, ScanID: summary.ID,
				Target: f.Key.Target, Transport: f.Key.Transport, Port: f.Key.Port,
				Capture: opts.Capture.Path, Packets: f.Packets, Truncated: f.Truncated,
			}
			mu.Lock()
			for _, s := range opts.Sinks {
				if sinkErr == nil {
					sinkErr = s.PacketEvidence(pe)
				}
			}
			mu.Unlock()
		}
	}

	mu.Lock()
	if sinkErr != nil {
		runErr = sinkErr // the discovery error is only the resulting cancellation
	}
	mu.Unlock()
	summary.Finished = time.Now().UTC()
	summary.Status = "completed"
	if runErr != nil {
		summary.Status, summary.Error = "failed", runErr.Error()
	}
	for _, s := range opts.Sinks {
		if err := s.Finish(summary); err != nil {
			runErr = errors.Join(runErr, err)
		}
	}
	return summary, runErr
}

func startCapture(ctx context.Context, cfg config.Config, o CaptureOptions, open packetio.Opener) (*capture.Recorder, error) {
	iface := o.Interface
	if iface == "" {
		iface = cfg.Interface
	}
	if iface == "" {
		return nil, errors.New("packet capture requires --interface")
	}
	if open == nil {
		open = packetio.OpenLive
	}
	src, err := open(iface)
	if err != nil {
		return nil, fmt.Errorf("packet capture on %s: %w", iface, err)
	}
	var match func(netip.Addr) bool
	if cfg.TargetStream != nil {
		match = cfg.TargetStream.Contains
	}
	rec, err := capture.Start(ctx, src, capture.Options{Path: o.Path, Interface: iface, Targets: cfg.Targets, TargetMatch: match, MaxBytes: o.MaxBytes})
	if err != nil {
		_ = src.Close()
		return nil, err
	}
	return rec, nil
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// fromScan lifts a discovery result into the versioned record.
func fromScan(s scan.Observation) observe.Observation {
	return observe.Observation{
		Timestamp: s.Timestamp, Target: s.Target, Transport: s.Transport, Port: s.Port, State: s.State,
		Confidence: s.Confidence, Reason: s.Reason, Probe: s.Probe, Service: s.Service, MAC: s.MAC, RTT: s.RTT,
		PacketsTX: s.PacketsTX, PacketsRX: s.PacketsRX, ProbesAttempted: s.ProbesAttempted, ResponseHex: s.ResponseHex, Fields: s.Fields,
	}
}
