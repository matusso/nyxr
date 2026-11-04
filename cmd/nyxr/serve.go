package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/matusso/nyxr/internal/api"
	"github.com/matusso/nyxr/internal/central"
	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/fleet"
	"github.com/matusso/nyxr/internal/horizon"
	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/packetd"
	"github.com/matusso/nyxr/internal/packetio"
	"github.com/matusso/nyxr/internal/service"
	"github.com/matusso/nyxr/internal/storage"
)

func serveUsage(out io.Writer) {
	fmt.Fprint(out, `Usage: nyxr serve [--db file] [flags]

Serve the REST API, live scan events and the web UI. The server runs
unprivileged; raw SYN, ARP/NDP and pcapng capture go through nyxr-packetd.

Flags:
  --listen addr        listen address (default 127.0.0.1:8484)
  --db file            SQLite database for scans and results (default ~/.nyxr/nyxr.db)
  --packetd socket     nyxr-packetd Unix socket for raw packet I/O
  --evidence-dir dir   directory for pcapng captures requested through the API
  --protocol-registry files  comma-separated operator-owned protocol YAML files
  --token-file file    require this bearer token (or set NYXR_API_TOKEN)
  --max-scans int      concurrent scans (default 1)
  --allow-packet-send  enable single-frame send/resend from the web UI (requires --packetd)
  --horizon-simulate scenario   enable synthetic HORIZON API (sack/stable/loss/noise/shared-limit/port-limit)
  --horizon-policy profile      lab/enterprise/fragile/ot-restricted
  --horizon-allow-targets CIDRs independent HORIZON target scope
  --horizon-allow-ports ports   independent HORIZON TCP port scope
  --horizon-permit cross-port  independent cross-port permission
  --horizon-modes list         enabled modes (default recognize,resolve; reconstruct is opt-in)
  --horizon-audit file         append-only hash-chained audit trail (required for HORIZON)
  --horizon-max-runs int       retained HORIZON runs, 1..16 (default 8)
  --horizon-retention dur      drop finished HORIZON runs after this age (default 24h)
  --allow-privileged   run even with root or raw-socket capabilities
  --fleet-listen addr  serve the gRPC fleet controller for remote agents (requires an API token)
  --fleet-tls-cert file  controller certificate (PEM)
  --fleet-tls-key file   controller key (PEM)
  --fleet-client-ca file require agent client certificates signed by this CA
  --fleet-enroll-token-file file  token new agents enroll with (omit to disable enrollment)
  --fleet-lease-ttl dur  lease lifetime without a heartbeat (default 30s)
  --fleet-insecure       plaintext gRPC; only on a loopback --fleet-listen
  --central dsn          push this database to a central store (postgres://... or a SQLite path)
  --central-dsn-file file  read the central DSN from a file (or set NYXR_CENTRAL_DSN)
  --central-objects loc  object storage for captures: a directory or s3://bucket/prefix?endpoint=..
  --central-objects-credentials-file file  S3 credential-process JSON (default AWS_* variables)
  --central-sync dur     push interval (default 1m)
  --central-capture-retention dur  retention of pushed captures (default: keep)

A non-loopback --listen address requires a token. The HORIZON API always
requires a token and an audit file; it only drives synthetic transports.
`)
}

func runServe(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { serveUsage(out) }
	listen := fs.String("listen", "127.0.0.1:8484", "listen address")
	dbFlag := dbFlags{path: fs.String("db", "", "SQLite database")}
	packetdSocket := fs.String("packetd", "", "packetd socket")
	evidenceDir := fs.String("evidence-dir", "", "pcapng directory")
	protocolRegistry := fs.String("protocol-registry", "", "operator-owned protocol YAML files")
	tokenFile := fs.String("token-file", "", "bearer token file")
	maxScans := fs.Int("max-scans", 1, "concurrent scans")
	horizonSim := fs.String("horizon-simulate", "", "synthetic HORIZON API scenario")
	horizonPolicy := fs.String("horizon-policy", "", "HORIZON operator profile")
	horizonTargets := fs.String("horizon-allow-targets", "", "HORIZON operator target scope")
	horizonPorts := fs.String("horizon-allow-ports", "", "HORIZON operator TCP ports")
	horizonPermit := fs.String("horizon-permit", "", "HORIZON operator permissions")
	horizonModes := fs.String("horizon-modes", strings.Join(horizon.DefaultModes, ","), "enabled HORIZON modes")
	horizonAudit := fs.String("horizon-audit", "", "HORIZON audit trail file")
	horizonMaxRuns := fs.Int("horizon-max-runs", 8, "retained HORIZON runs")
	horizonRetention := fs.Duration("horizon-retention", 24*time.Hour, "HORIZON run retention")
	allowPacketSend := fs.Bool("allow-packet-send", false, "enable web UI packet transmission")
	allowPrivileged := fs.Bool("allow-privileged", false, "allow root or raw-socket capabilities")
	fleetListen := fs.String("fleet-listen", "", "fleet gRPC listen address")
	fleetCert := fs.String("fleet-tls-cert", "", "fleet certificate")
	fleetKey := fs.String("fleet-tls-key", "", "fleet key")
	fleetClientCA := fs.String("fleet-client-ca", "", "fleet client CA")
	fleetEnroll := fs.String("fleet-enroll-token-file", "", "fleet enrollment token file")
	fleetTTL := fs.Duration("fleet-lease-ttl", 30*time.Second, "fleet lease TTL")
	fleetInsecure := fs.Bool("fleet-insecure", false, "plaintext fleet gRPC on loopback")
	centralDSN := fs.String("central", "", "central store DSN")
	centralDSNFile := fs.String("central-dsn-file", "", "central store DSN file")
	centralObjects := fs.String("central-objects", "", "central object storage")
	centralObjectsCreds := fs.String("central-objects-credentials-file", "", "S3 credential-process JSON")
	centralSync := fs.Duration("central-sync", time.Minute, "central push interval")
	centralRetention := fs.Duration("central-capture-retention", 0, "central capture retention")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			serveUsage(out)
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("serve takes no positional arguments")
	}
	var horizonController *horizon.Controller
	var horizonRuns *horizon.Runs
	if *horizonSim != "" {
		if *horizonPolicy == "" || *horizonTargets == "" || *horizonPorts == "" || *horizonAudit == "" {
			return errors.New("HORIZON API requires --horizon-policy, --horizon-allow-targets, --horizon-allow-ports and --horizon-audit")
		}
		profOK := false
		for _, p := range dsl.Profiles() {
			if p.Name == *horizonPolicy {
				profOK = true
			}
		}
		if !profOK {
			return errors.New("unknown HORIZON policy")
		}
		scope, err := config.ParseScope(strings.Split(*horizonTargets, ","))
		if err != nil || scope.Empty() {
			return errors.New("invalid HORIZON target scope")
		}
		ports, err := config.ParsePorts(*horizonPorts)
		if err != nil {
			return err
		}
		policy := model.Policy{Profile: *horizonPolicy, AllowTargets: strings.Split(*horizonTargets, ","), AllowPorts: ports}
		if *horizonPermit != "" {
			if *horizonPermit != "cross-port" {
				return errors.New("unsupported HORIZON permission")
			}
			policy.Permissions = []string{"cross-port"}
		}
		sim, err := horizon.NewSimulator(*horizonSim)
		if err != nil {
			return err
		}
		sim.Close()
		link := horizon.Link{SourceIP: netip.MustParseAddr("192.0.2.1"), SourceMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, NextHopMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, Build: version, Backend: "synthetic/" + *horizonSim}
		audit, err := horizon.OpenAudit(*horizonAudit)
		if err != nil {
			return err
		}
		defer audit.Close()
		horizonController = horizon.NewController(policy, link, func() (packetio.PacketIO, error) { return horizon.NewSimulator(*horizonSim) })
		defer horizonController.Close()
		horizonRuns, err = horizon.NewRuns(horizonController, horizon.RunsConfig{Modes: strings.Split(*horizonModes, ","), Audit: audit,
			Metrics: horizon.NewMetrics(), MaxRuns: *horizonMaxRuns, Retention: *horizonRetention})
		if err != nil {
			return err
		}
		defer horizonRuns.Close()
	} else if *horizonPolicy != "" || *horizonTargets != "" || *horizonPorts != "" || *horizonPermit != "" || *horizonAudit != "" {
		return errors.New("HORIZON API options require --horizon-simulate")
	}
	db, err := dbFlag.resolve()
	if err != nil {
		return err
	}
	if *maxScans < 1 {
		return errors.New("--max-scans must be at least 1")
	}
	if *allowPacketSend && *packetdSocket == "" {
		return errors.New("--allow-packet-send requires --packetd")
	}
	if reason := privileged(); reason != "" && !*allowPrivileged {
		return fmt.Errorf("refusing to serve with %s; run nyxr-packetd for raw packet I/O, or pass --allow-privileged", reason)
	}
	token := os.Getenv("NYXR_API_TOKEN")
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		token = strings.TrimSpace(string(b))
	}
	if token != "" && len(token) < 16 {
		return errors.New("API token must be at least 16 characters")
	}
	if horizonRuns != nil && token == "" {
		return errors.New("the HORIZON API requires --token-file or NYXR_API_TOKEN")
	}
	if *protocolRegistry != "" && token == "" {
		return errors.New("--protocol-registry requires --token-file or NYXR_API_TOKEN for reload authentication")
	}
	var fleetTLS *tls.Config
	var enrollToken string
	if *fleetListen != "" {
		if token == "" {
			return errors.New("--fleet-listen requires --token-file or NYXR_API_TOKEN: fleet scans are submitted through the API")
		}
		if *fleetTTL < 3*time.Second || *fleetTTL > time.Hour {
			return errors.New("--fleet-lease-ttl must be 3s..1h")
		}
		if *fleetInsecure {
			if !fleet.IsLoopback(*fleetListen) {
				return errors.New("--fleet-insecure is only allowed on a loopback --fleet-listen address")
			}
			if *fleetCert != "" || *fleetKey != "" || *fleetClientCA != "" {
				return errors.New("--fleet-insecure cannot be combined with fleet TLS flags")
			}
		} else {
			if fleetTLS, err = fleet.ServerTLS(*fleetCert, *fleetKey, *fleetClientCA); err != nil {
				return fmt.Errorf("%w (or --fleet-insecure on loopback)", err)
			}
		}
		if *fleetEnroll != "" {
			b, err := os.ReadFile(*fleetEnroll)
			if err != nil {
				return err
			}
			if enrollToken = strings.TrimSpace(string(b)); len(enrollToken) < 16 {
				return errors.New("fleet enrollment token must be at least 16 characters")
			}
		}
	} else if *fleetCert != "" || *fleetKey != "" || *fleetClientCA != "" || *fleetEnroll != "" || *fleetInsecure {
		return errors.New("fleet options require --fleet-listen")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	loopback := isLoopbackHost(host)
	if !loopback && token == "" {
		return errors.New("a non-loopback --listen address requires --token-file or NYXR_API_TOKEN")
	}
	if *evidenceDir != "" {
		if err := os.MkdirAll(*evidenceDir, 0o700); err != nil {
			return err
		}
	}
	var registry *service.Registry
	if *protocolRegistry != "" {
		var paths []string
		for _, path := range strings.Split(*protocolRegistry, ",") {
			path = strings.TrimSpace(path)
			if path == "" {
				return errors.New("empty protocol registry path")
			}
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			paths = append(paths, abs)
		}
		registry, err = service.NewRegistry(paths)
		if err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := openStore(ctx, db)
	if err != nil {
		return err
	}
	defer store.Close()
	mcfg := api.ManagerConfig{Store: store, EvidenceDir: *evidenceDir, MaxRunning: *maxScans, ProtocolRegistry: registry}
	if *packetdSocket != "" {
		mcfg.OpenLive = packetd.Opener(*packetdSocket)
	}
	manager, err := api.NewManager(mcfg)
	if err != nil {
		return err
	}
	var hosts []string
	if loopback {
		// Refuse other Host headers so a rebinding DNS name cannot reach
		// the loopback API from a browser.
		hosts = []string{"localhost", "127.0.0.1", "::1", strings.Trim(host, "[]")}
	}
	var fleetCtrl *fleet.Controller
	var fleetSrv *grpc.Server
	if *fleetListen != "" {
		fleetCtrl, err = fleet.NewController(fleet.ControllerConfig{Store: store, EnrollToken: enrollToken, LeaseTTL: *fleetTTL,
			Log: log.New(os.Stderr, "nyxr fleet: ", log.LstdFlags)})
		if err != nil {
			return err
		}
		defer fleetCtrl.Close()
		opts := []grpc.ServerOption{grpc.MaxRecvMsgSize(fleet.MaxMessageBytes), grpc.MaxSendMsgSize(fleet.MaxMessageBytes),
			grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
			// Detect half-open agent connections instead of leasing to them.
			grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second})}
		if fleetTLS != nil {
			opts = append(opts, grpc.Creds(credentials.NewTLS(fleetTLS)))
		}
		fleetSrv = grpc.NewServer(opts...)
		fleetCtrl.Register(fleetSrv)
		fl, err := net.Listen("tcp", *fleetListen)
		if err != nil {
			return err
		}
		mode := "TLS"
		if fleetTLS == nil {
			mode = "plaintext loopback"
		}
		fmt.Fprintf(os.Stderr, "nyxr fleet controller (%s, %s) on %s\n", fleet.Protocol, mode, fl.Addr())
		go func() { _ = fleetSrv.Serve(fl) }()
		defer fleetSrv.Stop()
	}
	if *centralDSN != "" || *centralDSNFile != "" || os.Getenv("NYXR_CENTRAL_DSN") != "" {
		if *centralSync < 5*time.Second {
			return errors.New("--central-sync must be at least 5s")
		}
		cdb, err := openCentral(ctx, *centralDSN, *centralDSNFile, *centralObjects, *centralObjectsCreds)
		if err != nil {
			return fmt.Errorf("central store: %w", err)
		}
		defer cdb.Close()
		kind := central.LineageStandalone
		if *fleetListen != "" {
			kind = central.LineageController
		}
		fmt.Fprintf(os.Stderr, "nyxr central sync (%s, %s lineage) every %s\n", cdb.Dialect(), kind, *centralSync)
		go centralSyncLoop(ctx, store, cdb, central.PushOptions{Kind: kind, UploadCaptures: *centralObjects != "" || os.Getenv("NYXR_CENTRAL_OBJECTS") != "",
			CaptureRetention: *centralRetention}, *centralSync, log.New(os.Stderr, "nyxr central: ", log.LstdFlags))
	}
	handler := api.Handler(api.ServerConfig{Horizon: horizonRuns, Manager: manager, Store: store, Token: token, AllowedHosts: hosts,
		Version: version, EvidenceDir: *evidenceDir, PacketSendEnabled: *allowPacketSend, Fleet: fleetCtrl})
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	fmt.Fprintf(os.Stderr, "nyxr %s serving http://%s\n", version, l.Addr())
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(l) }()
	select {
	case err := <-errc:
		manager.Close()
		return err
	case <-ctx.Done():
	}
	if horizonController != nil {
		horizonController.Stop()
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	manager.Close() // cancels scans; their partial results are stored
	_ = srv.Shutdown(shutdown)
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// centralSyncLoop pushes the serve database to the central store until ctx
// ends. Pushes are idempotent and resume from the lineage cursor, so a failed
// round is simply retried on the next tick.
func centralSyncLoop(ctx context.Context, src *storage.Store, dst central.Store, opts central.PushOptions, every time.Duration, logger *log.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		res, err := central.Push(ctx, src, dst, opts)
		switch {
		case err != nil && ctx.Err() == nil:
			logger.Printf("push failed: %v", err)
		case err == nil && (res.Ingested.Observations > 0 || res.Ingested.Conflicts > 0 || res.Uploaded > 0):
			logger.Printf("pushed %d observation(s), %d conflict(s), %d capture(s) uploaded, %d pending",
				res.Ingested.Observations, res.Ingested.Conflicts, res.Uploaded, res.Pending)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
