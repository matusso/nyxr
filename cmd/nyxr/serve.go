package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/matusso/nyxr/internal/api"
	"github.com/matusso/nyxr/internal/packetd"
	"github.com/matusso/nyxr/internal/storage"
)

func serveUsage(out io.Writer) {
	fmt.Fprint(out, `Usage: nyxr serve --db file [flags]

Serve the REST API, live scan events and the web UI. The server runs
unprivileged; raw SYN, ARP/NDP and pcapng capture go through nyxr-packetd.

Flags:
  --listen addr        listen address (default 127.0.0.1:8484)
  --db file            SQLite database for scans and results (required)
  --packetd socket     nyxr-packetd Unix socket for raw packet I/O
  --evidence-dir dir   directory for pcapng captures requested through the API
  --token-file file    require this bearer token (or set NYXR_API_TOKEN)
  --max-scans int      concurrent scans (default 1)
  --allow-privileged   run even with root or raw-socket capabilities

A non-loopback --listen address requires a token.
`)
}

func runServe(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { serveUsage(out) }
	listen := fs.String("listen", "127.0.0.1:8484", "listen address")
	db := fs.String("db", "", "SQLite database")
	packetdSocket := fs.String("packetd", "", "packetd socket")
	evidenceDir := fs.String("evidence-dir", "", "pcapng directory")
	tokenFile := fs.String("token-file", "", "bearer token file")
	maxScans := fs.Int("max-scans", 1, "concurrent scans")
	allowPrivileged := fs.Bool("allow-privileged", false, "allow root or raw-socket capabilities")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			serveUsage(out)
		}
		return err
	}
	if *db == "" || fs.NArg() != 0 {
		return errors.New("serve requires --db and no positional arguments")
	}
	if *maxScans < 1 {
		return errors.New("--max-scans must be at least 1")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := storage.Open(ctx, *db)
	if err != nil {
		return err
	}
	defer store.Close()
	mcfg := api.ManagerConfig{Store: store, EvidenceDir: *evidenceDir, MaxRunning: *maxScans}
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
	handler := api.Handler(api.ServerConfig{Manager: manager, Store: store, Token: token, AllowedHosts: hosts,
		Version: version, EvidenceDir: *evidenceDir})
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
