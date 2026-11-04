package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/matusso/nyxr/internal/fleet"
	"github.com/matusso/nyxr/internal/packetd"
)

func agentUsage(out io.Writer) {
	fmt.Fprint(out, `Usage: nyxr agent --controller host:port --allow-targets CIDRs [flags]

Run a fleet agent. The agent dials the controller (nyxr serve --fleet-listen)
over gRPC, advertises what this vantage can do, and runs the scans the
controller leases to it through the same pipeline as the CLI. It never scans
outside --allow-targets, whatever the controller asks.

Flags:
  --controller addr      controller gRPC address (required)
  --allow-targets CIDRs  scope this agent is authorized to scan (required)
  --name name            agent name shown on the controller (default hostname)
  --identity file        enrolled credential (default ~/.nyxr/agent.json)
  --enroll-token-file f  enrollment token, used once when --identity does not exist
  --ca file              CA bundle that signed the controller certificate (default system roots)
  --server-name name     expected controller certificate name
  --tls-cert file        client certificate for mutual TLS
  --tls-key file         client key for mutual TLS
  --insecure             plaintext gRPC; only to a loopback controller
  --packetd socket       nyxr-packetd socket for raw SYN, ARP/NDP and capture
  --interface name       raw interface (default: the route to the first target)
  --xdp-pin-dir dir      Linux AF_XDP pinned maps for SYN scans
  --evidence-dir dir     directory for pcapng captures leased to this agent
  --max-leases int       concurrent leases (default 1)
  --max-rate int         total packets/s budget of this agent (0 = controller share)
  --max-service-rate int total service connections/s budget (0 = controller share)
  --allow-ot             permit the ot-safe profile on this agent
  --allow-privileged     run with root or raw-socket capabilities (enables local raw I/O and ICMP)
`)
}

func runAgent(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { agentUsage(out) }
	controller := fs.String("controller", "", "controller address")
	allow := fs.String("allow-targets", "", "authorized scope")
	name := fs.String("name", "", "agent name")
	identityFile := fs.String("identity", "", "credential file")
	tokenFile := fs.String("enroll-token-file", "", "enrollment token file")
	caFile := fs.String("ca", "", "controller CA bundle")
	serverName := fs.String("server-name", "", "controller certificate name")
	certFile := fs.String("tls-cert", "", "client certificate")
	keyFile := fs.String("tls-key", "", "client key")
	plaintext := fs.Bool("insecure", false, "plaintext to a loopback controller")
	packetdSocket := fs.String("packetd", "", "packetd socket")
	iface := fs.String("interface", "", "raw interface")
	xdp := fs.String("xdp-pin-dir", "", "AF_XDP pin directory")
	evidenceDir := fs.String("evidence-dir", "", "pcapng directory")
	maxLeases := fs.Int("max-leases", 1, "concurrent leases")
	maxRate := fs.Int("max-rate", 0, "packets/s budget")
	maxServiceRate := fs.Int("max-service-rate", 0, "service connections/s budget")
	allowOT := fs.Bool("allow-ot", false, "permit ot-safe")
	allowPrivileged := fs.Bool("allow-privileged", false, "allow root or raw-socket capabilities")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			agentUsage(out)
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("agent takes no positional arguments")
	}
	if *controller == "" || *allow == "" {
		return errors.New("agent requires --controller and --allow-targets")
	}
	if *maxLeases < 1 || *maxLeases > 64 || *maxRate < 0 || *maxServiceRate < 0 {
		return errors.New("--max-leases must be 1..64 and rates nonnegative")
	}
	reason := privileged()
	if reason != "" && !*allowPrivileged {
		return fmt.Errorf("refusing to run the agent with %s; use nyxr-packetd for raw packet I/O, or pass --allow-privileged", reason)
	}
	cfg := fleet.AgentConfig{Controller: *controller, Name: *name, AllowTargets: strings.Split(*allow, ","), Interface: *iface,
		XDPPinDir: *xdp, EvidenceDir: *evidenceDir, MaxLeases: *maxLeases, MaxRate: *maxRate, MaxServiceRate: *maxServiceRate,
		AllowOT: *allowOT, Version: version, Privileged: reason != "", Log: log.New(os.Stderr, "nyxr agent: ", log.LstdFlags)}
	switch {
	case reason == "root privileges":
		cfg.Privilege = "root"
	case reason != "":
		cfg.Privilege = "raw-capabilities"
	case *packetdSocket != "":
		cfg.Privilege = "packetd"
	default:
		cfg.Privilege = "unprivileged"
	}
	if *packetdSocket != "" {
		cfg.OpenLive = packetd.Opener(*packetdSocket)
	}
	if *plaintext {
		if !fleet.IsLoopback(*controller) {
			return errors.New("--insecure is only allowed for a loopback controller; use --ca for TLS")
		}
		if *caFile != "" || *certFile != "" || *keyFile != "" {
			return errors.New("--insecure cannot be combined with TLS flags")
		}
	} else {
		tlsCfg, err := fleet.ClientTLS(*caFile, *certFile, *keyFile, *serverName)
		if err != nil {
			return err
		}
		cfg.TLS = tlsCfg
	}
	if *evidenceDir != "" {
		if err := os.MkdirAll(*evidenceDir, 0o700); err != nil {
			return err
		}
	}
	cfg.IdentityFile = *identityFile
	if cfg.IdentityFile == "" {
		home, err := homeDir()
		if err != nil {
			return errors.New("cannot locate home directory for the agent identity; pass --identity")
		}
		cfg.IdentityFile = filepath.Join(home, ".nyxr", "agent.json")
	}
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		cfg.EnrollToken = strings.TrimSpace(string(b))
	}
	agent, err := fleet.NewAgent(cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return agent.Run(ctx)
}
