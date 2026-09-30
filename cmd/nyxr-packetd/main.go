// Command nyxr-packetd is the only nyxr process that needs raw packet
// privilege (CAP_NET_RAW and CAP_NET_ADMIN on Linux, BPF device access on
// macOS, Npcap on Windows). It relays Ethernet frames for an allowlist of
// interfaces over a Unix socket so nyxr serve and nyxr scan --packetd run
// unprivileged.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/matusso/nyxr/internal/packetd"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "nyxr-packetd:", err)
		os.Exit(1)
	}
}

func usage(out io.Writer) {
	fmt.Fprint(out, `Usage: nyxr-packetd --socket path --interface eth0[,eth1] [flags]

Relay raw Ethernet frames for the listed interfaces to unprivileged nyxr
processes over a Unix socket. Grant this binary, not nyxr, the packet
privilege (Linux: setcap cap_net_raw,cap_net_admin+ep nyxr-packetd).

Flags:
  --socket path        Unix socket to create (required)
  --interface list     comma list of interfaces clients may open (required)
  --socket-mode octal  socket file permissions (default 0660)
  --max-clients int    concurrent sessions (default 4)
  --max-pps int        transmitted frames/second per session (0 = unlimited)
  --version            print the version
`)
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("nyxr-packetd", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	socket := fs.String("socket", "", "Unix socket path")
	ifaces := fs.String("interface", "", "allowed interfaces")
	mode := fs.String("socket-mode", "0660", "socket permissions")
	maxClients := fs.Int("max-clients", 4, "concurrent sessions")
	maxPPS := fs.Int("max-pps", 0, "transmit frames per second per session")
	showVersion := fs.Bool("version", false, "print the version")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(out)
		}
		return err
	}
	if *showVersion {
		_, err := fmt.Fprintln(out, version)
		return err
	}
	if *socket == "" || *ifaces == "" || fs.NArg() != 0 {
		usage(out)
		return errors.New("--socket and --interface are required")
	}
	perm, err := strconv.ParseUint(*mode, 8, 32)
	if err != nil || perm > 0o777 || perm&0o007 != 0 {
		return errors.New("--socket-mode must be octal without world access (e.g. 0660)")
	}
	var names []string
	for _, n := range strings.Split(*ifaces, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	srv, err := packetd.NewServer(packetd.ServerConfig{Interfaces: names, MaxClients: *maxClients, MaxPPS: *maxPPS})
	if err != nil {
		return err
	}
	l, err := packetd.Listen(*socket, os.FileMode(perm))
	if err != nil {
		return err
	}
	defer os.Remove(*socket)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "nyxr-packetd %s listening on %s for %s\n", version, *socket, strings.Join(names, ", "))
	return srv.Serve(ctx, l)
}
