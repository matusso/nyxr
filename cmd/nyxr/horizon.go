package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/horizon"
	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/packetd"
	"github.com/matusso/nyxr/internal/packetio"
)

func runHorizon(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		_, err := fmt.Fprintln(out, `Usage:
  nyxr horizon resolve --experiment file --allow-targets CIDR --allow-ports 443 [--dry-run]
  nyxr horizon resolve --experiment file --allow-targets CIDR --allow-ports 443 --simulate sack
  nyxr horizon resolve --experiment file --allow-targets CIDR --allow-ports 443 --interface eth0 --source-ip IP --next-hop-mac MAC [--packetd socket]
  nyxr horizon replay report.json
  nyxr horizon explain report.json
  nyxr horizon references report.json

HZ-001 only: one literal target/port, MSS baseline vs SACK permission.
resolve emits versioned JSON; --output writes evidence to a new private file.
Simulations (sack, stable, loss, noise) send no network traffic.
Live mode requires an explicit interface source and unicast next-hop MAC.
Ctrl-C cancels execution and emits partial evidence. No active mode is a default.`)
		return err
	}
	if args[0] == "replay" || args[0] == "explain" || args[0] == "references" {
		if len(args) != 2 {
			return errors.New("horizon replay/explain/references requires one report file")
		}
		file, err := os.Open(args[1])
		if err != nil {
			return err
		}
		defer file.Close()
		if args[0] == "references" {
			refs, err := horizon.ImportReferences(file)
			if err != nil {
				return err
			}
			return horizonJSON(out, refs)
		}
		envelope, err := horizon.Replay(file)
		if err != nil {
			return err
		}
		if args[0] == "replay" {
			return horizonJSON(out, envelope)
		}
		r := envelope.Report
		_, err = fmt.Fprintf(out, "%s (%s)\nExperiment: %s\nRun: %s; backend: %s\nObserved: %d trials, %d transmitted packets, %d evidence bytes\nConclusion [%s]: %s\nComplete pairs: %d; discordant: %d; exact paired p-value: %.6g\n", r.Experiment.Metadata.Name, r.APIVersion, r.ExperimentHash, r.RunID, r.Backend, len(r.Trials), r.PacketsTX, r.CaptureBytes, r.Comparison.Status, r.Comparison.Conclusion, r.Comparison.CompletePairs, r.Comparison.DiscordantPairs, r.Comparison.PValue)
		if err != nil {
			return err
		}
		for _, limitation := range r.Limitations {
			if _, err = fmt.Fprintln(out, "Limitation:", limitation); err != nil {
				return err
			}
		}
		return nil
	}
	if args[0] != "resolve" {
		return fmt.Errorf("unsupported Horizon command %q", args[0])
	}
	fs := flag.NewFlagSet("horizon resolve", flag.ContinueOnError)
	fs.SetOutput(out)
	experiment := fs.String("experiment", "", "versioned HZ-001 YAML/JSON")
	allowTargets := fs.String("allow-targets", "", "independent approved IP/CIDR scope")
	allowPorts := fs.String("allow-ports", "", "independent approved TCP ports")
	target := fs.String("target", "", "assert the literal target in the experiment")
	ports := fs.String("ports", "", "assert the TCP port in the experiment")
	dry := fs.Bool("dry-run", false, "compile and print the plan; open no packet backend")
	sim := fs.String("simulate", "", "sack, stable, loss or noise (no network traffic)")
	device := fs.String("interface", "", "live Ethernet interface")
	sourceIP := fs.String("source-ip", "", "source IP assigned to the live interface")
	sourceMAC := fs.String("source-mac", "", "source MAC for unmapped Npcap adapter names")
	nextHop := fs.String("next-hop-mac", "", "target/gateway unicast MAC")
	socket := fs.String("packetd", "", "existing packet daemon socket")
	output := fs.String("output", "", "new private evidence file (refuses overwrites)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *experiment == "" || strings.TrimSpace(*allowTargets) == "" || strings.TrimSpace(*allowPorts) == "" {
		return errors.New("require --experiment, --allow-targets and --allow-ports, without positional targets")
	}
	file, err := os.Open(*experiment)
	if err != nil {
		return err
	}
	e, parseErr := dsl.Parse(file)
	closeErr := file.Close()
	if err = errors.Join(parseErr, closeErr); err != nil {
		return err
	}
	authorizedPorts, err := config.ParsePorts(*allowPorts)
	if err != nil {
		return err
	}
	policy := model.Policy{AllowTargets: strings.Split(*allowTargets, ","), AllowPorts: authorizedPorts}
	p, err := dsl.Compile(e, policy)
	if err != nil {
		return err
	}
	if *target != "" && *target != e.Spec.Scope.Targets[0] {
		return errors.New("--target does not match experiment scope; edit the DSL explicitly")
	}
	if *ports != "" {
		requested, err := config.ParsePorts(*ports)
		if err != nil {
			return err
		}
		if len(requested) != 1 || requested[0] != e.Spec.Scope.TCPPorts[0] {
			return errors.New("--ports does not match experiment scope")
		}
	}
	if *dry {
		return horizonJSON(out, p)
	}
	if *sim != "" && (*device != "" || *sourceIP != "" || *sourceMAC != "" || *nextHop != "" || *socket != "") {
		return errors.New("simulation cannot be combined with live packet settings")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	link := horizon.Link{Build: version}
	var transport packetio.PacketIO
	if *sim != "" {
		transport, err = horizon.NewSimulator(*sim)
		link.Backend = "synthetic/" + *sim
		link.SourceIP = netip.MustParseAddr("192.0.2.1")
		if netip.MustParseAddr(e.Spec.Scope.Targets[0]).Is6() {
			link.SourceIP = netip.MustParseAddr("2001:db8::1")
		}
		link.SourceMAC = net.HardwareAddr{2, 0, 0, 0, 0, 1}
		link.NextHopMAC = net.HardwareAddr{2, 0, 0, 0, 0, 2}
	} else {
		if *device == "" || *sourceIP == "" || *nextHop == "" {
			return errors.New("live mode requires --interface, --source-ip and --next-hop-mac")
		}
		link.SourceIP, err = netip.ParseAddr(*sourceIP)
		if err != nil {
			return err
		}
		link.NextHopMAC, err = net.ParseMAC(*nextHop)
		if err != nil {
			return err
		}
		iface, lookupErr := net.InterfaceByName(*device)
		if lookupErr == nil {
			link.SourceMAC = iface.HardwareAddr
			addrs, err := iface.Addrs()
			if err != nil {
				return err
			}
			assigned := false
			for _, addr := range addrs {
				if prefix, err := netip.ParsePrefix(addr.String()); err == nil && prefix.Addr() == link.SourceIP {
					assigned = true
				}
			}
			if !assigned {
				return errors.New("source IP is not assigned to interface")
			}
			if *sourceMAC != "" {
				mac, err := net.ParseMAC(*sourceMAC)
				if err != nil {
					return err
				}
				if mac.String() != link.SourceMAC.String() {
					return errors.New("source MAC does not match interface")
				}
			}
		} else {
			if *sourceMAC == "" {
				return errors.New("unmapped adapter requires --source-mac")
			}
			link.SourceMAC, err = net.ParseMAC(*sourceMAC)
			if err != nil {
				return err
			}
		}
		if len(link.SourceMAC) != 6 || len(link.NextHopMAC) != 6 || link.SourceMAC[0]&1 != 0 || link.NextHopMAC[0]&1 != 0 {
			return errors.New("live packet addresses must be unicast Ethernet MACs")
		}
		open := packetio.OpenLive
		link.Backend = "raw/" + *device
		if *socket != "" {
			open = packetd.Opener(*socket)
			link.Backend = "packetd/" + *device
		}
		transport, err = open(*device)
	}
	if err != nil {
		return err
	}
	defer transport.Close()
	// Reserve the destination before transmitting; never overwrite evidence.
	var destination *os.File
	if *output != "" {
		destination, err = os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		defer destination.Close()
	}
	report, runErr := horizon.Run(ctx, e, policy, link, transport)
	if report.APIVersion == "" {
		return runErr
	}
	envelope, err := horizon.Seal(report)
	if err != nil {
		return errors.Join(runErr, err)
	}
	if destination != nil {
		if err := horizonJSON(destination, envelope); err != nil {
			return errors.Join(runErr, err)
		}
		if err := destination.Close(); err != nil {
			return errors.Join(runErr, err)
		}
	}
	return errors.Join(runErr, horizonJSON(out, envelope))
}

func horizonJSON(out io.Writer, value any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
