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
	"slices"
	"strings"
	"syscall"
	"time"

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
  nyxr horizon verify-capture report.json evidence.pcapng
  nyxr horizon environment report.json
  nyxr horizon calibrate --protocol protocol.json
  nyxr horizon graph --report r.json [--study main=a.json,same-port=b.json] [--change TIME@host:IP] [--ttl 24h] [--now TIME] [--output graph.json]
  nyxr horizon explain --graph graph.json --hypothesis HYP-1
  nyxr horizon cross-port --main main.json [--same-port r.json] [--reverse r.json] [--time-separated r.json] [--null r.json]
  nyxr horizon adapt --main main.yaml [--same-port ...] --policy lab --permit cross-port --allow-targets CIDR --allow-ports P --simulate S|live opts
      [--budget-packets N] [--budget-ms N] [--refine direction,cooldown] [--require null] [--full-coverage] [--curtail] [--profile p.json]
  nyxr horizon adapt --replay main=a.json,same-port=b.json,... [--retro-curtail] [task/budget/profile options]
  nyxr horizon profile build --study main=a.json,... --class LABEL [--ttl 24h] [--output profile.json]
  nyxr horizon profile check --profile profile.json --study main=a.json,... [--change TIME@host:IP] [--now TIME]
  nyxr horizon audit-verify audit.jsonl

v1alpha1 HZ-001 and v1alpha2 bounded send/observe/wait/repeat sequences.
v1alpha2 requires --policy; cross-port requires --permit cross-port.
resolve emits versioned JSON; --output writes evidence to a new private file.
--pcapng exports bounded evidence; --pcapng-minimize strips application payload.
Simulations (sack, stable, loss, noise, shared-limit, port-limit) send no network traffic.
environment assesses drift, throttling, carryover, clock quality and RTT
uncertainty offline; calibrate runs a pre-registered synthetic decision-rule
calibration and exits nonzero when a registered gate fails. cross-port
replays HZ-003/HZ-004 precondition reports by role and reports shared-state
candidates with competing explanations. graph builds a versioned provenance
graph of hypotheses (repeat --report/--study/--change); explain --graph traces
one hypothesis to its runs, builds and captures. adapt chooses study roles by
expected information under a packet/time budget and records why it stopped;
statements and ports are tested, profile-inferred or not-tested, and
--full-coverage never skips a role. profile build/check compress a validated
study into an expiring profile and invalidate it on drift or change.
Live mode requires an explicit interface source and unicast next-hop MAC.
Ctrl-C cancels execution and emits partial evidence. No active mode is a default.`)
		return err
	}
	if args[0] == "verify-capture" {
		if len(args) != 3 {
			return errors.New("horizon verify-capture requires report.json and evidence.pcapng")
		}
		report, err := os.Open(args[1])
		if err != nil {
			return err
		}
		defer report.Close()
		envelope, err := horizon.Replay(report)
		if err != nil {
			return err
		}
		artifact, err := os.Open(args[2])
		if err != nil {
			return err
		}
		defer artifact.Close()
		if err := horizon.VerifyPCAPNG(envelope.Report, artifact); err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, "PCAPNG artifact and packet references verified")
		return err
	}
	if args[0] == "calibrate" {
		fs := flag.NewFlagSet("horizon calibrate", flag.ContinueOnError)
		fs.SetOutput(out)
		protocol := fs.String("protocol", "", "pre-registered calibration protocol JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *protocol == "" {
			return errors.New("horizon calibrate requires --protocol FILE")
		}
		file, err := os.Open(*protocol)
		if err != nil {
			return err
		}
		p, hash, err := horizon.LoadCalibrationProtocol(file)
		if err = errors.Join(err, file.Close()); err != nil {
			return err
		}
		report, err := horizon.Calibrate(p, hash)
		if err != nil {
			return err
		}
		if err := horizonJSON(out, report); err != nil {
			return err
		}
		if !report.Passed {
			return errors.New("registered calibration gates failed")
		}
		return nil
	}
	if args[0] == "explain" && len(args) > 1 && strings.HasPrefix(args[1], "--graph") {
		fs := flag.NewFlagSet("horizon explain", flag.ContinueOnError)
		fs.SetOutput(out)
		path := fs.String("graph", "", "saved evidence graph")
		id := fs.String("hypothesis", "", "hypothesis ID")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *path == "" || *id == "" {
			return errors.New("horizon explain --graph requires --hypothesis ID")
		}
		file, err := os.Open(*path)
		if err != nil {
			return err
		}
		g, err := horizon.LoadGraph(file)
		if err = errors.Join(err, file.Close()); err != nil {
			return err
		}
		text, err := horizon.ExplainHypothesis(g, *id)
		if err != nil {
			return err
		}
		_, err = io.WriteString(out, text)
		return err
	}
	if args[0] == "graph" {
		return horizonGraph(args[1:], out)
	}
	if args[0] == "adapt" {
		return horizonAdapt(args[1:], out)
	}
	if args[0] == "profile" {
		return horizonProfile(args[1:], out)
	}
	if args[0] == "audit-verify" {
		if len(args) != 2 {
			return errors.New("horizon audit-verify requires one audit file")
		}
		file, err := os.Open(args[1])
		if err != nil {
			return err
		}
		n, err := horizon.VerifyAudit(file)
		if err = errors.Join(err, file.Close()); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "audit chain verified: %d entries\n", n)
		return err
	}
	if args[0] == "cross-port" {
		fs := flag.NewFlagSet("horizon cross-port", flag.ContinueOnError)
		fs.SetOutput(out)
		paths := map[string]*string{}
		for _, role := range horizon.CrossPortRoles {
			paths[role] = fs.String(role, "", role+" role precondition report")
		}
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *paths[horizon.RoleMain] == "" {
			return errors.New("horizon cross-port requires --main REPORT")
		}
		reports := map[string]model.Report{}
		for role, path := range paths {
			if *path == "" {
				continue
			}
			file, err := os.Open(*path)
			if err != nil {
				return err
			}
			envelope, err := horizon.Replay(file)
			if err = errors.Join(err, file.Close()); err != nil {
				return fmt.Errorf("%s: %w", role, err)
			}
			reports[role] = envelope.Report
		}
		study, err := horizon.AnalyzeCrossPort(reports)
		if err != nil {
			return err
		}
		return horizonJSON(out, study)
	}
	if args[0] == "replay" || args[0] == "explain" || args[0] == "references" || args[0] == "environment" {
		if len(args) != 2 {
			return errors.New("horizon replay/explain/references/environment requires one report file")
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
		if args[0] == "environment" {
			// Replay verified a saved assessment; older reports are assessed now.
			return horizonJSON(out, horizon.Assess(envelope.Report))
		}
		r := envelope.Report
		_, err = fmt.Fprintf(out, "%s (%s)\nExperiment: %s\nRun: %s; backend: %s\nObserved: %d trials, %d transmitted packets, %d evidence bytes\nConclusion [%s]: %s\nComplete pairs: %d; discordant: %d; exact paired p-value: %.6g\n", r.Experiment.Metadata.Name, r.APIVersion, r.ExperimentHash, r.RunID, r.Backend, len(r.Trials), r.PacketsTX, r.CaptureBytes, r.Comparison.Status, r.Comparison.Conclusion, r.Comparison.CompletePairs, r.Comparison.DiscordantPairs, r.Comparison.PValue)
		if err != nil {
			return err
		}
		if env := r.Environment; env != nil {
			_, err = fmt.Fprintf(out, "Environment [%s]: gating %v; quality %v\nConfounders: %s\nReferences answered: %d/%d; throttling p=%.4g; carryover p=%.4g\n", env.Version, env.GatingFlags, env.QualityFlags, strings.Join(env.Confounders, ", "), env.Responses.ReferencesAnswered, env.Responses.References, env.Responses.ThrottlingPValue, env.Carryover.PValue)
			if err == nil && env.Latency.PairedLowerNS != nil {
				_, err = fmt.Fprintf(out, "Paired RTT difference (treatment-control): median %.3f ms, %.0f%% interval [%.3f, %.3f] ms over %d pairs (userspace clock)\n", float64(*env.Latency.PairedMedianNS)/1e6, 100*env.Latency.Confidence, float64(*env.Latency.PairedLowerNS)/1e6, float64(*env.Latency.PairedUpperNS)/1e6, env.Latency.PairedSamples)
			}
			if err != nil {
				return err
			}
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
	experiment := fs.String("experiment", "", "versioned HORIZON YAML/JSON")
	policyName := fs.String("policy", "", "lab, enterprise, fragile or ot-restricted")
	permissions := fs.String("permit", "", "independent permissions: cross-port")
	allowTargets := fs.String("allow-targets", "", "independent approved IP/CIDR scope")
	allowPorts := fs.String("allow-ports", "", "independent approved TCP ports")
	target := fs.String("target", "", "assert the literal target in the experiment")
	ports := fs.String("ports", "", "assert the TCP port in the experiment")
	dry := fs.Bool("dry-run", false, "compile and print the plan; open no packet backend")
	lf := addLinkFlags(fs)
	pcapPath := fs.String("pcapng", "", "new private bounded PCAPNG evidence file")
	pcapMax := fs.Int64("pcapng-max-bytes", 8<<20, "encoded PCAPNG file cap, 256 bytes..8 MiB")
	pcapMinimize := fs.Bool("pcapng-minimize", false, "omit application payload in PCAPNG; raw JSON remains authoritative")
	output := fs.String("output", "", "new private evidence file (refuses overwrites)")
	auditPath := fs.String("audit", "", "append this run to a hash-chained audit trail (fails closed)")
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
	policy := model.Policy{Profile: *policyName, AllowTargets: strings.Split(*allowTargets, ","), AllowPorts: authorizedPorts}
	if *permissions != "" {
		policy.Permissions = strings.Split(*permissions, ",")
	}
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
		declared := append([]uint16(nil), e.Spec.Scope.TCPPorts...)
		slices.Sort(requested)
		slices.Sort(declared)
		if !slices.Equal(requested, declared) {
			return errors.New("--ports does not match experiment scope")
		}
	}
	if *pcapMax < 256 || *pcapMax > 8<<20 {
		return errors.New("PCAPNG cap must be 256 bytes..8 MiB")
	}
	if *pcapPath == "" && (*pcapMinimize || *pcapMax != 8<<20) {
		return errors.New("PCAPNG options require --pcapng")
	}
	if *dry {
		return horizonJSON(out, p)
	}
	link, open, err := lf.open(netip.MustParseAddr(e.Spec.Scope.Targets[0]))
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	transport, err := open()
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
	var pcapFile *os.File
	if *pcapPath != "" {
		pcapFile, err = os.OpenFile(*pcapPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		defer pcapFile.Close()
	}
	audit, err := openCLIAudit(*auditPath)
	if err != nil {
		return err
	}
	if audit != nil {
		defer audit.Close()
	}
	report, runErr := auditedRun(ctx, audit, e, policy, link, transport)
	if report.APIVersion == "" {
		return runErr
	}
	if pcapFile != nil {
		captureErr := horizon.WritePCAPNG(pcapFile, &report, *pcapMax, *pcapMinimize)
		closeErr := pcapFile.Close()
		if captureErr != nil || closeErr != nil {
			report.CaptureArtifact = nil
			for i := range report.Trials {
				for j := range report.Trials[i].Evidence {
					report.Trials[i].Evidence[j].PacketID = 0
				}
			}
			report.Completed = false
			report.StopReason = "PCAPNG export failed"
			report.Comparison = horizon.Compare(report)
		}
		runErr = errors.Join(runErr, captureErr, closeErr)
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

// linkFlags select a synthetic or live packet transport for active commands.
type linkFlags struct {
	sim, device, sourceIP, sourceMAC, nextHop, socket *string
}

func addLinkFlags(fs *flag.FlagSet) linkFlags {
	return linkFlags{
		sim:       fs.String("simulate", "", "sack, stable, loss, noise, shared-limit or port-limit (no network traffic)"),
		device:    fs.String("interface", "", "live Ethernet interface"),
		sourceIP:  fs.String("source-ip", "", "source IP assigned to the live interface"),
		sourceMAC: fs.String("source-mac", "", "source MAC for unmapped Npcap adapter names"),
		nextHop:   fs.String("next-hop-mac", "", "target/gateway unicast MAC"),
		socket:    fs.String("packetd", "", "existing packet daemon socket"),
	}
}

func (l linkFlags) live() bool {
	return *l.device != "" || *l.sourceIP != "" || *l.sourceMAC != "" || *l.nextHop != "" || *l.socket != ""
}

// open validates the link and returns a factory for fresh transports.
func (l linkFlags) open(target netip.Addr) (horizon.Link, func() (packetio.PacketIO, error), error) {
	link := horizon.Link{Build: version}
	if *l.sim != "" {
		if l.live() {
			return link, nil, errors.New("simulation cannot be combined with live packet settings")
		}
		scenario := *l.sim
		if _, err := horizon.NewSimulator(scenario); err != nil {
			return link, nil, err
		}
		link.Backend = "synthetic/" + scenario
		link.SourceIP = netip.MustParseAddr("192.0.2.1")
		if target.Is6() {
			link.SourceIP = netip.MustParseAddr("2001:db8::1")
		}
		link.SourceMAC = net.HardwareAddr{2, 0, 0, 0, 0, 1}
		link.NextHopMAC = net.HardwareAddr{2, 0, 0, 0, 0, 2}
		return link, func() (packetio.PacketIO, error) { return horizon.NewSimulator(scenario) }, nil
	}
	if *l.device == "" || *l.sourceIP == "" || *l.nextHop == "" {
		return link, nil, errors.New("live mode requires --interface, --source-ip and --next-hop-mac")
	}
	var err error
	link.SourceIP, err = netip.ParseAddr(*l.sourceIP)
	if err != nil {
		return link, nil, err
	}
	link.NextHopMAC, err = net.ParseMAC(*l.nextHop)
	if err != nil {
		return link, nil, err
	}
	iface, lookupErr := net.InterfaceByName(*l.device)
	if lookupErr == nil {
		link.SourceMAC = iface.HardwareAddr
		addrs, err := iface.Addrs()
		if err != nil {
			return link, nil, err
		}
		assigned := false
		for _, addr := range addrs {
			if prefix, err := netip.ParsePrefix(addr.String()); err == nil && prefix.Addr() == link.SourceIP {
				assigned = true
			}
		}
		if !assigned {
			return link, nil, errors.New("source IP is not assigned to interface")
		}
		if *l.sourceMAC != "" {
			mac, err := net.ParseMAC(*l.sourceMAC)
			if err != nil {
				return link, nil, err
			}
			if mac.String() != link.SourceMAC.String() {
				return link, nil, errors.New("source MAC does not match interface")
			}
		}
	} else {
		if *l.sourceMAC == "" {
			return link, nil, errors.New("unmapped adapter requires --source-mac")
		}
		link.SourceMAC, err = net.ParseMAC(*l.sourceMAC)
		if err != nil {
			return link, nil, err
		}
	}
	if len(link.SourceMAC) != 6 || len(link.NextHopMAC) != 6 || link.SourceMAC[0]&1 != 0 || link.NextHopMAC[0]&1 != 0 {
		return link, nil, errors.New("live packet addresses must be unicast Ethernet MACs")
	}
	open := packetio.OpenLive
	link.Backend = "raw/" + *l.device
	if *l.socket != "" {
		open = packetd.Opener(*l.socket)
		link.Backend = "packetd/" + *l.device
	}
	device := *l.device
	return link, func() (packetio.PacketIO, error) { return open(device) }, nil
}

func horizonJSON(out io.Writer, value any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func replayFile(path string) (model.Envelope, error) {
	file, err := os.Open(path)
	if err != nil {
		return model.Envelope{}, err
	}
	envelope, err := horizon.Replay(file)
	if err = errors.Join(err, file.Close()); err != nil {
		return model.Envelope{}, fmt.Errorf("%s: %w", path, err)
	}
	return envelope, nil
}

// horizonGraph replays every input before projecting it; nothing unverified
// enters the graph.
func horizonGraph(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("horizon graph", flag.ContinueOnError)
	fs.SetOutput(out)
	var reports, studies, changes stringList
	fs.Var(&reports, "report", "replayable HZ-001/HZ-002 report (repeatable)")
	fs.Var(&studies, "study", "cross-port study as role=report,... (repeatable)")
	fs.Var(&changes, "change", "declared change TIME@host:IP or TIME@network[@detail] (repeatable)")
	ttl := fs.Duration("ttl", 24*time.Hour, "confidence TTL after the latest supporting run")
	nowFlag := fs.String("now", "", "evaluation time (RFC 3339); default current time")
	output := fs.String("output", "", "new private graph file (refuses overwrites)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || len(reports)+len(studies) == 0 {
		return errors.New("horizon graph requires --report or --study inputs")
	}
	in := horizon.GraphInput{Now: time.Now().UTC(), TTL: *ttl}
	if *nowFlag != "" {
		now, err := time.Parse(time.RFC3339, *nowFlag)
		if err != nil {
			return fmt.Errorf("--now: %w", err)
		}
		in.Now = now
	}
	for _, path := range reports {
		e, err := replayFile(path)
		if err != nil {
			return err
		}
		in.Reports = append(in.Reports, e)
	}
	for _, spec := range studies {
		study, err := parseStudy(spec)
		if err != nil {
			return err
		}
		in.Studies = append(in.Studies, study)
	}
	declared, err := parseChanges(changes)
	if err != nil {
		return err
	}
	in.Changes = declared
	g, err := horizon.BuildGraph(in)
	if err != nil {
		return err
	}
	if *output != "" {
		file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		err = horizonJSON(file, g)
		if err = errors.Join(err, file.Close()); err != nil {
			return err
		}
	}
	return horizonJSON(out, g)
}
