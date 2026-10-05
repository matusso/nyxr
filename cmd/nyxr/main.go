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
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/netmon"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetd"
	"github.com/matusso/nyxr/internal/packetio"
	"github.com/matusso/nyxr/internal/pipeline"
	"github.com/matusso/nyxr/internal/scan"
	"github.com/matusso/nyxr/internal/ui"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "nyxr:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	args, noColor := extractNoColor(args)
	style := ui.New(out, noColor)
	if len(args) == 0 {
		return usage(out)
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], out, style, stderrProgress(out, noColor))
	case "profiles":
		return runProfiles(args[1:], out, style)
	case "decode":
		return runDecode(args[1:], out, style)
	case "sniff":
		return runSniff(args[1:], out)
	case "completion":
		return runCompletion(args[1:], out)
	case "serve":
		return runServe(args[1:], out)
	case "history":
		return runHistory(args[1:], out, style)
	case "probe":
		return runProbe(args[1:], out, style)
	case "version":
		_, err := fmt.Fprintln(out, version)
		return err
	case "help", "-h", "--help":
		return usage(out)
	default:
		return fmt.Errorf("unknown command %q (try nyxr help)", args[0])
	}
}

// extractNoColor pulls the global --no-color flag out of args, wherever it
// appears, so every subcommand honors it without registering it on each
// FlagSet. It returns the remaining args and whether color was disabled.
func extractNoColor(args []string) ([]string, bool) {
	disabled := false
	kept := args[:0:0]
	for _, a := range args {
		switch a {
		case "--no-color", "-no-color", "--no-color=true", "-no-color=true":
			disabled = true
			continue
		case "--no-color=false", "-no-color=false":
			continue
		}
		kept = append(kept, a)
	}
	return kept, disabled
}

func usage(out io.Writer) error {
	_, err := fmt.Fprint(out, `nyxr scanner `+version+`

Usage:
  nyxr scan [flags] target [target...]   run a scan
  nyxr profiles [--json]                 list scan profiles
  nyxr decode [--tui] capture.pcap[ng]   summarize hosts and open ports, or browse packets
  nyxr decode [--tui] --last             decode the last scan's capture (~/.nyxr/last.pcapng)
  nyxr sniff --interface eth0 [flags]    capture and decode live frames
  nyxr history [--db file] [flags]       list or query stored scans, assets and evidence
  nyxr probe import file [--json]        import and summarize an nmap-service-probes file
  nyxr probe validate file [--json]      validate a Nyxr Protocol DSL file
  nyxr serve [--db file] [flags]         serve the REST API and web UI (unprivileged)
  nyxr completion <shell>                print a bash, zsh, fish or powershell completion script
  nyxr version                           print the version
  nyxr help                              show this help

Global flags:
  --no-color    disable ANSI color (also honored: the NO_COLOR environment
                variable; color is off automatically when output is not a tty)

Targets may be IP addresses, hostnames, CIDRs, or inclusive A-B ranges.
"nyxr scan --known-open [scope...]" re-probes only ports stored as open.
Run "nyxr scan -h" for scan flags, or "nyxr profiles" for profiles.
`)
	return err
}

func scanUsage(out io.Writer) {
	fmt.Fprint(out, `Usage: nyxr scan [flags] target [target...]

Flags:
  --profile string      scan profile (default "tcp-basic"; see: nyxr profiles)
  --ports string        ports, ranges (80,443,8000-8100), or a set (all, top100, top1000, top2000,
                        top5000, top8387, web, udp, database)
  --protocols string    comma list of tcp, udp, icmp, arp, ndp; research also accepts sctp, ip
  --timeout duration    per-probe timeout (e.g. 1s, 750ms)
  --rate int            max probes/second (0 = unlimited)
  --host-rate int       max probes/second per address
  --subnet-rate int     max probes/second per IPv4 /24 or IPv6 /64
  --interface-rate int  max probes/second on selected raw interface
  --workers int         concurrent probe workers
  --udp-retries int     extra retries per UDP probe
  --tcp-mode string     connect (default) or raw Ethernet syn
  --interface string    Ethernet interface for SYN mode
  --xdp-pin-dir dir     use Linux AF_XDP with pinned Nyxr XDP maps (SYN mode)
  --source-ip string    interface IPv4 address for SYN mode (auto if unique)
  --source-mac string   source Ethernet MAC (for Npcap adapter names)
  --next-hop-mac string destination or gateway MAC for SYN mode
  --payload file        native YAML UDP probe definition
  --send-hex string     custom UDP payload as hex
  --send-base64 string  custom UDP payload as base64
  --payload-file file   custom raw UDP payload file
  --nmap-udp-probes f   add UDP payloads from a local Nmap probe file
  --config file         YAML scan configuration (flags override its fields)
  --json                newline-delimited JSON output
  --dry-run             resolve and print the plan without sending packets
  --no-progress         hide the progress bar (shown on stderr when it is a tty)
  --no-summary          hide the closing statistics (time, tasks, rate, workers, packets) on stderr
  --open                show only open ports and responsive hosts (--db still stores all)
  --allow-targets list  approved IP/CIDR targets (required for ot-safe)
  --research-kind name  tcp, udp, icmp, sctp or ip (research profile only)
  --ip-protocol n      IP protocol number for research IP scans
  --tcp-flags list     TCP flags (syn, ack, fin, null, xmas or numeric mask)
  --fragment-size n   IP payload bytes per fragment, multiple of eight
  --bad-checksum      deliberately corrupt transport checksum
  --ip-length n       override IP payload/total length field
  --forge-payload-hex hex  raw research payload bytes
  --fingerprint         classify devices from independent observations
  --packetd socket      raw packet I/O through nyxr-packetd instead of local privilege
  --known-open          rescan only the ports --db last saw open (service probes on by
                        default); targets, if given, narrow it by IP, CIDR or range

Service identification, evidence and storage:
  --service             deep probes on open TCP ports, or UDP with Protocol DSL definitions
  --service-probes list banner, ssh, tls, http, dns, socks, modbus, ethernetip, nmap, database, smb, rdp, msrpc, ldap, kerberos, nfs
  --service-fallback l  probes for silent ports without a port hint, or none
  --service-timeout d   upper bound for each service probe
  --service-workers int concurrent service probe workers
  --service-rate int    new service connections/second (0 = unlimited)
  --nmap-service-probes f  import an nmap-service-probes file to match banners
  --protocol-definitions files  comma-separated Nyxr Protocol DSL YAML files
  --nse-scripts list    run named, installed safe Nmap NSE scripts on discovered open ports
  --nse-timeout d       maximum Nmap execution time per host (default 30s)
  --pcapng file         capture scan traffic on --interface as pcapng evidence
  --pcapng-max-mb int   pcapng size budget (default 1024)
  --no-last-pcapng      do not keep this scan's traffic in ~/.nyxr/last.pcapng
                        (kept by default for scans with --interface; see decode --last)
  --db file             SQLite database for the scan, observations and evidence
                        (default ~/.nyxr/nyxr.db)
  --no-db               do not store the scan

Global:
  --no-color            disable ANSI color (see also the NO_COLOR variable)

Explicit flags override profile defaults and configuration-file fields.
`)
}

// progressOptions say where a scan may draw its progress bar. The zero value
// draws none, which is what tests and embedded callers get.
type progressOptions struct {
	w       io.Writer
	noColor bool
}

// stderrProgress draws the bar on stderr, but only when the CLI writes its
// results to a real file or terminal, never to a caller's buffer.
func stderrProgress(out io.Writer, noColor bool) progressOptions {
	if _, ok := out.(*os.File); !ok {
		return progressOptions{}
	}
	return progressOptions{w: os.Stderr, noColor: noColor}
}

func (o progressOptions) start(tasks int, disabled bool) *ui.Progress {
	return ui.NewProgress(o.w, tasks, o.w != nil && !disabled, ui.New(o.w, o.noColor))
}

// trafficDevice picks the interface whose traffic a scan reports: the scan's
// raw interface when one is set, loopback when every target is local, and
// otherwise "" for the sum over every interface that is up. label names it.
func trafficDevice(cfg config.Config) (device, label string) {
	device = cfg.Interface
	if device == "" && allLoopback(cfg.Targets) {
		device = loopbackInterface()
	}
	label = device
	if label == "" {
		label = "all interfaces"
	}
	return device, label
}

// monitorTraffic shows the traffic of trafficDevice under the bar.
func monitorTraffic(bar *ui.Progress, cfg config.Config) {
	if !bar.Enabled() {
		return
	}
	device, label := trafficDevice(cfg)
	bar.Monitor(label, func() (netmon.Counters, error) { return netmon.Read(device) })
}

// scanTally counts finished tasks for the closing summary and advances the
// progress bar, which keeps no counts while it is disabled.
type scanTally struct {
	bar         *ui.Progress
	done, found atomic.Int64
}

func (t *scanTally) Step(found bool) {
	t.done.Add(1)
	if found {
		t.found.Add(1)
	}
	t.bar.Step(found)
}

// scanSummary measures a scan from start to the call of its print method.
type scanSummary struct {
	w       io.Writer
	style   *ui.Styler
	tally   *scanTally
	cfg     config.Config
	planned int
	start   time.Time
	device  string
	label   string
	before  netmon.Counters
	netOK   bool
}

func startSummary(w io.Writer, style *ui.Styler, tally *scanTally, cfg config.Config, planned int) *scanSummary {
	s := &scanSummary{w: w, style: style, tally: tally, cfg: cfg, planned: planned, start: time.Now()}
	s.device, s.label = trafficDevice(cfg)
	c, err := netmon.Read(s.device)
	s.before, s.netOK = c, err == nil
	return s
}

func (s *scanSummary) print(failed bool) {
	if s == nil || s.w == nil {
		return
	}
	st := ui.RunStats{
		Elapsed: time.Since(s.start), Tasks: int(s.tally.done.Load()), Planned: s.planned,
		Found: int(s.tally.found.Load()), Workers: s.cfg.Workers, Failed: failed, Interface: s.label,
	}
	if s.netOK {
		if after, err := netmon.Read(s.device); err == nil && after.TxPackets >= s.before.TxPackets && after.RxPackets >= s.before.RxPackets &&
			after.TxBytes >= s.before.TxBytes && after.RxBytes >= s.before.RxBytes {
			st.Traffic = netmon.Counters{
				TxPackets: after.TxPackets - s.before.TxPackets, RxPackets: after.RxPackets - s.before.RxPackets,
				TxBytes: after.TxBytes - s.before.TxBytes, RxBytes: after.RxBytes - s.before.RxBytes,
			}
			st.HasTraffic = true
		}
	}
	fmt.Fprint(s.w, s.style.RunSummary(st))
}

func allLoopback(targets []netip.Addr) bool {
	for _, t := range targets {
		if !t.IsLoopback() {
			return false
		}
	}
	return len(targets) > 0
}

func loopbackInterface() string {
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			return ifc.Name
		}
	}
	return ""
}

func runScan(args []string, out io.Writer, style *ui.Styler, progress progressOptions) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { scanUsage(out) }
	portsFlag := fs.String("ports", "", "comma-separated ports, ranges, or a named set")
	protoFlag := fs.String("protocols", "", "tcp,udp,icmp,arp,ndp; research: sctp,ip")
	profileFlag := fs.String("profile", "", "scan profile")
	timeoutFlag := fs.Duration("timeout", 0, "probe timeout")
	rateFlag := fs.Int("rate", -1, "maximum probes per second (0 unlimited)")
	hostRateFlag := fs.Int("host-rate", -1, "maximum probes per second per address (0 unlimited)")
	subnetRateFlag := fs.Int("subnet-rate", -1, "maximum probes per second per IPv4 /24 or IPv6 /64 (0 unlimited)")
	interfaceRateFlag := fs.Int("interface-rate", -1, "maximum probes per second on the raw interface (0 unlimited)")
	workersFlag := fs.Int("workers", -1, "concurrent probe workers")
	configFlag := fs.String("config", "", "YAML configuration file")
	udpRetriesFlag := fs.Int("udp-retries", -1, "extra retries for each UDP probe")
	tcpModeFlag := fs.String("tcp-mode", "", "connect or syn")
	interfaceFlag := fs.String("interface", "", "Ethernet interface for SYN mode")
	xdpPinDirFlag := fs.String("xdp-pin-dir", "", "pinned Nyxr AF_XDP maps for SYN mode")
	sourceIPFlag := fs.String("source-ip", "", "interface IPv4 address for SYN mode")
	sourceMACFlag := fs.String("source-mac", "", "source Ethernet MAC for SYN mode")
	nextHopMACFlag := fs.String("next-hop-mac", "", "destination or gateway MAC for SYN mode")
	probeFlag := fs.String("payload", "", "native YAML UDP probe definition")
	hexFlag := fs.String("send-hex", "", "custom UDP payload in hex")
	base64Flag := fs.String("send-base64", "", "custom UDP payload in base64")
	fileFlag := fs.String("payload-file", "", "custom raw UDP payload file")
	nmapUDPFlag := fs.String("nmap-udp-probes", "", "add UDP payloads from this nmap-service-probes file")
	jsonFlag := fs.Bool("json", false, "newline-delimited JSON output")
	dryRunFlag := fs.Bool("dry-run", false, "resolve and print the plan without scanning")
	noProgressFlag := fs.Bool("no-progress", false, "hide the progress bar")
	noSummaryFlag := fs.Bool("no-summary", false, "hide the closing scan statistics")
	openFlag := fs.Bool("open", false, "show only open ports and responsive hosts")
	allowTargetsFlag := fs.String("allow-targets", "", "comma-separated approved IPs or CIDRs")
	researchKindFlag := fs.String("research-kind", "", "tcp, udp, icmp, sctp or ip")
	ipProtocolFlag := fs.String("ip-protocol", "", "IP protocol number")
	tcpFlagsFlag := fs.String("tcp-flags", "", "TCP flags")
	fragmentSizeFlag := fs.Int("fragment-size", 0, "fragment payload size")
	badChecksumFlag := fs.Bool("bad-checksum", false, "corrupt transport checksum")
	ipLengthFlag := fs.Int("ip-length", 0, "override IP length field")
	forgePayloadFlag := fs.String("forge-payload-hex", "", "raw research payload hex")
	packetdFlag := fs.String("packetd", "", "packetd Unix socket for raw packet I/O")
	knownOpenFlag := fs.Bool("known-open", false, "rescan only ports the database last saw open")
	noLastFlag := fs.Bool("no-last-pcapng", false, "do not keep this scan's traffic in ~/.nyxr/last.pcapng")
	stages := addStageFlags(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			scanUsage(out)
		}
		return err
	}

	req, err := config.ParseFile(*configFlag)
	if err != nil {
		return err
	}
	if *rateFlag < -1 || *hostRateFlag < -1 || *subnetRateFlag < -1 || *interfaceRateFlag < -1 || *workersFlag < -1 || *udpRetriesFlag < -1 {
		return errors.New("rates, workers and UDP retries must be nonnegative")
	}

	// Flags overlay the configuration file; the merged Request then takes the
	// same Resolve path as an API request.
	req.Targets = append(append([]string{}, req.Targets...), fs.Args()...)
	if *allowTargetsFlag != "" {
		req.AllowTargets = []string{*allowTargetsFlag}
	}
	req.Profile = first(*profileFlag, req.Profile)
	req.Ports = first(*portsFlag, req.Ports)
	req.Protocols = first(*protoFlag, req.Protocols)
	req.Timeout = first(timeoutText(*timeoutFlag), req.Timeout)
	req.TCPMode = first(*tcpModeFlag, req.TCPMode)
	req.Interface = first(*interfaceFlag, req.Interface)
	req.XDPPinDir = first(*xdpPinDirFlag, req.XDPPinDir)
	req.SourceIP = first(*sourceIPFlag, req.SourceIP)
	req.SourceMAC = first(*sourceMACFlag, req.SourceMAC)
	req.NextHopMAC = first(*nextHopMACFlag, req.NextHopMAC)
	req.Rate = mergeInt(*rateFlag, req.Rate)
	req.HostRate = mergeInt(*hostRateFlag, req.HostRate)
	req.SubnetRate = mergeInt(*subnetRateFlag, req.SubnetRate)
	req.InterfaceRate = mergeInt(*interfaceRateFlag, req.InterfaceRate)
	req.Workers = mergeInt(*workersFlag, req.Workers)
	req.UDPRetries = mergeInt(*udpRetriesFlag, req.UDPRetries)
	req.NmapUDPProbes = first(*nmapUDPFlag, req.NmapUDPProbes)
	req.ResearchKind = first(*researchKindFlag, req.ResearchKind)
	req.IPProtocol = first(*ipProtocolFlag, req.IPProtocol)
	req.TCPFlags = first(*tcpFlagsFlag, req.TCPFlags)
	if *fragmentSizeFlag != 0 {
		req.FragmentSize = *fragmentSizeFlag
	}
	if *badChecksumFlag {
		req.BadChecksum = true
	}
	if *ipLengthFlag != 0 {
		req.IPLength = *ipLengthFlag
	}
	req.ForgePayloadHex = first(*forgePayloadFlag, req.ForgePayloadHex)

	baseDir := ""
	if *probeFlag != "" || *hexFlag != "" || *base64Flag != "" || *fileFlag != "" {
		// A payload flag replaces any payload named in the file.
		req.UDPProbeFile, req.SendHex, req.SendBase64, req.PayloadFile = *probeFlag, *hexFlag, *base64Flag, *fileFlag
	} else if req.UDPProbeFile != "" && *configFlag != "" {
		baseDir = filepath.Dir(*configFlag)
	}
	if baseDir == "" && req.ProtocolDefinitions != "" && *configFlag != "" {
		baseDir = filepath.Dir(*configFlag)
	}
	if err := stages.overlay(&req); err != nil {
		return err
	}
	db, err := stages.db.resolve()
	if err != nil {
		return err
	}
	opts := config.ResolveOptions{BaseDir: baseDir}
	if *knownOpenFlag {
		req.KnownOpen = true
	}
	if req.KnownOpen {
		if db == "" {
			return errors.New("--known-open reads earlier results; it cannot be combined with --no-db")
		}
		opts.KnownOpen = func() ([]config.KnownPort, error) { return knownOpen(db) }
	}

	resolved, err := req.Resolve(opts)
	if err != nil {
		return err
	}
	if *packetdFlag != "" && resolved.Config.XDPPinDir != "" {
		return errors.New("AF_XDP opens local privileged sockets and cannot use --packetd")
	}
	if *dryRunFlag {
		return emitStagePlan(out, resolved, db, *jsonFlag, style)
	}
	var open packetio.Opener
	if *packetdFlag != "" {
		open = packetd.Opener(*packetdFlag)
	}
	var last *lastCapture
	if !*noLastFlag {
		last = startLastCapture(resolved, open, progress.w)
	}
	planned := resolved.Config.Plan().Tasks
	bar := progress.start(planned, *noProgressFlag)
	monitorTraffic(bar, resolved.Config)
	tally := &scanTally{bar: bar}
	var summary *scanSummary
	if progress.w != nil && !*noSummaryFlag {
		summary = startSummary(progress.w, ui.New(progress.w, progress.noColor), tally, resolved.Config, planned)
	}
	err = runResolved(bar.Wrap(out), resolved, db, open, *jsonFlag, *openFlag, style, tally)
	bar.Done()
	last.finish()
	summary.print(err != nil)
	return err
}

// knownOpen reads the stored open ports for a --known-open rescan.
func knownOpen(db string) ([]config.KnownPort, error) {
	ctx := context.Background()
	store, err := openStore(ctx, db)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	return store.KnownOpen(ctx)
}

func runResolved(out io.Writer, resolved config.Resolved, db string, open packetio.Opener, asJSON, openOnly bool, style *ui.Styler, tally *scanTally) error {
	if resolved.UsesPipeline() || db != "" {
		return runPipeline(out, resolved, db, open, asJSON, openOnly, style, tally)
	}

	encoder := json.NewEncoder(out)
	return scan.RunWithIO(context.Background(), resolved.Config, func(o scan.Observation) error {
		tally.Step(o.State == "open" || o.State == "responsive")
		if openOnly && !pipeline.IsOpen(o.State) {
			return nil
		}
		if asJSON {
			return encoder.Encode(o)
		}
		reason := o.Reason
		if o.MAC != "" {
			reason += " (MAC " + o.MAC + ")"
		}
		_, err := fmt.Fprintln(out, style.Discovery(o.Target.String(), o.Port, o.Transport, o.State, o.Confidence, reason))
		return err
	}, open)
}

func emitPlan(out io.Writer, plan config.Plan, asJSON bool, style *ui.Styler) error {
	if asJSON {
		return json.NewEncoder(out).Encode(plan)
	}
	// key colors an 11-wide label; a trailing space makes the 12-column gutter
	// the original layout used, so plain output is unchanged.
	key := func(k string) string { return style.Key(fmt.Sprintf("%-11s", k)) + " " }
	row := func(k, format string, a ...any) {
		fmt.Fprintf(out, "%s%s\n", key(k), fmt.Sprintf(format, a...))
	}
	row("profile", "%s", style.Bold(plan.Profile))
	fmt.Fprintf(out, "%s%d", key("targets"), plan.Targets)
	if len(plan.SampleTargets) > 0 {
		fmt.Fprintf(out, " %s", style.Dim("("+strings.Join(plan.SampleTargets, ", ")+ellipsis(plan.Targets > len(plan.SampleTargets))+")"))
	}
	fmt.Fprintln(out)
	if len(plan.AllowTargets) > 0 {
		row("allow", "%s", strings.Join(plan.AllowTargets, ", "))
	}
	row("protocols", "%s", strings.Join(plan.Protocols, ", "))
	if plan.Ports > 0 {
		row("ports", "%s", plan.PortSummary)
	}
	if plan.UDPPorts > 0 {
		row("udp-ports", "%s", plan.UDPPortSummary)
	}
	row("timeout", "%s", plan.Timeout)
	row("rate", "%s", rateText(plan.Rate))
	if plan.HostRate > 0 {
		row("host-rate", "%s", rateText(plan.HostRate))
	}
	if plan.SubnetRate > 0 {
		row("subnet-rate", "%s", rateText(plan.SubnetRate))
	}
	if plan.InterfaceRate > 0 {
		row("interface-rate", "%s", rateText(plan.InterfaceRate))
	}
	row("workers", "%d", plan.Workers)
	row("tcp-mode", "%s", plan.TCPMode)
	if plan.Interface != "" {
		row("interface", "%s", plan.Interface)
	}
	if plan.SourceIP != "" {
		row("source-ip", "%s", plan.SourceIP)
	}
	if plan.SourceMAC != "" {
		row("source-mac", "%s", plan.SourceMAC)
	}
	if plan.NextHopMAC != "" {
		row("next-hop", "%s", plan.NextHopMAC)
	}
	if plan.Research != nil {
		row("research", "%s, IP protocol %d, TCP flags 0x%02x, %d payload bytes", plan.Research.Kind, plan.Research.IPProtocol, plan.Research.TCPFlags, plan.Research.PayloadBytes)
		if plan.Research.FragmentSize != 0 {
			row("fragment", "%d bytes", plan.Research.FragmentSize)
		}
		if plan.Research.BadChecksum {
			row("checksum", "%s", style.Yellow("deliberately invalid"))
		}
		if plan.Research.IPLength != 0 {
			row("ip-length", "%d (override)", plan.Research.IPLength)
		}
	}
	if plan.UDPRetries > 0 {
		row("udp-retries", "%d", plan.UDPRetries)
	}
	if plan.UDPMode != "" {
		row("udp-mode", "%s", plan.UDPMode)
	}
	if len(plan.UDPProbes) > 0 {
		row("udp-probes", "%s", strings.Join(plan.UDPProbes, ", "))
	}
	if plan.NmapUDPSource != "" {
		row("udp-db", "%s %s", plan.NmapUDPSource, style.Dim("(SHA-256 "+plan.NmapUDPSHA+")"))
	}
	row("tasks", "%s", style.Bold(fmt.Sprintf("%d", plan.Tasks)))
	return nil
}

// ellipsis returns ", ..." when there are more targets than the sample shows.
func ellipsis(more bool) string {
	if more {
		return ", ..."
	}
	return ""
}

func rateText(rate int) string {
	if rate == 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d/s", rate)
}

func runProfiles(args []string, out io.Writer, style *ui.Styler) error {
	fs := flag.NewFlagSet("profiles", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonFlag := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	profiles := config.Profiles()
	if *jsonFlag {
		return json.NewEncoder(out).Encode(profiles)
	}
	rows := [][]string{{style.Header("PROFILE"), style.Header("STATUS"), style.Header("DESCRIPTION")}}
	for _, p := range profiles {
		desc := p.Description
		if p.Availability == config.StatusPlanned {
			desc = "planned: needs " + p.Requires
		}
		rows = append(rows, []string{style.Bold(p.Name), availabilityText(style, string(p.Availability)), style.Dim(desc)})
	}
	return style.Table(out, rows)
}

// availabilityText colors a profile's availability: green when available,
// yellow when planned.
func availabilityText(style *ui.Styler, availability string) string {
	switch availability {
	case string(config.StatusAvailable):
		return style.Green(availability)
	case string(config.StatusPlanned):
		return style.Yellow(availability)
	default:
		return availability
	}
}

func first(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// mergeInt picks the flag value when set (>=0), otherwise the file value when
// present, otherwise nil so the profile default applies.
func mergeInt(flagValue int, fileValue *int) *int {
	if flagValue >= 0 {
		v := flagValue
		return &v
	}
	if fileValue != nil {
		v := *fileValue
		return &v
	}
	return nil
}

func timeoutText(d time.Duration) string {
	if d == 0 {
		return ""
	}
	return d.String()
}

func runSniff(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("sniff", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	device := fs.String("interface", "", "network interface")
	count := fs.Int("count", 100, "number of decoded packets")
	duration := fs.Duration("timeout", 10*time.Second, "capture duration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *device == "" || *count < 1 || *duration <= 0 {
		return errors.New("sniff requires --interface, positive --count and --timeout")
	}
	src, err := packetio.OpenLive(*device)
	if err != nil {
		return err
	}
	defer src.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	decoder := packet.NewDecoder()
	encoder := json.NewEncoder(out)
	buffers := make([][]byte, 32)
	for i := range buffers {
		buffers[i] = make([]byte, 65535)
	}
	seen := 0
	for seen < *count {
		n, err := src.ReceiveBatch(ctx, buffers)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			return err
		}
		for i := 0; i < n; i++ {
			if decoded, ok := decoder.Decode(buffers[i]); ok {
				if err := encoder.Encode(decoded); err != nil {
					return err
				}
				seen++
			}
			buffers[i] = buffers[i][:cap(buffers[i])]
			if seen >= *count {
				break
			}
		}
	}
	return nil
}
