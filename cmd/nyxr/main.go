package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/matusso/nyxr/internal/capture"
	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetd"
	"github.com/matusso/nyxr/internal/packetio"
	"github.com/matusso/nyxr/internal/scan"
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
	if len(args) == 0 {
		return usage(out)
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], out)
	case "profiles":
		return runProfiles(args[1:], out)
	case "decode":
		return runDecode(args[1:], out)
	case "sniff":
		return runSniff(args[1:], out)
	case "completion":
		return runCompletion(args[1:], out)
	case "serve":
		return runServe(args[1:], out)
	case "history":
		return runHistory(args[1:], out)
	case "probe":
		return runProbe(args[1:], out)
	case "version":
		_, err := fmt.Fprintln(out, version)
		return err
	case "help", "-h", "--help":
		return usage(out)
	default:
		return fmt.Errorf("unknown command %q (try nyxr help)", args[0])
	}
}

func usage(out io.Writer) error {
	_, err := fmt.Fprint(out, `nyxr scanner `+version+`

Usage:
  nyxr scan [flags] target [target...]   run a scan
  nyxr profiles [--json]                 list scan profiles
  nyxr decode capture.pcap[ng]           decode an Ethernet pcap or pcapng to JSON
  nyxr sniff --interface eth0 [flags]    capture and decode live frames
  nyxr history --db file [flags]         list or query stored scans, assets and evidence
  nyxr probe import file [--json]        import and summarize an nmap-service-probes file
  nyxr serve --db file [flags]           serve the REST API and web UI (unprivileged)
  nyxr completion <shell>                print a bash, zsh, fish or powershell completion script
  nyxr version                           print the version
  nyxr help                              show this help

Targets may be IP addresses, hostnames, CIDRs, or inclusive A-B ranges.
Run "nyxr scan -h" for scan flags, or "nyxr profiles" for profiles.
`)
	return err
}

func scanUsage(out io.Writer) {
	fmt.Fprint(out, `Usage: nyxr scan [flags] target [target...]

Flags:
  --profile string      scan profile (default "discovery"; see: nyxr profiles)
  --ports string        ports, ranges (80,443,8000-8100), or a set (all, top100)
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
  --source-ip string    interface IPv4 address for SYN mode (auto if unique)
  --source-mac string   source Ethernet MAC (for Npcap adapter names)
  --next-hop-mac string destination or gateway MAC for SYN mode
  --payload file        native YAML UDP probe definition
  --send-hex string     custom UDP payload as hex
  --send-base64 string  custom UDP payload as base64
  --payload-file file   custom raw UDP payload file
  --nmap-udp-probes f   add port-directed UDP payloads from a local Nmap probe file
  --config file         YAML scan configuration (flags override its fields)
  --json                newline-delimited JSON output
  --dry-run             resolve and print the plan without sending packets
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

Service identification, evidence and storage:
  --service             deep probes on open TCP ports (on for service, deep, web, full)
  --service-probes list banner, ssh, tls, http, dns, modbus, ethernetip, nmap
  --service-fallback l  probes for silent ports without a port hint, or none
  --service-timeout d   upper bound for each service probe
  --service-workers int concurrent service probe workers
  --service-rate int    new service connections/second (0 = unlimited)
  --nmap-service-probes f  import an nmap-service-probes file to match banners
  --pcapng file         capture scan traffic on --interface as pcapng evidence
  --pcapng-max-mb int   pcapng size budget (default 1024)
  --db file             store the scan, observations and evidence in SQLite

Explicit flags override profile defaults and configuration-file fields.
`)
}

func runScan(args []string, out io.Writer) error {
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
	sourceIPFlag := fs.String("source-ip", "", "interface IPv4 address for SYN mode")
	sourceMACFlag := fs.String("source-mac", "", "source Ethernet MAC for SYN mode")
	nextHopMACFlag := fs.String("next-hop-mac", "", "destination or gateway MAC for SYN mode")
	probeFlag := fs.String("payload", "", "native YAML UDP probe definition")
	hexFlag := fs.String("send-hex", "", "custom UDP payload in hex")
	base64Flag := fs.String("send-base64", "", "custom UDP payload in base64")
	fileFlag := fs.String("payload-file", "", "custom raw UDP payload file")
	nmapUDPFlag := fs.String("nmap-udp-probes", "", "add port-directed UDP payloads from this nmap-service-probes file")
	jsonFlag := fs.Bool("json", false, "newline-delimited JSON output")
	dryRunFlag := fs.Bool("dry-run", false, "resolve and print the plan without scanning")
	allowTargetsFlag := fs.String("allow-targets", "", "comma-separated approved IPs or CIDRs")
	researchKindFlag := fs.String("research-kind", "", "tcp, udp, icmp, sctp or ip")
	ipProtocolFlag := fs.String("ip-protocol", "", "IP protocol number")
	tcpFlagsFlag := fs.String("tcp-flags", "", "TCP flags")
	fragmentSizeFlag := fs.Int("fragment-size", 0, "fragment payload size")
	badChecksumFlag := fs.Bool("bad-checksum", false, "corrupt transport checksum")
	ipLengthFlag := fs.Int("ip-length", 0, "override IP length field")
	forgePayloadFlag := fs.String("forge-payload-hex", "", "raw research payload hex")
	packetdFlag := fs.String("packetd", "", "packetd Unix socket for raw packet I/O")
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
	if err := stages.overlay(&req); err != nil {
		return err
	}

	resolved, err := req.Resolve(config.ResolveOptions{BaseDir: baseDir})
	if err != nil {
		return err
	}
	if *dryRunFlag {
		return emitStagePlan(out, resolved, *stages.db, *jsonFlag)
	}
	var open packetio.Opener
	if *packetdFlag != "" {
		open = packetd.Opener(*packetdFlag)
	}
	if resolved.UsesPipeline() || *stages.db != "" {
		return runPipeline(out, resolved, *stages.db, open, *jsonFlag)
	}

	encoder := json.NewEncoder(out)
	return scan.RunWithIO(context.Background(), resolved.Config, func(o scan.Observation) error {
		if *jsonFlag {
			return encoder.Encode(o)
		}
		port := ""
		if o.Port != 0 {
			port = fmt.Sprintf(":%d", o.Port)
		}
		reason := o.Reason
		if o.MAC != "" {
			reason += " (MAC " + o.MAC + ")"
		}
		_, err := fmt.Fprintf(out, "%s%s %-5s %-14s %3d%% %s\n", o.Target, port, o.Transport, o.State, o.Confidence, reason)
		return err
	}, open)
}

func emitPlan(out io.Writer, plan config.Plan, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(out).Encode(plan)
	}
	fmt.Fprintf(out, "profile     %s\n", plan.Profile)
	fmt.Fprintf(out, "targets     %d", plan.Targets)
	if len(plan.SampleTargets) > 0 {
		fmt.Fprintf(out, " (%s", strings.Join(plan.SampleTargets, ", "))
		if plan.Targets > len(plan.SampleTargets) {
			fmt.Fprint(out, ", ...")
		}
		fmt.Fprint(out, ")")
	}
	fmt.Fprintln(out)
	if len(plan.AllowTargets) > 0 {
		fmt.Fprintf(out, "allow       %s\n", strings.Join(plan.AllowTargets, ", "))
	}
	fmt.Fprintf(out, "protocols   %s\n", strings.Join(plan.Protocols, ", "))
	if plan.Ports > 0 {
		fmt.Fprintf(out, "ports       %s\n", plan.PortSummary)
	}
	fmt.Fprintf(out, "timeout     %s\n", plan.Timeout)
	fmt.Fprintf(out, "rate        %s\n", rateText(plan.Rate))
	if plan.HostRate > 0 {
		fmt.Fprintf(out, "host-rate   %s\n", rateText(plan.HostRate))
	}
	if plan.SubnetRate > 0 {
		fmt.Fprintf(out, "subnet-rate %s\n", rateText(plan.SubnetRate))
	}
	if plan.InterfaceRate > 0 {
		fmt.Fprintf(out, "interface-rate %s\n", rateText(plan.InterfaceRate))
	}
	fmt.Fprintf(out, "workers     %d\n", plan.Workers)
	fmt.Fprintf(out, "tcp-mode    %s\n", plan.TCPMode)
	if plan.Interface != "" {
		fmt.Fprintf(out, "interface   %s\n", plan.Interface)
	}
	if plan.SourceIP != "" {
		fmt.Fprintf(out, "source-ip   %s\n", plan.SourceIP)
	}
	if plan.SourceMAC != "" {
		fmt.Fprintf(out, "source-mac  %s\n", plan.SourceMAC)
	}
	if plan.NextHopMAC != "" {
		fmt.Fprintf(out, "next-hop    %s\n", plan.NextHopMAC)
	}
	if plan.Research != nil {
		fmt.Fprintf(out, "research    %s, IP protocol %d, TCP flags 0x%02x, %d payload bytes\n", plan.Research.Kind, plan.Research.IPProtocol, plan.Research.TCPFlags, plan.Research.PayloadBytes)
		if plan.Research.FragmentSize != 0 {
			fmt.Fprintf(out, "fragment    %d bytes\n", plan.Research.FragmentSize)
		}
		if plan.Research.BadChecksum {
			fmt.Fprintln(out, "checksum    deliberately invalid")
		}
		if plan.Research.IPLength != 0 {
			fmt.Fprintf(out, "ip-length   %d (override)\n", plan.Research.IPLength)
		}
	}
	if plan.UDPRetries > 0 {
		fmt.Fprintf(out, "udp-retries %d\n", plan.UDPRetries)
	}
	if len(plan.UDPProbes) > 0 {
		fmt.Fprintf(out, "udp-probes  %s\n", strings.Join(plan.UDPProbes, ", "))
	}
	if plan.NmapUDPSource != "" {
		fmt.Fprintf(out, "udp-db      %s (SHA-256 %s)\n", plan.NmapUDPSource, plan.NmapUDPSHA)
	}
	fmt.Fprintf(out, "tasks       %d\n", plan.Tasks)
	return nil
}

func rateText(rate int) string {
	if rate == 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d/s", rate)
}

func runProfiles(args []string, out io.Writer) error {
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
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PROFILE\tSTATUS\tDESCRIPTION")
	for _, p := range profiles {
		desc := p.Description
		if p.Availability == config.StatusPlanned {
			desc = "planned: needs " + p.Requires
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", p.Name, p.Availability, desc)
	}
	return w.Flush()
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

func runDecode(args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("decode requires one pcap or pcapng file")
	}
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := capture.NewReader(f)
	if err != nil {
		return err
	}
	decoder := packet.NewDecoder()
	encoder := json.NewEncoder(out)
	for {
		data, err := r.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if decoded, ok := decoder.Decode(data); ok {
			if err := encoder.Encode(decoded); err != nil {
				return err
			}
		}
	}
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
