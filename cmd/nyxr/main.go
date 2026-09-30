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

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/packet"
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
  nyxr decode capture.pcap               decode an Ethernet pcap to JSON
  nyxr sniff --interface eth0 [flags]    capture and decode live frames
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
  --protocols string    comma list of tcp, udp, icmp
  --timeout duration    per-probe timeout (e.g. 1s, 750ms)
  --rate int            max probes/second (0 = unlimited)
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
  --config file         YAML scan configuration (flags override its fields)
  --json                newline-delimited JSON output
  --dry-run             resolve and print the plan without sending packets

Explicit flags override profile defaults and configuration-file fields.
`)
}

func runScan(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { scanUsage(out) }
	portsFlag := fs.String("ports", "", "comma-separated ports, ranges, or a named set")
	protoFlag := fs.String("protocols", "", "tcp,udp,icmp")
	profileFlag := fs.String("profile", "", "scan profile")
	timeoutFlag := fs.Duration("timeout", 0, "probe timeout")
	rateFlag := fs.Int("rate", -1, "maximum probes per second (0 unlimited)")
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
	jsonFlag := fs.Bool("json", false, "newline-delimited JSON output")
	dryRunFlag := fs.Bool("dry-run", false, "resolve and print the plan without scanning")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			scanUsage(out)
		}
		return err
	}

	fc, err := config.ParseFile(*configFlag)
	if err != nil {
		return err
	}
	if *rateFlag < -1 || *workersFlag < -1 || *udpRetriesFlag < -1 {
		return errors.New("rate, workers and UDP retries must be nonnegative")
	}

	opts := config.Options{
		Targets:    append(append([]string{}, fc.Targets...), fs.Args()...),
		Profile:    first(*profileFlag, fc.Profile),
		Ports:      first(*portsFlag, fc.Ports),
		Protocols:  first(*protoFlag, fc.Protocols),
		Timeout:    first(timeoutText(*timeoutFlag), fc.Timeout),
		TCPMode:    first(*tcpModeFlag, fc.TCPMode),
		Interface:  first(*interfaceFlag, fc.Interface),
		SourceIP:   first(*sourceIPFlag, fc.SourceIP),
		SourceMAC:  first(*sourceMACFlag, fc.SourceMAC),
		NextHopMAC: first(*nextHopMACFlag, fc.NextHopMAC),
	}
	opts.Rate = mergeInt(*rateFlag, fc.Rate)
	opts.Workers = mergeInt(*workersFlag, fc.Workers)
	opts.UDPRetries = mergeInt(*udpRetriesFlag, fc.UDPRetries)

	probeFile := *probeFlag
	baseDir := ""
	if probeFile == "" && fc.UDPProbeFile != "" {
		probeFile = fc.UDPProbeFile
		if *configFlag != "" {
			baseDir = filepath.Dir(*configFlag)
		}
	}
	opts.Payload = config.PayloadSource{
		ProbeFile: probeFile, SendHex: *hexFlag, SendBase64: *base64Flag,
		PayloadFile: *fileFlag, BaseDir: baseDir,
	}

	cfg, err := config.Build(opts)
	if err != nil {
		return err
	}

	if *dryRunFlag {
		return emitPlan(out, cfg.Plan(), *jsonFlag)
	}

	encoder := json.NewEncoder(out)
	return scan.Run(context.Background(), cfg, func(o scan.Observation) error {
		if *jsonFlag {
			return encoder.Encode(o)
		}
		port := ""
		if o.Port != 0 {
			port = fmt.Sprintf(":%d", o.Port)
		}
		_, err := fmt.Fprintf(out, "%s%s %-5s %-14s %3d%% %s\n", o.Target, port, o.Transport, o.State, o.Confidence, o.Reason)
		return err
	})
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
	fmt.Fprintf(out, "protocols   %s\n", strings.Join(plan.Protocols, ", "))
	if plan.Ports > 0 {
		fmt.Fprintf(out, "ports       %s\n", plan.PortSummary)
	}
	fmt.Fprintf(out, "timeout     %s\n", plan.Timeout)
	fmt.Fprintf(out, "rate        %s\n", rateText(plan.Rate))
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
	if plan.UDPRetries > 0 {
		fmt.Fprintf(out, "udp-retries %d\n", plan.UDPRetries)
	}
	if len(plan.UDPProbes) > 0 {
		fmt.Fprintf(out, "udp-probes  %s\n", strings.Join(plan.UDPProbes, ", "))
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
		return errors.New("decode requires one pcap file")
	}
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := packet.NewPCAPReader(f)
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
