package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
	"github.com/matusso/nyxr/internal/scan"
	"gopkg.in/yaml.v3"
)

var version = "dev"

type fileConfig struct {
	Targets   []string `yaml:"targets"`
	Ports     string   `yaml:"ports"`
	Protocols string   `yaml:"protocols"`
	Timeout   string   `yaml:"timeout"`
	Rate      int      `yaml:"rate"`
	Workers   int      `yaml:"workers"`
	Profile   string   `yaml:"profile"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "scanner:", err)
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
	case "decode":
		return runDecode(args[1:], out)
	case "sniff":
		return runSniff(args[1:], out)
	case "version":
		_, err := fmt.Fprintln(out, version)
		return err
	case "help", "-h", "--help":
		return usage(out)
	default:
		return fmt.Errorf("unknown command %q (try scanner help)", args[0])
	}
}

func usage(out io.Writer) error {
	_, err := fmt.Fprintln(out, "Usage: scanner scan [flags] target [target...]\n       scanner decode capture.pcap\n       scanner sniff --interface eth0 [--count 100]\n       scanner version\n\nScan flags: --ports, --protocols, --profile, --timeout, --rate, --workers, --config, --json")
	return err
}

func readConfig(path string) (fileConfig, error) {
	var cfg fileConfig
	if path == "" {
		return cfg, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	decoder := yaml.NewDecoder(f)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func runScan(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	portsFlag := fs.String("ports", "", "comma-separated ports and ranges")
	protoFlag := fs.String("protocols", "", "tcp,udp,icmp")
	profileFlag := fs.String("profile", "", "discovery, tcp, udp, ot-safe")
	timeoutFlag := fs.Duration("timeout", 0, "probe timeout")
	rateFlag := fs.Int("rate", -1, "maximum probes per second (0 unlimited)")
	workersFlag := fs.Int("workers", -1, "concurrent probe workers")
	configFlag := fs.String("config", "", "YAML configuration file")
	jsonFlag := fs.Bool("json", false, "newline-delimited JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fc, err := readConfig(*configFlag)
	if err != nil {
		return err
	}
	profile := first(*profileFlag, fc.Profile, "discovery")
	var defaults fileConfig
	switch profile {
	case "discovery", "tcp":
		defaults = fileConfig{Ports: "22,80,443", Protocols: "tcp", Timeout: "1s", Rate: 100, Workers: 64}
	case "udp":
		defaults = fileConfig{Ports: "53,123", Protocols: "udp", Timeout: "1500ms", Rate: 50, Workers: 32}
	case "ot-safe":
		defaults = fileConfig{Ports: "80,443,502", Protocols: "tcp", Timeout: "3s", Rate: 5, Workers: 4}
	default:
		return fmt.Errorf("unknown profile %q", profile)
	}
	ports, err := config.ParsePorts(first(*portsFlag, fc.Ports, defaults.Ports))
	if err != nil {
		return err
	}
	tcp, udp, icmp, err := config.ParseProtocols(first(*protoFlag, fc.Protocols, defaults.Protocols))
	if err != nil {
		return err
	}
	timeout, err := time.ParseDuration(first(timeoutText(*timeoutFlag), fc.Timeout, defaults.Timeout))
	if err != nil {
		return err
	}
	rate := defaults.Rate
	if fc.Rate != 0 {
		rate = fc.Rate
	}
	if *rateFlag >= 0 {
		rate = *rateFlag
	}
	workers := defaults.Workers
	if fc.Workers != 0 {
		workers = fc.Workers
	}
	if *workersFlag >= 0 {
		workers = *workersFlag
	}
	if profile == "ot-safe" && (rate > 5 || workers > 4 || timeout < 3*time.Second || udp || icmp) {
		return errors.New("ot-safe requires TCP only, rate <=5, workers <=4, and timeout >=3s")
	}
	targetInputs := append(append([]string{}, fc.Targets...), fs.Args()...)
	targets, err := config.ParseTargets(targetInputs)
	if err != nil {
		return err
	}
	cfg := config.Config{Targets: targets, Ports: ports, TCP: tcp, UDP: udp, ICMP: icmp,
		Timeout: timeout, Rate: rate, Workers: workers, Profile: profile}
	if err := cfg.Validate(); err != nil {
		return err
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

func first(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
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
	io, err := packetio.OpenLive(*device)
	if err != nil {
		return err
	}
	defer io.Close()
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
		n, err := io.ReceiveBatch(ctx, buffers)
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
