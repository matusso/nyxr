// Package nse runs selected, locally installed Nmap scripts against ports
// nyxr discovered and imports Nmap's XML results into observation records.
package nse

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/observe"
)

const maxOutput = 4 << 20

type Port struct {
	Transport string
	Number    uint16
}

type Executor interface {
	Validate(context.Context, config.NSE) error
	RunHost(context.Context, config.NSE, netip.Addr, []Port, int) ([]observe.Observation, error)
}

// Runner uses Binary when supplied (also useful for isolated tests), or the
// Nmap executable in PATH. The selector itself always requires Nmap's safe
// category, even if a local script database changes after validation.
type Runner struct{ Binary string }

func (r Runner) binary() string {
	if r.Binary != "" {
		return r.Binary
	}
	return "nmap"
}

func selector(names []string) string {
	return "(" + strings.Join(names, " or ") + ") and safe and not (intrusive or exploit or dos or external or fuzzer or brute)"
}

// Validate checks that every requested name resolves to an installed script
// in the safe category. Nmap's script-help performs no network scan.
func (r Runner) Validate(ctx context.Context, cfg config.NSE) error {
	if !cfg.Enabled() {
		return nil
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var stdout, stderr boundedBuffer
	cmd := exec.CommandContext(checkCtx, r.binary(), "--script-help", selector(cfg.Scripts))
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nmap --script-help: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if stdout.truncated || stderr.truncated {
		return errors.New("nmap --script-help output exceeded limit")
	}
	found := make(map[string]bool)
	wanted := make(map[string]bool, len(cfg.Scripts))
	for _, name := range cfg.Scripts {
		wanted[name] = true
	}
	current := ""
	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if wanted[line] {
			current = line
		} else if strings.HasPrefix(line, "Categories:") && current != "" {
			categories := strings.Fields(strings.TrimPrefix(line, "Categories:"))
			blocked := false
			for _, category := range categories {
				switch category {
				case "intrusive", "exploit", "dos", "external", "fuzzer", "brute":
					blocked = true
				}
			}
			for _, category := range categories {
				if category == "safe" && !blocked {
					found[current] = true
				}
			}
			current = ""
		}
	}
	for _, name := range cfg.Scripts {
		if !found[name] {
			return fmt.Errorf("NSE script %q is not installed or not in Nmap's safe category", name)
		}
	}
	return nil
}

// RunHost invokes one bounded Nmap process for a host's discovered open ports.
// Nmap rechecks those ports before applying NSE portrules.
func (r Runner) RunHost(ctx context.Context, cfg config.NSE, target netip.Addr, ports []Port, maxRate int) ([]observe.Observation, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		return nil, nil
	}
	var tcp, udp []int
	allowed := make(map[Port]bool, len(ports))
	for _, port := range ports {
		if port.Number == 0 || (port.Transport != "tcp" && port.Transport != "udp") {
			return nil, fmt.Errorf("unsupported NSE port %s/%d", port.Transport, port.Number)
		}
		if allowed[port] {
			continue
		}
		allowed[port] = true
		if port.Transport == "tcp" {
			tcp = append(tcp, int(port.Number))
		} else {
			udp = append(udp, int(port.Number))
		}
	}
	sort.Ints(tcp)
	sort.Ints(udp)
	var portSpec []string
	args := []string{"-n", "-Pn"}
	if len(tcp) > 0 {
		args = append(args, "-sT")
		portSpec = append(portSpec, "T:"+joinPorts(tcp))
	}
	if len(udp) > 0 {
		args = append(args, "-sU")
		portSpec = append(portSpec, "U:"+joinPorts(udp))
	}
	if target.Is6() {
		args = append(args, "-6")
	}
	args = append(args, "-p", strings.Join(portSpec, ","), "--script", selector(cfg.Scripts),
		"--script-timeout", cfg.Timeout.String(), "--host-timeout", cfg.Timeout.String(), "-oX", "-")
	if maxRate > 0 {
		args = append(args, "--max-rate", strconv.Itoa(maxRate))
	}
	args = append(args, target.String())
	runCtx, cancel := context.WithTimeout(ctx, cfg.Timeout+2*time.Second)
	defer cancel()
	var stdout, stderr boundedBuffer
	cmd := exec.CommandContext(runCtx, r.binary(), args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nmap NSE on %s: %w: %s", target, err, strings.TrimSpace(stderr.String()))
	}
	if stdout.truncated || stderr.truncated {
		return nil, fmt.Errorf("nmap NSE on %s: output exceeded limit", target)
	}
	return parseXML(stdout.Bytes(), target, allowed, cfg.Scripts)
}

func joinPorts(ports []int) string {
	values := make([]string, len(ports))
	for i, port := range ports {
		values[i] = strconv.Itoa(port)
	}
	return strings.Join(values, ",")
}

type boundedBuffer struct {
	bytes.Buffer
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxOutput {
		b.truncated = true
		return 0, errors.New("Nmap output exceeded limit")
	}
	return b.Buffer.Write(p)
}

type xmlRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []struct {
		Addresses []struct {
			Addr string `xml:"addr,attr"`
		} `xml:"address"`
		Ports []struct {
			Protocol string      `xml:"protocol,attr"`
			ID       uint16      `xml:"portid,attr"`
			Scripts  []xmlScript `xml:"script"`
		} `xml:"ports>port"`
		Scripts []xmlScript `xml:"hostscript>script"`
	} `xml:"host"`
}

type xmlScript struct {
	ID     string     `xml:"id,attr"`
	Output string     `xml:"output,attr"`
	Fields []xmlField `xml:",any"`
}

type xmlField struct {
	XMLName  xml.Name
	Key      string     `xml:"key,attr"`
	Value    string     `xml:",chardata"`
	Children []xmlField `xml:",any"`
}

func parseXML(data []byte, target netip.Addr, allowed map[Port]bool, scripts []string) ([]observe.Observation, error) {
	var doc xmlRun
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse Nmap XML: %w", err)
	}
	var out []observe.Observation
	wanted := make(map[string]bool, len(scripts))
	for _, script := range scripts {
		wanted[script] = true
	}
	for _, host := range doc.Hosts {
		match := false
		for _, addr := range host.Addresses {
			if parsed, err := netip.ParseAddr(addr.Addr); err == nil && parsed == target {
				match = true
			}
		}
		if !match {
			continue
		}
		for _, port := range host.Ports {
			if !allowed[Port{port.Protocol, port.ID}] {
				continue
			}
			for _, script := range port.Scripts {
				if wanted[script.ID] {
					out = append(out, result(target, port.Protocol, port.ID, script))
				}
			}
		}
		for _, script := range host.Scripts {
			if wanted[script.ID] {
				out = append(out, result(target, "host", 0, script))
			}
		}
	}
	return out, nil
}

func result(target netip.Addr, transport string, port uint16, script xmlScript) observe.Observation {
	fields := make([]observe.NSEField, 0, len(script.Fields))
	for _, field := range script.Fields {
		if field.XMLName.Local == "table" || field.XMLName.Local == "elem" {
			fields = append(fields, convertField(field))
		}
	}
	return observe.Observation{Kind: observe.KindScript, Timestamp: time.Now().UTC(), Target: target,
		Transport: transport, Port: port, State: "reported", Confidence: 100,
		Reason: "Nmap NSE script output", Probe: "nse/" + script.ID,
		NSE: &observe.NSEResult{ID: script.ID, Output: script.Output, Fields: fields}}
}

func convertField(in xmlField) observe.NSEField {
	out := observe.NSEField{Kind: in.XMLName.Local, Key: in.Key, Value: strings.TrimSpace(in.Value)}
	for _, child := range in.Children {
		if child.XMLName.Local == "table" || child.XMLName.Local == "elem" {
			out.Children = append(out.Children, convertField(child))
		}
	}
	return out
}
