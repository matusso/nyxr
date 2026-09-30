package config

import (
	"fmt"
	"strconv"
	"strings"
)

// Plan is a human- and machine-readable summary of a resolved Config. The CLI
// prints it for --dry-run so an operator can confirm the scope, protocols and
// pacing before any packet is sent.
type Plan struct {
	Profile       string   `json:"profile"`
	Targets       int      `json:"targets"`
	SampleTargets []string `json:"sample_targets,omitempty"`
	AllowTargets  []string `json:"allow_targets,omitempty"`
	Ports         int      `json:"ports"`
	PortSummary   string   `json:"port_summary,omitempty"`
	Protocols     []string `json:"protocols"`
	Timeout       string   `json:"timeout"`
	Rate          int      `json:"rate"`
	HostRate      int      `json:"host_rate,omitempty"`
	SubnetRate    int      `json:"subnet_rate,omitempty"`
	InterfaceRate int      `json:"interface_rate,omitempty"`
	Workers       int      `json:"workers"`
	UDPRetries    int      `json:"udp_retries,omitempty"`
	UDPProbes     []string `json:"udp_probes,omitempty"`
	TCPMode       string   `json:"tcp_mode"`
	Interface     string   `json:"interface,omitempty"`
	SourceIP      string   `json:"source_ip,omitempty"`
	SourceMAC     string   `json:"source_mac,omitempty"`
	NextHopMAC    string   `json:"next_hop_mac,omitempty"`
	// Tasks is the number of scheduled probe tasks (targets x protocols x
	// ports, plus one ICMP task per target). It is a task count, not a packet
	// count: a UDP campaign can send several packets per task.
	Tasks int `json:"tasks"`
}

// Plan builds the summary from a resolved Config.
func (c Config) Plan() Plan {
	p := Plan{
		Profile:     c.Profile,
		Targets:     len(c.Targets),
		Ports:       len(c.Ports),
		PortSummary: summarizePorts(c.Ports),
		Protocols:   c.protocolList(),
		Timeout:     c.Timeout.String(),
		Rate:        c.Rate,
		HostRate:    c.HostRate, SubnetRate: c.SubnetRate, InterfaceRate: c.InterfaceRate,
		Workers:    c.Workers,
		UDPRetries: c.UDPRetries,
		TCPMode:    c.TCPMode,
		Interface:  c.Interface,
	}
	if c.SourceIP.IsValid() {
		p.SourceIP = c.SourceIP.String()
	}
	if len(c.SourceMAC) != 0 {
		p.SourceMAC = c.SourceMAC.String()
	}
	if len(c.NextHopMAC) != 0 {
		p.NextHopMAC = c.NextHopMAC.String()
	}
	for i, t := range c.Targets {
		if i == 5 {
			break
		}
		p.SampleTargets = append(p.SampleTargets, t.String())
	}
	for _, prefix := range c.AllowTargets {
		p.AllowTargets = append(p.AllowTargets, prefix.String())
	}
	for _, pr := range c.UDPProbes {
		p.UDPProbes = append(p.UDPProbes, pr.Name)
	}
	perTarget := 0
	if c.TCP {
		perTarget += len(c.Ports)
	}
	if c.UDP {
		perTarget += len(c.Ports)
	}
	if c.ICMP {
		perTarget++
	}
	p.Tasks = perTarget * len(c.Targets)
	if c.ARP || c.NDP {
		p.Tasks = len(c.Targets)
	}
	return p
}

func (c Config) protocolList() []string {
	var protos []string
	if c.TCP {
		protos = append(protos, "tcp")
	}
	if c.UDP {
		protos = append(protos, "udp")
	}
	if c.ICMP {
		protos = append(protos, "icmp")
	}
	if c.ARP {
		protos = append(protos, "arp")
	}
	if c.NDP {
		protos = append(protos, "ndp")
	}
	return protos
}

// summarizePorts renders a compact port description: the exact list when short,
// otherwise a count with the range endpoints.
func summarizePorts(ports []uint16) string {
	if len(ports) == 0 {
		return ""
	}
	if len(ports) <= 16 {
		parts := make([]string, len(ports))
		for i, p := range ports {
			parts[i] = strconv.Itoa(int(p))
		}
		return strings.Join(parts, ",")
	}
	return fmt.Sprintf("%d ports (%d-%d)", len(ports), ports[0], ports[len(ports)-1])
}
