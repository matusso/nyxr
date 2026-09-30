package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

func buildResearch(o Options, profile Profile) (Config, error) {
	if o.TCPMode != "" && o.TCPMode != "forge" {
		return Config{}, errors.New("research always uses raw forge mode; omit --tcp-mode")
	}
	if o.Payload.count() != 0 || o.UDPRetries != nil {
		return Config{}, errors.New("research uses --forge-payload-hex; UDP probe options are unavailable")
	}
	kind := strings.ToLower(first(o.Research.Kind, o.Protocols, "tcp"))
	if strings.Contains(o.Protocols, ",") {
		return Config{}, errors.New("research permits exactly one protocol")
	}
	if strings.Contains(kind, ",") {
		return Config{}, errors.New("research permits exactly one protocol")
	}
	var ports []uint16
	var err error
	if kind == "tcp" || kind == "udp" || kind == "sctp" {
		ports, err = ResolvePorts(first(o.Ports, profile.Ports))
		if err != nil {
			return Config{}, err
		}
	} else if o.Ports != "" {
		return Config{}, errors.New("ICMP/IP research scans do not use ports")
	}
	timeout, err := time.ParseDuration(first(o.Timeout, profile.Timeout))
	if err != nil {
		return Config{}, err
	}
	targets, err := ParseTargets(o.Targets)
	if err != nil {
		return Config{}, err
	}
	allow, err := ParseAllowTargets(o.AllowTargets)
	if err != nil {
		return Config{}, err
	}
	var source netip.Addr
	if o.SourceIP != "" {
		source, err = netip.ParseAddr(o.SourceIP)
		if err != nil {
			return Config{}, fmt.Errorf("source IP: %w", err)
		}
	}
	var sourceMAC, nextMAC net.HardwareAddr
	if o.SourceMAC != "" {
		sourceMAC, err = net.ParseMAC(o.SourceMAC)
		if err != nil {
			return Config{}, fmt.Errorf("source MAC: %w", err)
		}
	}
	if o.NextHopMAC != "" {
		nextMAC, err = net.ParseMAC(o.NextHopMAC)
		if err != nil {
			return Config{}, fmt.Errorf("next-hop MAC: %w", err)
		}
	}
	ipNumber := uint8(0)
	if o.Research.IPProtocol != "" {
		n, parseErr := strconv.ParseUint(o.Research.IPProtocol, 0, 8)
		if parseErr != nil {
			return Config{}, fmt.Errorf("IP protocol: %w", parseErr)
		}
		ipNumber = uint8(n)
	} else if kind == "ip" {
		return Config{}, errors.New("IP research scan requires --ip-protocol")
	}
	flags := uint8(2)
	if o.Research.TCPFlags != "" {
		flags, err = ParseTCPFlags(o.Research.TCPFlags)
		if err != nil {
			return Config{}, err
		}
	}
	if kind != "tcp" && o.Research.TCPFlags != "" {
		return Config{}, errors.New("TCP flags require TCP research")
	}
	if kind != "ip" && o.Research.IPProtocol != "" {
		return Config{}, errors.New("--ip-protocol requires IP research")
	}
	if o.Research.IPLength < 0 || o.Research.IPLength > 65535 {
		return Config{}, errors.New("forge IP length must fit 16 bits")
	}
	payload, err := hex.DecodeString(strings.Join(strings.Fields(o.Research.PayloadHex), ""))
	if err != nil {
		return Config{}, fmt.Errorf("forge payload hex: %w", err)
	}
	if kind == "sctp" && len(payload) != 0 {
		return Config{}, errors.New("SCTP INIT does not accept a custom payload")
	}
	cfg := Config{Targets: targets, AllowTargets: allow, Ports: ports, TCP: kind == "tcp", Profile: "research", Timeout: timeout,
		Rate: valueOr(o.Rate, profile.Rate), HostRate: valueOr(o.HostRate, 0), SubnetRate: valueOr(o.SubnetRate, 0), InterfaceRate: valueOr(o.InterfaceRate, 0),
		Workers: valueOr(o.Workers, profile.Workers), Interface: o.Interface, SourceIP: source, SourceMAC: sourceMAC, NextHopMAC: nextMAC,
		TCPMode: "forge", Research: &ResearchConfig{Kind: kind, IPProtocol: ipNumber, TCPFlags: flags, FragmentSize: o.Research.FragmentSize,
			BadChecksum: o.Research.BadChecksum, IPLength: uint16(o.Research.IPLength), Payload: payload}}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ParseTCPFlags accepts standard names, a comma list, or a numeric mask.
func ParseTCPFlags(raw string) (uint8, error) {
	if n, err := strconv.ParseUint(raw, 0, 8); err == nil {
		if n > 63 {
			return 0, errors.New("TCP flags must fit FIN,SYN,RST,PSH,ACK,URG")
		}
		return uint8(n), nil
	}
	if strings.EqualFold(raw, "null") {
		return 0, nil
	}
	if strings.EqualFold(raw, "xmas") {
		return 0x29, nil
	}
	values := map[string]uint8{"fin": 1, "syn": 2, "rst": 4, "psh": 8, "ack": 16, "urg": 32}
	var flags uint8
	for _, item := range strings.Split(raw, ",") {
		v, ok := values[strings.ToLower(strings.TrimSpace(item))]
		if !ok {
			return 0, fmt.Errorf("unknown TCP flag %q", item)
		}
		flags |= v
	}
	return flags, nil
}
