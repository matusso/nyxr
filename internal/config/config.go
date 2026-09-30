package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/probe"
)

// Config is shared by the CLI and scan engine. A future API can use the same
// validated object without inheriting command-line parsing behavior.
type Config struct {
	Targets    []netip.Addr
	Ports      []uint16
	TCP        bool
	UDP        bool
	ICMP       bool
	Timeout    time.Duration
	Rate       int
	Workers    int
	Profile    string
	UDPProbes  []probe.Probe
	UDPRetries int
}

const MaxTargets = 65536

func (c Config) Validate() error {
	if len(c.Targets) == 0 || (!c.TCP && !c.UDP && !c.ICMP) {
		return errors.New("at least one target and protocol are required")
	}
	if (c.TCP || c.UDP) && len(c.Ports) == 0 {
		return errors.New("TCP or UDP requires at least one port")
	}
	if c.Timeout <= 0 || c.Workers < 1 || c.Workers > 4096 || c.Rate < 0 {
		return errors.New("timeout must be positive, workers 1..4096, and rate nonnegative")
	}
	if c.UDPRetries < 0 || c.UDPRetries > 5 || len(c.UDPProbes) > 256 {
		return errors.New("UDP retries must be 0..5 and custom probes at most 256")
	}
	return nil
}

func ParseProtocols(s string) (tcp, udp, icmp bool, err error) {
	for _, part := range strings.Split(s, ",") {
		switch strings.ToLower(strings.TrimSpace(part)) {
		case "tcp":
			tcp = true
		case "udp":
			udp = true
		case "icmp":
			icmp = true
		default:
			return false, false, false, fmt.Errorf("unknown protocol %q", part)
		}
	}
	return
}

func ParsePorts(s string) ([]uint16, error) {
	seen := make(map[uint16]bool)
	for _, part := range strings.Split(s, ",") {
		bounds := strings.Split(strings.TrimSpace(part), "-")
		if len(bounds) == 0 || len(bounds) > 2 {
			return nil, fmt.Errorf("invalid port range %q", part)
		}
		lo, err := strconv.Atoi(bounds[0])
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		hi := lo
		if len(bounds) == 2 {
			hi, err = strconv.Atoi(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", part)
			}
		}
		if lo < 1 || hi > 65535 || hi < lo {
			return nil, fmt.Errorf("invalid port range %q", part)
		}
		for p := lo; p <= hi; p++ {
			seen[uint16(p)] = true
		}
	}
	ports := make([]uint16, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports, nil
}

// ParseTargets accepts addresses, CIDRs, inclusive address ranges, and DNS
// names. Large ranges are refused before scan tasks are generated.
func ParseTargets(inputs []string) ([]netip.Addr, error) {
	seen := make(map[netip.Addr]bool)
	add := func(a netip.Addr) error {
		a = a.Unmap()
		if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() {
			return fmt.Errorf("unsupported target %s", a)
		}
		seen[a] = true
		if len(seen) > MaxTargets {
			return fmt.Errorf("target limit of %d exceeded", MaxTargets)
		}
		return nil
	}
	for _, input := range inputs {
		for _, token := range strings.Split(input, ",") {
			token = strings.TrimSpace(token)
			if token == "" {
				return nil, errors.New("empty target")
			}
			if prefix, err := netip.ParsePrefix(token); err == nil {
				prefix = prefix.Masked()
				for a := prefix.Addr(); prefix.Contains(a); a = a.Next() {
					if err := add(a); err != nil {
						return nil, err
					}
					if !a.Next().IsValid() {
						break
					}
				}
				continue
			}
			if a, err := netip.ParseAddr(token); err == nil {
				if err := add(a); err != nil {
					return nil, err
				}
				continue
			}
			if parts := strings.Split(token, "-"); len(parts) == 2 {
				start, e1 := netip.ParseAddr(parts[0])
				end, e2 := netip.ParseAddr(parts[1])
				if e1 == nil && e2 == nil {
					if start.Is4() != end.Is4() || start.Compare(end) > 0 {
						return nil, fmt.Errorf("invalid target range %q", token)
					}
					for a := start; a.Compare(end) <= 0; a = a.Next() {
						if err := add(a); err != nil {
							return nil, err
						}
						if a == end {
							break
						}
					}
					continue
				}
			}
			ips, err := net.LookupIP(token)
			if err != nil {
				return nil, fmt.Errorf("resolve %q: %w", token, err)
			}
			for _, ip := range ips {
				a, ok := netip.AddrFromSlice(ip)
				if ok {
					if err := add(a); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	result := make([]netip.Addr, 0, len(seen))
	for a := range seen {
		result = append(result, a)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Compare(result[j]) < 0 })
	return result, nil
}
