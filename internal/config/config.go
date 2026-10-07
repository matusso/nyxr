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
	Targets       []netip.Addr
	TargetStream  *TargetStream  // compact IPv4 ranges for large SYN scans
	AllowTargets  []netip.Prefix // explicit CIDR/IP authorization for target policy
	Ports         []uint16
	UDPPorts      []uint16 // UDP ports when they differ from Ports; nil means Ports
	TCP           bool
	UDP           bool
	ICMP          bool
	ARP           bool
	NDP           bool
	Timeout       time.Duration
	Rate          int
	HostRate      int // probes/s to one address
	SubnetRate    int // probes/s to one IPv4 /24 or IPv6 /64
	InterfaceRate int // probes/s on the selected raw interface
	Workers       int
	Profile       string
	UDPProbes     []probe.Probe
	UDPMode       UDPMode
	UDPRetries    int
	NmapUDPSource string // local source path for imported UDP payloads
	NmapUDPSHA    string // SHA-256 of the imported file
	TCPMode       string // connect (default) or syn
	Interface     string // required for raw Ethernet SYN scans
	XDPPinDir     string // pinned maps for opt-in Linux AF_XDP SYN I/O
	SourceIP      netip.Addr
	SourceMAC     net.HardwareAddr
	NextHopMAC    net.HardwareAddr
	Research      *ResearchConfig

	StackFingerprint bool // set by the fingerprint stage for raw SYN scans

	// TargetPorts, when set, limits each target to its listed ports
	// (a known-open rescan).
	TargetPorts TargetPorts
}

type UDPMode string

const (
	UDPBasic  UDPMode = "basic"
	UDPCommon UDPMode = "common"
	UDPFull   UDPMode = "full"
)

// ResearchConfig is deliberately separate from ordinary scan modes. Only a
// validated research profile can carry raw header or malformed controls.
type ResearchConfig struct {
	Kind         string // tcp, udp, icmp, sctp, ip
	IPProtocol   uint8
	TCPFlags     uint8
	FragmentSize int
	BadChecksum  bool
	IPLength     uint16 // zero means computed length
	Payload      []byte
}

const MaxTargets = 65536

// PortsFor returns the ports scanned for transport ("tcp" or "udp").
func (c Config) PortsFor(transport string) []uint16 {
	if transport == "udp" && c.UDPPorts != nil {
		return c.UDPPorts
	}
	return c.Ports
}

func (c Config) Validate() error {
	if c.Profile == "research" && c.Research == nil {
		return errors.New("research profile requires a validated research packet configuration")
	}
	if c.Research != nil {
		return c.validateResearch()
	}
	if c.TargetCount() == 0 || (!c.TCP && !c.UDP && !c.ICMP && !c.ARP && !c.NDP) {
		return errors.New("at least one target and protocol are required")
	}
	if c.UDPMode != "" && c.UDPMode != UDPBasic && c.UDPMode != UDPCommon && c.UDPMode != UDPFull {
		return fmt.Errorf("unknown UDP mode %q", c.UDPMode)
	}
	if c.UDPMode == UDPBasic && len(c.UDPProbes) != 0 {
		return errors.New("udp-basic does not use payload probes")
	}
	if c.Profile == "ot-safe" && len(c.AllowTargets) == 0 {
		return errors.New("ot-safe requires --allow-targets")
	}
	if err := c.TargetStream.validateAllowed(c.AllowTargets); err != nil {
		return err
	}
	for _, target := range c.Targets {
		if len(c.AllowTargets) == 0 {
			break
		}
		allowed := false
		for _, prefix := range c.AllowTargets {
			if prefix.Contains(target) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("target %s is outside --allow-targets", target)
		}
	}
	if c.Profile == "ot-safe" {
		if !c.TCP || c.UDP || c.ICMP || c.ARP || c.NDP || c.TCPMode == "syn" || len(c.UDPProbes) > 0 || c.UDPRetries > 0 {
			return errors.New("ot-safe permits TCP connect and approved identity probes only")
		}
		if c.Rate < 1 || c.Rate > 5 || c.Workers > 4 || c.Timeout < 3*time.Second {
			return errors.New("ot-safe requires rate 1..5, workers <=4 and timeout >=3s")
		}
		for _, port := range c.Ports {
			if port != 80 && port != 443 && port != 502 && port != 44818 {
				return fmt.Errorf("ot-safe does not permit port %d", port)
			}
		}
	}
	if (c.TCP || c.UDP) && len(c.Ports) == 0 {
		return errors.New("TCP or UDP requires at least one port")
	}
	if c.Timeout <= 0 || c.Workers < 1 || c.Workers > 4096 || c.Rate < 0 {
		return errors.New("timeout must be positive, workers 1..4096, and rate nonnegative")
	}
	if c.HostRate < 0 || c.SubnetRate < 0 || c.InterfaceRate < 0 {
		return errors.New("host, subnet and interface rates must be nonnegative")
	}
	if c.InterfaceRate > 0 && c.TCPMode != "syn" && !c.ARP && !c.NDP {
		return errors.New("interface rate requires raw SYN, ARP or NDP mode")
	}
	if c.ARP || c.NDP {
		if c.TCP || c.UDP || c.ICMP || c.Interface == "" {
			return errors.New("ARP/NDP discovery requires an interface and cannot be mixed with TCP, UDP or ICMP")
		}
		if len(c.SourceMAC) != 0 && (len(c.SourceMAC) != 6 || c.SourceMAC[0]&1 != 0 || isZeroMAC(c.SourceMAC)) {
			return errors.New("neighbor discovery source MAC must be a unicast Ethernet address")
		}
		if c.SourceIP.IsValid() && (c.SourceIP.IsUnspecified() || c.SourceIP.IsMulticast() || (c.ARP && c.NDP)) {
			return errors.New("neighbor discovery source IP must be unicast and cannot override both ARP and NDP")
		}
		if c.SourceIP.IsValid() && ((c.ARP && !c.SourceIP.Is4()) || (c.NDP && !c.SourceIP.Is6())) {
			return errors.New("neighbor discovery source IP must match the selected address family")
		}
		if len(c.NextHopMAC) != 0 {
			return errors.New("ARP/NDP discovery does not use a next-hop MAC override")
		}
		for _, target := range c.Targets {
			if (target.Is4() && !c.ARP) || (target.Is6() && !c.NDP) {
				return fmt.Errorf("no ARP/NDP discovery protocol selected for %s", target)
			}
		}
	}
	if c.UDPRetries < 0 || c.UDPRetries > 5 {
		return errors.New("UDP retries must be 0..5")
	}
	if c.TCPMode != "" && c.TCPMode != "connect" && c.TCPMode != "syn" {
		return fmt.Errorf("unknown TCP mode %q", c.TCPMode)
	}
	if c.XDPPinDir != "" && c.TCPMode != "syn" {
		return errors.New("AF_XDP requires TCP SYN mode")
	}
	if c.TCPMode == "syn" {
		if !c.TCP || c.UDP || c.ICMP || c.ARP || c.NDP {
			return errors.New("TCP SYN mode requires TCP-only scanning")
		}
		if c.Profile == "ot-safe" {
			return errors.New("ot-safe requires TCP connect mode")
		}
		if c.Interface == "" {
			return errors.New("TCP SYN mode requires an Ethernet interface")
		}
		if len(c.SourceMAC) != 0 && len(c.SourceMAC) != 6 {
			return errors.New("source MAC must be an Ethernet address")
		}
		if len(c.SourceMAC) == 6 && (c.SourceMAC[0]&1 != 0 || isZeroMAC(c.SourceMAC)) {
			return errors.New("source MAC must be a unicast Ethernet address")
		}
		if c.SourceIP.IsValid() && !c.SourceIP.Is4() {
			return errors.New("TCP SYN mode currently requires an IPv4 source")
		}
		if c.SourceIP.IsValid() && (c.SourceIP.IsUnspecified() || c.SourceIP.IsMulticast()) {
			return errors.New("TCP SYN source must be a unicast IPv4 address")
		}
		if len(c.NextHopMAC) != 0 && len(c.NextHopMAC) != 6 {
			return errors.New("TCP SYN next-hop MAC must be an Ethernet address")
		}
		if len(c.NextHopMAC) == 6 && (c.NextHopMAC[0]&1 != 0 || isZeroMAC(c.NextHopMAC)) {
			return errors.New("TCP SYN next-hop MAC must be a unicast Ethernet address")
		}
		for _, target := range c.Targets {
			if !target.Is4() {
				return errors.New("TCP SYN mode currently supports IPv4 targets only")
			}
		}
	}
	return nil
}

func (c Config) validateResearch() error {
	if c.Profile != "research" || c.Research == nil {
		return errors.New("raw research controls require the research profile")
	}
	if len(c.Targets) == 0 || len(c.Targets) > 256 || len(c.AllowTargets) == 0 {
		return errors.New("research requires 1..256 targets and --allow-targets")
	}
	for _, target := range c.Targets {
		if target.Is4() != c.Targets[0].Is4() {
			return errors.New("research targets must share one IP family")
		}
		allowed := false
		for _, prefix := range c.AllowTargets {
			if prefix.Contains(target) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("target %s is outside --allow-targets", target)
		}
	}
	if c.Interface == "" || c.Timeout <= 0 || c.Timeout > 5*time.Second || c.Rate < 1 || c.Rate > 5 || c.Workers != 1 {
		return errors.New("research requires an interface, timeout 1ns..5s, rate 1..5 and one worker")
	}
	if c.HostRate < 0 || c.SubnetRate < 0 || c.InterfaceRate < 0 || c.InterfaceRate > 5 {
		return errors.New("research scoped rates must be nonnegative and interface rate <=5")
	}
	if c.UDP || c.ICMP || c.ARP || c.NDP || c.UDPRetries != 0 || len(c.UDPProbes) != 0 {
		return errors.New("research cannot mix ordinary discovery protocols or UDP probes")
	}
	if c.TCP != (c.Research.Kind == "tcp") || c.TCPMode != "forge" {
		return errors.New("research protocol flags do not match forge mode")
	}
	if c.Research.TCPFlags > 63 {
		return errors.New("research TCP flags exceed six supported bits")
	}
	if c.Research.Kind != "tcp" && c.Research.TCPFlags != 2 {
		return errors.New("TCP flags require TCP research")
	}
	if len(c.SourceMAC) != 0 && (len(c.SourceMAC) != 6 || c.SourceMAC[0]&1 != 0 || isZeroMAC(c.SourceMAC)) {
		return errors.New("research source MAC must be unicast Ethernet")
	}
	if len(c.NextHopMAC) != 0 && (len(c.NextHopMAC) != 6 || c.NextHopMAC[0]&1 != 0 || isZeroMAC(c.NextHopMAC)) {
		return errors.New("research next-hop MAC must be unicast Ethernet")
	}
	if c.SourceIP.IsValid() && (c.SourceIP.IsUnspecified() || c.SourceIP.IsMulticast()) {
		return errors.New("research source IP must be unicast")
	}
	for _, target := range c.Targets {
		if c.SourceIP.IsValid() && target.Is4() != c.SourceIP.Is4() {
			return errors.New("research source and targets must use one IP family")
		}
	}
	if len(c.Research.Payload) > 1400 || c.Research.FragmentSize < 0 || c.Research.FragmentSize > 1400 || (c.Research.FragmentSize != 0 && (c.Research.FragmentSize < 8 || c.Research.FragmentSize%8 != 0)) {
		return errors.New("research payload and fragmentation must fit a 1400-byte frame")
	}
	switch c.Research.Kind {
	case "tcp", "udp", "sctp":
		if len(c.Ports) == 0 || len(c.Ports) > 1024 {
			return errors.New("research transport scan requires 1..1024 ports")
		}
		for _, port := range c.Ports {
			if port == 0 {
				return errors.New("research transport ports must be nonzero")
			}
		}
	case "icmp", "ip":
		if len(c.Ports) != 0 {
			return errors.New("research ICMP/IP scans do not use ports")
		}
	default:
		return fmt.Errorf("unsupported research kind %q", c.Research.Kind)
	}
	if c.Research.BadChecksum && (c.Research.Kind == "ip" || c.Research.Kind == "sctp") {
		return errors.New("bad checksum override currently supports TCP, UDP and ICMP research")
	}
	if c.Research.Kind == "sctp" && len(c.Research.Payload) != 0 {
		return errors.New("SCTP INIT does not accept a custom payload")
	}
	return nil
}

// ParseAllowTargets accepts only literal addresses and CIDRs. DNS names are
// deliberately excluded so resolution cannot widen an approved target set.
func ParseAllowTargets(inputs []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, input := range inputs {
		for _, token := range strings.Split(input, ",") {
			token = strings.TrimSpace(token)
			if token == "" {
				return nil, errors.New("empty allow-targets entry")
			}
			p, err := netip.ParsePrefix(token)
			if err != nil {
				a, addrErr := netip.ParseAddr(token)
				if addrErr != nil {
					return nil, fmt.Errorf("allow-targets entry %q must be an IP or CIDR", token)
				}
				p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
			}
			if !p.Addr().IsValid() || p.Addr().Is4In6() {
				return nil, fmt.Errorf("invalid allow-targets entry %q", token)
			}
			out = append(out, p.Masked())
		}
	}
	return out, nil
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

func ParseProtocols(s string) (tcp, udp, icmp, arp, ndp bool, err error) {
	for _, part := range strings.Split(s, ",") {
		switch strings.ToLower(strings.TrimSpace(part)) {
		case "tcp":
			tcp = true
		case "udp":
			udp = true
		case "icmp":
			icmp = true
		case "arp":
			arp = true
		case "ndp":
			ndp = true
		default:
			return false, false, false, false, false, fmt.Errorf("unknown protocol %q", part)
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
