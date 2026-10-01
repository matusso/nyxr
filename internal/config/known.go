package config

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// KnownPort is a port a stored scan last observed open.
type KnownPort struct {
	Address   netip.Addr
	Transport string // tcp or udp
	Port      uint16
}

// KnownPortSource returns every stored port whose latest state is open.
type KnownPortSource func() ([]KnownPort, error)

// TargetPorts restricts a scan to listed transport/port pairs per address.
// A nil TargetPorts scans every configured port on every target.
type TargetPorts map[netip.Addr]map[portKey]bool

type portKey struct {
	transport string
	port      uint16
}

// Includes reports whether the scan probes transport/port on target.
func (c Config) Includes(target netip.Addr, transport string, port uint16) bool {
	if c.TargetPorts == nil {
		return true
	}
	return c.TargetPorts[target][portKey{transport, port}]
}

// KnownProfile is the profile a known-open rescan uses when none is named:
// its service probes are the point of the rescan.
const KnownProfile = "service"

// applyKnownOpen rewrites a KnownOpen request into explicit targets, ports
// and protocols drawn from the database. Targets, when given, are a scope
// (IPs, CIDRs or ranges) that narrows the stored addresses. It returns the
// per-target restriction that keeps the rescan to exactly the known pairs.
func (r *Request) applyKnownOpen(source KnownPortSource) (TargetPorts, error) {
	if source == nil {
		return nil, errors.New("known_open needs a database of earlier scans")
	}
	if r.Profile == "research" {
		return nil, errors.New("known_open cannot be combined with the research profile")
	}
	if r.Ports != "" || r.Protocols != "" {
		return nil, errors.New("known_open takes ports and protocols from the database; drop ports and protocols")
	}
	scope, err := ParseScope(r.Targets)
	if err != nil {
		return nil, fmt.Errorf("known_open targets: %w", err)
	}
	known, err := source()
	if err != nil {
		return nil, fmt.Errorf("known_open: %w", err)
	}
	restrict := TargetPorts{}
	ports := map[uint16]bool{}
	var tcp, udp bool
	for _, k := range known {
		if !scope.Contains(k.Address) || (k.Transport != "tcp" && k.Transport != "udp") || k.Port == 0 {
			continue
		}
		addr := k.Address.Unmap()
		if restrict[addr] == nil {
			restrict[addr] = map[portKey]bool{}
		}
		restrict[addr][portKey{k.Transport, k.Port}] = true
		ports[k.Port] = true
		tcp = tcp || k.Transport == "tcp"
		udp = udp || k.Transport == "udp"
	}
	if len(restrict) == 0 {
		where := "the database"
		if !scope.Empty() {
			where = strings.Join(r.Targets, ", ")
		}
		return nil, fmt.Errorf("no open ports are known for %s; run a discovery scan first", where)
	}
	targets := make([]string, 0, len(restrict))
	for a := range restrict {
		targets = append(targets, a.String())
	}
	sort.Slice(targets, func(i, j int) bool {
		return netip.MustParseAddr(targets[i]).Compare(netip.MustParseAddr(targets[j])) < 0
	})
	list := make([]int, 0, len(ports))
	for p := range ports {
		list = append(list, int(p))
	}
	sort.Ints(list)
	spec := make([]string, len(list))
	for i, p := range list {
		spec[i] = strconv.Itoa(p)
	}
	var protocols []string
	if tcp {
		protocols = append(protocols, "tcp")
	}
	if udp {
		protocols = append(protocols, "udp")
	}
	r.Targets, r.Ports, r.Protocols = targets, strings.Join(spec, ","), strings.Join(protocols, ",")
	if r.Profile == "" {
		r.Profile = KnownProfile
	}
	if r.Service == nil && tcp {
		on := true
		r.Service = &on
	}
	return restrict, nil
}

// tasks counts the probes a restricted scan sends.
func (t TargetPorts) tasks(tcp, udp bool) int {
	n := 0
	for _, pairs := range t {
		for k := range pairs {
			if (k.transport == "tcp" && tcp) || (k.transport == "udp" && udp) {
				n++
			}
		}
	}
	return n
}
