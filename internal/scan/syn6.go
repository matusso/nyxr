package scan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
)

// syn6Group is the set of targets one interface address sends to. Link-local
// and global targets need different sources, so one scan may run several.
type syn6Group struct {
	source  netip.Addr
	targets []netip.Addr
}

// runSYN6 is the IPv6 front end of the shared SYN engine. It picks a source
// per target scope, resolves next hops through the IPv6 route table and NDP,
// and reports link-local targets with the scan interface as their zone.
func runSYN6(parent context.Context, cfg config.Config, emit func(Observation) error, open liveOpener) error {
	if cfg.XDPPinDir != "" {
		return fmt.Errorf("AF_XDP SYN supports IPv4 targets only; omit --xdp-pin-dir for IPv6 targets")
	}
	targets, zones, err := unscopedSYN6Targets(cfg.Targets, cfg.Interface)
	if err != nil {
		return err
	}
	iface, lookupErr := net.InterfaceByName(cfg.Interface)
	var srcMAC net.HardwareAddr
	var groups []syn6Group
	var linkLocal netip.Addr
	if lookupErr == nil {
		if len(iface.HardwareAddr) != 6 {
			return fmt.Errorf("interface %s is not Ethernet", cfg.Interface)
		}
		srcMAC = iface.HardwareAddr
		if len(cfg.SourceMAC) != 0 && string(cfg.SourceMAC) != string(srcMAC) {
			if !kernelNeighborProbes {
				return fmt.Errorf("source MAC does not match interface %s", cfg.Interface)
			}
			srcMAC = cfg.SourceMAC
		}
		addrs, err := ipv6InterfaceAddrs(iface)
		if err != nil {
			return err
		}
		for _, prefix := range addrs {
			if prefix.Addr().IsLinkLocalUnicast() {
				linkLocal = prefix.Addr()
				break
			}
		}
		groups, err = groupIPv6Sources(cfg.Interface, addrs, cfg.SourceIP, targets)
		if err != nil {
			return err
		}
	} else {
		// An Npcap device ID is not an OS interface, so neither its
		// addresses nor its link-local scope can be discovered.
		if !cfg.SourceIP.Is6() || len(cfg.SourceMAC) != 6 {
			return fmt.Errorf("interface %s not found by OS; specify an IPv6 source IP and source MAC for an Npcap adapter", cfg.Interface)
		}
		srcMAC = cfg.SourceMAC
		groups = []syn6Group{{source: cfg.SourceIP.WithZone(""), targets: targets}}
	}
	io, err := open(cfg.Interface)
	if err != nil {
		return fmt.Errorf("raw packet I/O on %s: %w", cfg.Interface, err)
	}
	defer io.Close()
	limiter := newScopedProbeLimiter(cfg)
	scoped := emit
	if len(zones) > 0 {
		scoped = func(o Observation) error {
			if zone, ok := zones[o.Target]; ok {
				o.Target = o.Target.WithZone(zone)
			}
			return emit(o)
		}
	}
	cache := make(map[netip.Addr]net.HardwareAddr)
	if kernelNeighborProbes && lookupErr == nil {
		// As for IPv4: learn the Ethernet source the interface really
		// transmits with before any NDP or SYN frame depends on it.
		if lookup, err := loadIPv6Routes(cfg.Interface); err == nil {
			if hop, err := lookup(groups[0].targets[0]); err == nil {
				wire, macs, err := observeKernelNeighbors(parent, io, cfg.Interface, groups[0].source, []netip.Addr{hop}, cfg.Timeout, limiter)
				if err != nil {
					return err
				}
				if len(wire) == 6 && len(cfg.SourceMAC) == 0 {
					srcMAC = wire
				}
				if mac := macs[hop]; len(mac) == 6 {
					cache[hop] = mac
				}
			}
		}
	}
	var neighborIO packetio.PacketIO
	var lookup func(netip.Addr) (netip.Addr, error)
	if len(cfg.NextHopMAC) == 0 {
		lookup, err = loadIPv6Routes(cfg.Interface)
		if err != nil {
			return fmt.Errorf("resolve IPv6 SYN next hops: %w", err)
		}
		// NDP and SYN reception must not compete for reads on one handle.
		neighborIO, err = open(cfg.Interface)
		if err != nil {
			return fmt.Errorf("neighbor packet I/O on %s: %w", cfg.Interface, err)
		}
		defer neighborIO.Close()
	}
	for _, group := range groups {
		family := cfg
		family.Targets, family.SourceIP = group.targets, group.source
		var resolve func(context.Context, []netip.Addr) (map[netip.Addr]net.HardwareAddr, error)
		if lookup != nil {
			solicitFrom := func(hop netip.Addr) netip.Addr {
				if hop.IsLinkLocalUnicast() && linkLocal.IsValid() {
					return linkLocal
				}
				return group.source
			}
			resolve = func(ctx context.Context, chunk []netip.Addr) (map[netip.Addr]net.HardwareAddr, error) {
				return resolveIPv6NextHops(ctx, family, neighborIO, srcMAC, group.source, solicitFrom, limiter, lookup, cache, chunk)
			}
		}
		if err := runSYNAsync(parent, family, scoped, io, srcMAC, group.source, nil, limiter, resolve); err != nil {
			return err
		}
	}
	return nil
}

// resolveIPv6NextHops maps each target to its next hop's MAC. Answers persist
// in cache across chunks; an unanswered hop is retried with the next chunk
// and its targets are reported unsent rather than sent to a guessed MAC.
func resolveIPv6NextHops(ctx context.Context, cfg config.Config, io packetio.PacketIO, srcMAC net.HardwareAddr, source netip.Addr, solicitFrom func(netip.Addr) netip.Addr, limiter *probeLimiter, lookup func(netip.Addr) (netip.Addr, error), cache map[netip.Addr]net.HardwareAddr, targets []netip.Addr) (map[netip.Addr]net.HardwareAddr, error) {
	hopOf := make(map[netip.Addr]netip.Addr, len(targets))
	seen := make(map[netip.Addr]bool)
	var missing []netip.Addr
	for _, target := range targets {
		hop, err := lookup(target)
		if err != nil {
			return nil, err
		}
		hopOf[target] = hop
		if len(cache[hop]) != 6 && !seen[hop] {
			seen[hop] = true
			missing = append(missing, hop)
		}
	}
	for start := 0; start < len(missing); start += 128 {
		end := min(start+128, len(missing))
		macs, err := resolveNDPBatch(ctx, io, srcMAC, solicitFrom, missing[start:end], cfg.Timeout, limiter)
		if err != nil {
			return nil, fmt.Errorf("NDP on %s: %w", cfg.Interface, err)
		}
		for hop, mac := range macs {
			cache[hop] = mac
		}
	}
	if kernelNeighborProbes {
		var silent []netip.Addr
		for _, hop := range missing {
			if len(cache[hop]) != 6 {
				silent = append(silent, hop)
			}
		}
		if len(silent) > 0 {
			_, macs, err := observeKernelNeighbors(ctx, io, cfg.Interface, source, silent, cfg.Timeout, limiter)
			if err != nil {
				return nil, err
			}
			for hop, mac := range macs {
				if len(mac) == 6 {
					cache[hop] = mac
				}
			}
		}
	}
	resolved := make(map[netip.Addr]net.HardwareAddr, len(targets))
	for target, hop := range hopOf {
		resolved[target] = cache[hop] // nil: the neighbor did not answer
	}
	return resolved, nil
}

// resolveNDPBatch is resolveARPBatch for IPv6: multicast solicitations to
// each hop's solicited-node group, validated unicast advertisements back.
func resolveNDPBatch(parent context.Context, io packetio.PacketIO, srcMAC net.HardwareAddr, solicitFrom func(netip.Addr) netip.Addr, hops []netip.Addr, timeout time.Duration, limiter *probeLimiter) (map[netip.Addr]net.HardwareAddr, error) {
	request := func(hop netip.Addr) ([]byte, error) {
		return packet.NeighborSolicitation(srcMAC, solicitFrom(hop), hop)
	}
	reply := func(frame []byte) (netip.Addr, net.HardwareAddr, bool) {
		hop, ok := packet.NeighborAdvertisementTarget(frame)
		if !ok {
			return netip.Addr{}, nil, false
		}
		mac, valid := packet.NeighborAdvertisementMAC(frame, hop, solicitFrom(hop))
		return hop, mac, valid
	}
	return resolveNeighborBatch(parent, io, "NDP", hops, timeout, limiter, request, reply)
}

// unscopedSYN6Targets checks link-local zones against the scan interface and
// returns zone-free targets for packets and reply correlation, with the zone
// each link-local target is reported under. Only fe80::/10 takes a zone.
func unscopedSYN6Targets(targets []netip.Addr, device string) ([]netip.Addr, map[netip.Addr]string, error) {
	out := make([]netip.Addr, 0, len(targets))
	zones := make(map[netip.Addr]string)
	seen := make(map[netip.Addr]bool, len(targets))
	for _, target := range targets {
		if zone := target.Zone(); zone != "" {
			if !target.IsLinkLocalUnicast() {
				return nil, nil, fmt.Errorf("IPv6 target %s has a zone but is not link-local", target)
			}
			if zone != device {
				return nil, nil, fmt.Errorf("IPv6 target %s is scoped to %s, not the scan interface %s", target, zone, device)
			}
		}
		target = target.WithZone("")
		if seen[target] {
			continue
		}
		seen[target] = true
		if target.IsLinkLocalUnicast() {
			zones[target] = device
		}
		out = append(out, target)
	}
	return out, zones, nil
}

func ipv6InterfaceAddrs(iface *net.Interface) ([]netip.Prefix, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			continue
		}
		a := prefix.Addr().WithZone("")
		if a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() {
			continue
		}
		out = append(out, netip.PrefixFrom(a, prefix.Bits()))
	}
	return out, nil
}

// groupIPv6Sources assigns every target a source on the interface. An
// explicit --source-ip must be assigned there and serves every target.
// Otherwise link-local targets use a link-local source and the rest the
// on-link (else longest-matching) global or unique-local source, after
// RFC 6724's scope and longest-prefix rules. Groups are ordered by source.
func groupIPv6Sources(device string, addrs []netip.Prefix, requested netip.Addr, targets []netip.Addr) ([]syn6Group, error) {
	if requested.IsValid() {
		requested = requested.WithZone("")
		for _, prefix := range addrs {
			if prefix.Addr() == requested {
				return []syn6Group{{source: requested, targets: targets}}, nil
			}
		}
		return nil, fmt.Errorf("source IP %s is not assigned to interface %s", requested, device)
	}
	index := make(map[netip.Addr]int)
	var groups []syn6Group
	for _, target := range targets {
		source, err := selectIPv6SYNSource(device, addrs, target)
		if err != nil {
			return nil, err
		}
		i, ok := index[source]
		if !ok {
			i = len(groups)
			index[source] = i
			groups = append(groups, syn6Group{source: source})
		}
		groups[i].targets = append(groups[i].targets, target)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].source.Less(groups[j].source) })
	return groups, nil
}

func selectIPv6SYNSource(device string, addrs []netip.Prefix, target netip.Addr) (netip.Addr, error) {
	linkLocal := target.IsLinkLocalUnicast()
	var best netip.Addr
	bestScore := -1
	for _, prefix := range addrs {
		a := prefix.Addr()
		if a.IsLinkLocalUnicast() != linkLocal {
			continue
		}
		score := commonPrefixBits(a, target)
		if prefix.Contains(target) {
			score += 256
		}
		if score > bestScore || (score == bestScore && a.Less(best)) {
			best, bestScore = a, score
		}
	}
	if !best.IsValid() {
		scope := "global or unique-local"
		if linkLocal {
			scope = "link-local"
		}
		return netip.Addr{}, fmt.Errorf("interface %s has no %s IPv6 address for %s; specify --source-ip", device, scope, target)
	}
	return best, nil
}

func commonPrefixBits(a, b netip.Addr) int {
	x, y := a.As16(), b.As16()
	for i := range x {
		if d := x[i] ^ y[i]; d != 0 {
			bits := i * 8
			for d&0x80 == 0 {
				bits++
				d <<= 1
			}
			return bits
		}
	}
	return 128
}
