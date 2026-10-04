//go:build darwin

package scan

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"strings"
)

type darwinRoute struct {
	prefix netip.Prefix
	hop    netip.Addr
	device string
	scoped bool // RTF_IFSCOPE: used only for traffic bound to device
}

// A single routing-table snapshot avoids one routing-socket command per
// target. It also works when a sandbox denies route(8)'s socket access while
// still allowing netstat's read-only table inspection.
func loadIPv4Routes(device string) (func(netip.Addr) (netip.Addr, error), error) {
	output, err := exec.Command("/usr/sbin/netstat", "-rn", "-f", "inet").Output()
	if err != nil {
		return nil, fmt.Errorf("read IPv4 routes: %w", err)
	}
	routes, err := parseDarwinRoutes(strings.NewReader(string(output)))
	if err != nil {
		return nil, err
	}
	return func(target netip.Addr) (netip.Addr, error) {
		best := -1
		for i, route := range routes {
			if route.prefix.Contains(target) && (best < 0 || route.prefix.Bits() > routes[best].prefix.Bits() ||
				(route.prefix.Bits() == routes[best].prefix.Bits() && route.device == device && routes[best].device != device)) {
				best = i
			}
		}
		if best < 0 {
			return netip.Addr{}, fmt.Errorf("no IPv4 route to %s", target)
		}
		route := routes[best]
		if route.device != device {
			return netip.Addr{}, fmt.Errorf("route to %s uses %s, not %s", target, route.device, device)
		}
		if route.hop.IsValid() {
			return route.hop, nil
		}
		return target, nil
	}, nil
}

// egressInterface names the interface route(8) get would report for target:
// the longest unscoped prefix, falling back to scoped routes only when no
// unscoped route matches.
func egressInterface(target netip.Addr) (string, error) {
	output, err := exec.Command("/usr/sbin/netstat", "-rn", "-f", "inet").Output()
	if err != nil {
		return "", fmt.Errorf("read IPv4 routes: %w", err)
	}
	routes, err := parseDarwinRoutes(strings.NewReader(string(output)))
	if err != nil {
		return "", err
	}
	return darwinEgress(routes, target)
}

func darwinEgress(routes []darwinRoute, target netip.Addr) (string, error) {
	best := -1
	for i, route := range routes {
		if !route.prefix.Contains(target) {
			continue
		}
		if best < 0 || (routes[best].scoped && !route.scoped) ||
			(route.scoped == routes[best].scoped && route.prefix.Bits() > routes[best].prefix.Bits()) {
			best = i
		}
	}
	if best < 0 {
		return "", fmt.Errorf("no IPv4 route to %s", target)
	}
	return routes[best].device, nil
}

func parseDarwinRoutes(r io.Reader) ([]darwinRoute, error) {
	var routes []darwinRoute
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || !strings.HasPrefix(fields[2], "U") {
			continue
		}
		prefix, ok := darwinDestination(fields[0])
		if !ok {
			continue
		}
		hop, _ := netip.ParseAddr(fields[1])
		if !hop.Is4() {
			hop = netip.Addr{} // link# and MAC gateways are on-link
		}
		routes = append(routes, darwinRoute{prefix: prefix, hop: hop, device: fields[3], scoped: strings.Contains(fields[2], "I")})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("no IPv4 routes")
	}
	return routes, nil
}

func darwinDestination(value string) (netip.Prefix, bool) {
	if value == "default" {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0), true
	}
	parts := strings.SplitN(value, "/", 2)
	if strings.Count(parts[0], ".") > 3 {
		return netip.Prefix{}, false
	}
	octets := strings.Split(parts[0], ".")
	if len(octets) == 0 || len(octets) > 4 {
		return netip.Prefix{}, false
	}
	address := parts[0]
	for i := len(octets); i < 4; i++ {
		address += ".0"
	}
	addr, err := netip.ParseAddr(address)
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, false
	}
	bits := len(octets) * 8
	if len(parts) == 2 {
		prefix, err := netip.ParsePrefix(address + "/" + parts[1])
		if err != nil {
			return netip.Prefix{}, false
		}
		return prefix.Masked(), true
	}
	return netip.PrefixFrom(addr, bits).Masked(), true
}
