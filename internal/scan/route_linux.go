//go:build linux

package scan

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type ipv4Route struct {
	network, gateway netip.Addr
	bits, metric     int
	device           string
}

func loadIPv4Routes(device string) (func(netip.Addr) (netip.Addr, error), error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("read IPv4 routes: %w", err)
	}
	defer f.Close()
	routes, err := parseIPv4Routes(f, device)
	if err != nil {
		return nil, err
	}
	return func(target netip.Addr) (netip.Addr, error) {
		best := -1
		for i, route := range routes {
			if netip.PrefixFrom(route.network, route.bits).Contains(target) &&
				(best < 0 || route.bits > routes[best].bits ||
					(route.bits == routes[best].bits && route.metric < routes[best].metric)) {
				best = i
			}
		}
		if best < 0 {
			return netip.Addr{}, fmt.Errorf("no IPv4 route to %s on %s", target, device)
		}
		if routes[best].gateway.IsUnspecified() {
			return target, nil
		}
		return routes[best].gateway, nil
	}, nil
}

// egressInterface names the interface the main IPv4 table sends target
// through: the longest prefix, then the lowest metric.
func egressInterface(target netip.Addr) (string, error) {
	if target.Is6() {
		routes, err := readIPv6Routes("")
		if err != nil {
			return "", err
		}
		route, ok := bestIPv6Route(routes, target.WithZone(""))
		if !ok {
			return "", fmt.Errorf("no IPv6 route to %s", target)
		}
		return route.device, nil
	}
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", fmt.Errorf("read IPv4 routes: %w", err)
	}
	defer f.Close()
	routes, err := parseIPv4Routes(f, "")
	if err != nil {
		return "", err
	}
	best := -1
	for i, route := range routes {
		if netip.PrefixFrom(route.network, route.bits).Contains(target) &&
			(best < 0 || route.bits > routes[best].bits ||
				(route.bits == routes[best].bits && route.metric < routes[best].metric)) {
			best = i
		}
	}
	if best < 0 {
		return "", fmt.Errorf("no IPv4 route to %s", target)
	}
	return routes[best].device, nil
}

// parseIPv4Routes reads /proc/net/route; an empty device keeps every
// interface's routes.
func parseIPv4Routes(r io.Reader, device string) ([]ipv4Route, error) {
	var routes []ipv4Route
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || (device != "" && fields[0] != device) {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&1 == 0 {
			continue
		}
		network, err1 := parseRouteAddress(fields[1])
		gateway, err2 := parseRouteAddress(fields[2])
		mask, err3 := parseRouteAddress(fields[7])
		metric, err4 := strconv.Atoi(fields[6])
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			continue
		}
		m := mask.As4()
		bits, valid := contiguousMask(m)
		if !valid {
			continue
		}
		routes = append(routes, ipv4Route{network: netip.PrefixFrom(network, bits).Masked().Addr(), gateway: gateway, bits: bits, metric: metric, device: fields[0]})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(routes) == 0 {
		if device == "" {
			return nil, fmt.Errorf("no IPv4 routes")
		}
		return nil, fmt.Errorf("no IPv4 routes for interface %s", device)
	}
	return routes, nil
}

func parseRouteAddress(hexText string) (netip.Addr, error) {
	value, err := strconv.ParseUint(hexText, 16, 32)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.AddrFrom4([4]byte{byte(value), byte(value >> 8), byte(value >> 16), byte(value >> 24)}), nil
}

func contiguousMask(mask [4]byte) (int, bool) {
	bits, zeroSeen := 0, false
	for _, octet := range mask {
		for bit := 7; bit >= 0; bit-- {
			if octet&(1<<bit) != 0 {
				if zeroSeen {
					return 0, false
				}
				bits++
			} else {
				zeroSeen = true
			}
		}
	}
	return bits, true
}

type ipv6Route struct {
	prefix  netip.Prefix
	gateway netip.Addr // invalid when the prefix is on-link
	metric  uint32
	device  string
}

// loadIPv6Routes returns the next hop for an IPv6 target on device. Link-local
// targets are on-link by definition and never consult the table.
func loadIPv6Routes(device string) (func(netip.Addr) (netip.Addr, error), error) {
	routes, err := readIPv6Routes(device)
	if err != nil {
		return nil, err
	}
	return func(target netip.Addr) (netip.Addr, error) {
		target = target.WithZone("")
		if target.IsLinkLocalUnicast() {
			return target, nil
		}
		route, ok := bestIPv6Route(routes, target)
		if !ok {
			return netip.Addr{}, fmt.Errorf("no IPv6 route to %s on %s", target, device)
		}
		if !route.gateway.IsValid() {
			return target, nil
		}
		return route.gateway, nil
	}, nil
}

func readIPv6Routes(device string) ([]ipv6Route, error) {
	f, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return nil, fmt.Errorf("read IPv6 routes: %w", err)
	}
	defer f.Close()
	return parseIPv6Routes(f, device)
}

func bestIPv6Route(routes []ipv6Route, target netip.Addr) (ipv6Route, bool) {
	best := -1
	for i, route := range routes {
		if route.prefix.Contains(target) && (best < 0 || route.prefix.Bits() > routes[best].prefix.Bits() ||
			(route.prefix.Bits() == routes[best].prefix.Bits() && route.metric < routes[best].metric)) {
			best = i
		}
	}
	if best < 0 {
		return ipv6Route{}, false
	}
	return routes[best], true
}

// parseIPv6Routes reads /proc/net/ipv6_route: destination, prefix length,
// source, source length, next hop, metric, refcount, use, flags and device.
// Down, reject and multicast routes are skipped; an empty device keeps all.
// No routes is not an error: link-local targets never need one.
func parseIPv6Routes(r io.Reader, device string) ([]ipv6Route, error) {
	var routes []ipv6Route
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || (device != "" && fields[9] != device) {
			continue
		}
		flags, err1 := strconv.ParseUint(fields[8], 16, 32)
		bits, err2 := strconv.ParseUint(fields[1], 16, 8)
		metric, err3 := strconv.ParseUint(fields[5], 16, 32)
		network, err4 := parseIPv6RouteAddress(fields[0])
		gateway, err5 := parseIPv6RouteAddress(fields[4])
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || flags&0x1 == 0 || flags&0x200 != 0 || bits > 128 || network.IsMulticast() {
			continue
		}
		if gateway.IsUnspecified() {
			gateway = netip.Addr{}
		}
		routes = append(routes, ipv6Route{prefix: netip.PrefixFrom(network, int(bits)).Masked(), gateway: gateway, metric: uint32(metric), device: fields[9]})
	}
	return routes, scanner.Err()
}

func parseIPv6RouteAddress(hexText string) (netip.Addr, error) {
	if len(hexText) != 32 {
		return netip.Addr{}, fmt.Errorf("IPv6 route address %q", hexText)
	}
	var b [16]byte
	for i := range b {
		v, err := strconv.ParseUint(hexText[2*i:2*i+2], 16, 8)
		if err != nil {
			return netip.Addr{}, err
		}
		b[i] = byte(v)
	}
	return netip.AddrFrom16(b), nil
}
