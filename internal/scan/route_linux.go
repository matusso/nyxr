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

func parseIPv4Routes(r io.Reader, device string) ([]ipv4Route, error) {
	var routes []ipv4Route
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || fields[0] != device {
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
		routes = append(routes, ipv4Route{network: netip.PrefixFrom(network, bits).Masked().Addr(), gateway: gateway, bits: bits, metric: metric})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(routes) == 0 {
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
