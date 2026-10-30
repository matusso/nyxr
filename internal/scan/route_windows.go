//go:build windows

package scan

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
)

// egressInterface is unsupported: Npcap adapters are named by device ID, not
// by the interface alias the routing table reports.
func egressInterface(netip.Addr) (string, error) {
	return "", fmt.Errorf("cannot map the route to an Npcap adapter; specify --interface")
}

func loadIPv4Routes(device string) (func(netip.Addr) (netip.Addr, error), error) {
	return loadWindowsRoutes(device, "IPv4")
}

// loadIPv6Routes treats link-local targets as on-link on device; the table's
// fe80::/64 entries name no interface the Npcap adapter can be matched to.
func loadIPv6Routes(device string) (func(netip.Addr) (netip.Addr, error), error) {
	next, err := loadWindowsRoutes(device, "IPv6")
	if err != nil {
		return nil, err
	}
	return func(target netip.Addr) (netip.Addr, error) {
		target = target.WithZone("")
		if target.IsLinkLocalUnicast() {
			return target, nil
		}
		return next(target)
	}, nil
}

func loadWindowsRoutes(device, family string) (func(netip.Addr) (netip.Addr, error), error) {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, fmt.Errorf("adapter %s is not an OS interface; specify --next-hop-mac: %w", device, err)
	}
	script := fmt.Sprintf("ConvertTo-Json -InputObject @(Get-NetRoute -AddressFamily %s -InterfaceIndex %d | Select-Object DestinationPrefix,NextHop,RouteMetric) -Compress", family, iface.Index)
	root := os.Getenv("SystemRoot")
	if root == "" {
		return nil, fmt.Errorf("SystemRoot is unset; cannot locate Windows PowerShell for route lookup")
	}
	powershell := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	output, err := exec.Command(powershell, "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return nil, fmt.Errorf("read Windows %s routes: %w", family, err)
	}
	var raw []struct {
		DestinationPrefix string
		NextHop           string
		RouteMetric       int
	}
	if err := json.Unmarshal(output, &raw); err != nil {
		return nil, fmt.Errorf("parse Windows %s routes: %w", family, err)
	}
	type route struct {
		prefix netip.Prefix
		hop    netip.Addr
		metric int
	}
	var routes []route
	for _, item := range raw {
		prefix, err1 := netip.ParsePrefix(item.DestinationPrefix)
		hop, err2 := netip.ParseAddr(item.NextHop)
		if err1 == nil && err2 == nil && prefix.Addr().Is4() == (family == "IPv4") && hop.Is4() == prefix.Addr().Is4() && !prefix.Addr().IsMulticast() {
			routes = append(routes, route{prefix, hop, item.RouteMetric})
		}
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("no %s routes on %s", family, device)
	}
	return func(target netip.Addr) (netip.Addr, error) {
		best := -1
		for i, item := range routes {
			if item.prefix.Contains(target) && (best < 0 || item.prefix.Bits() > routes[best].prefix.Bits() ||
				(item.prefix.Bits() == routes[best].prefix.Bits() && item.metric < routes[best].metric)) {
				best = i
			}
		}
		if best < 0 {
			return netip.Addr{}, fmt.Errorf("no %s route to %s on %s", family, target, device)
		}
		if routes[best].hop.IsUnspecified() {
			return target, nil
		}
		return routes[best].hop.WithZone(""), nil
	}, nil
}
