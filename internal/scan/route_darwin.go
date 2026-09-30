//go:build darwin

package scan

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

func loadIPv4Routes(device string) (func(netip.Addr) (netip.Addr, error), error) {
	return func(target netip.Addr) (netip.Addr, error) {
		output, err := exec.Command("/sbin/route", "-n", "get", "-ifscope", device, target.String()).Output()
		if err != nil {
			return netip.Addr{}, fmt.Errorf("route to %s on %s: %w", target, device, err)
		}
		var gateway, iface string
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			switch fields[0] {
			case "gateway:":
				gateway = fields[1]
			case "interface:":
				iface = fields[1]
			}
		}
		if iface != device {
			return netip.Addr{}, fmt.Errorf("route to %s uses %s, not %s", target, iface, device)
		}
		if hop, err := netip.ParseAddr(gateway); err == nil && hop.Is4() && !hop.IsUnspecified() {
			return hop, nil
		}
		return target, nil // link# routes are directly connected
	}, nil
}
