//go:build darwin

package scan

import (
	"net"
	"net/netip"
	"os/exec"
	"strings"
)

func cachedARPNeighbor(device string, hop netip.Addr) net.HardwareAddr {
	if !hop.Is4() {
		return nil
	}
	output, err := exec.Command("/usr/sbin/arp", "-n", hop.String()).Output()
	if err != nil {
		return nil
	}
	return parseDarwinARP(string(output), device, hop)
}

func parseDarwinARP(output, device string, hop netip.Addr) net.HardwareAddr {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[1] != "("+hop.String()+")" {
			continue
		}
		for i := 2; i+1 < len(fields); i++ {
			if fields[i] != "at" {
				continue
			}
			mac, err := net.ParseMAC(fields[i+1])
			if err != nil || len(mac) != 6 || mac[0]&1 != 0 || isZeroMAC(mac) {
				break
			}
			for j := i + 2; j+1 < len(fields); j++ {
				if fields[j] == "on" && fields[j+1] == device {
					return mac
				}
			}
			break
		}
	}
	return nil
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, octet := range mac {
		if octet != 0 {
			return false
		}
	}
	return true
}
