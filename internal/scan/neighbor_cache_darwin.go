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

func snapshotCachedARPNeighbors(device string) map[netip.Addr]net.HardwareAddr {
	output, err := exec.Command("/usr/sbin/arp", "-an").Output()
	if err != nil {
		return nil
	}
	return parseDarwinARPSnapshot(string(output), device)
}

func parseDarwinARPSnapshot(output, device string) map[netip.Addr]net.HardwareAddr {
	neighbors := make(map[netip.Addr]net.HardwareAddr)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[2] != "at" || fields[4] != "on" || fields[5] != device {
			continue
		}
		ip, err := netip.ParseAddr(strings.Trim(fields[1], "()"))
		if err != nil || !ip.Is4() {
			continue
		}
		mac, err := parseDarwinMAC(fields[3])
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || isZeroMAC(mac) {
			continue
		}
		neighbors[ip] = mac
	}
	return neighbors
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
			mac, err := parseDarwinMAC(fields[i+1])
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

// arp(8) prints octets without leading zeros ("0:1b:2:..."), which
// net.ParseMAC rejects.
func parseDarwinMAC(value string) (net.HardwareAddr, error) {
	octets := strings.Split(value, ":")
	if len(octets) == 6 {
		for i, octet := range octets {
			if len(octet) == 1 {
				octets[i] = "0" + octet
			}
		}
	}
	return net.ParseMAC(strings.Join(octets, ":"))
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, octet := range mac {
		if octet != 0 {
			return false
		}
	}
	return true
}
