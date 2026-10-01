//go:build !darwin

package scan

import (
	"net"
	"net/netip"
)

func cachedARPNeighbor(string, netip.Addr) net.HardwareAddr { return nil }
