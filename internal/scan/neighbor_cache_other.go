//go:build !darwin

package scan

import (
	"net"
	"net/netip"
)

func cachedARPNeighbor(string, netip.Addr) net.HardwareAddr             { return nil }
func snapshotCachedARPNeighbors(string) map[netip.Addr]net.HardwareAddr { return nil }
