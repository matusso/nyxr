//go:build !darwin

package scan

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/matusso/nyxr/internal/packetio"
)

const kernelNeighborProbes = false

func observeKernelNeighbors(context.Context, packetio.PacketIO, string, netip.Addr, []netip.Addr, time.Duration, *probeLimiter) (net.HardwareAddr, map[netip.Addr]net.HardwareAddr, error) {
	return nil, nil, nil
}
