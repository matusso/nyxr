//go:build !linux

package packetio

import (
	"fmt"
	"net"
)

func OpenXDP(device, pinDir string, source net.IP) (PacketIO, error) {
	return nil, fmt.Errorf("AF_XDP is available on Linux only: %w", ErrUnavailable)
}
