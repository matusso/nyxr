package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
)

// resolveNextHops uses the selected interface's route table and ARP. One
// gateway is queried once, while directly attached hosts use their own IP.
// An unanswered ARP request is retained as an unresolved target, not sent to
// a guessed Ethernet destination.
func resolveNextHops(ctx context.Context, cfg config.Config, io packetio.PacketIO, sourceMAC net.HardwareAddr, sourceIP netip.Addr) (map[netip.Addr]net.HardwareAddr, error) {
	lookup, err := loadIPv4Routes(cfg.Interface)
	if err != nil {
		return nil, err
	}
	byHop := make(map[netip.Addr]net.HardwareAddr)
	byTarget := make(map[netip.Addr]net.HardwareAddr, len(cfg.Targets))
	limiter := newScopedProbeLimiter(cfg)
	for _, target := range cfg.Targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hop, err := lookup(target)
		if err != nil {
			return nil, err
		}
		mac, seen := byHop[hop]
		if !seen {
			if err := limiter.WaitFor(ctx, hop); err != nil {
				return nil, err
			}
			mac, err = arpNeighbor(ctx, io, sourceMAC, sourceIP, hop, cfg.Timeout)
			if err != nil {
				return nil, fmt.Errorf("ARP %s on %s: %w", hop, cfg.Interface, err)
			}
			byHop[hop] = mac
		}
		byTarget[target] = mac // nil means this neighbor did not answer
	}
	return byTarget, nil
}

func arpNeighbor(parent context.Context, io packetio.PacketIO, sourceMAC net.HardwareAddr, sourceIP, neighbor netip.Addr, timeout time.Duration) (net.HardwareAddr, error) {
	frame, err := packet.ARPRequest(sourceMAC, sourceIP, neighbor)
	if err != nil {
		return nil, err
	}
	if timeout < 200*time.Millisecond {
		timeout = 200 * time.Millisecond
	}
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if n, err := io.SendBatch(ctx, [][]byte{frame}); err != nil || n != 1 {
		return nil, fmt.Errorf("send ARP request: %d/1 frames: %v", n, err)
	}
	var storage [65535]byte
	buf := [][]byte{storage[:]}
	for {
		buf[0] = storage[:]
		n, err := io.ReceiveBatch(ctx, buf)
		if n > 0 {
			if mac, ok := packet.ARPReplyMAC(buf[0], neighbor, sourceIP); ok {
				return mac, nil
			}
		}
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, nil
			}
			return nil, err
		}
	}
}
