package scan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
)

// resolveNextHops uses the selected interface's route table and ARP. One
// gateway is queried once, while directly attached hosts use their own IP.
// An unanswered ARP request is retained as an unresolved target, not sent to
// a guessed Ethernet destination.
func resolveNextHops(ctx context.Context, cfg config.Config, io packetio.PacketIO, sourceMAC net.HardwareAddr, sourceIP netip.Addr, limiter *probeLimiter) (map[netip.Addr]net.HardwareAddr, error) {
	lookup, err := loadIPv4Routes(cfg.Interface)
	if err != nil {
		return nil, err
	}
	byHop := make(map[netip.Addr]net.HardwareAddr)
	targetHops := make(map[netip.Addr]netip.Addr, len(cfg.Targets))
	var hops []netip.Addr
	byTarget := make(map[netip.Addr]net.HardwareAddr, len(cfg.Targets))
	for _, target := range cfg.Targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hop, err := lookup(target)
		if err != nil {
			return nil, err
		}
		if _, seen := byHop[hop]; !seen {
			byHop[hop] = nil
			hops = append(hops, hop)
		}
		targetHops[target] = hop
	}
	for start := 0; start < len(hops); start += 128 {
		end := min(start+128, len(hops))
		resolved, err := resolveARPBatch(ctx, io, sourceMAC, sourceIP, hops[start:end], cfg.Timeout, limiter)
		if err != nil {
			return nil, fmt.Errorf("ARP on %s: %w", cfg.Interface, err)
		}
		for hop, mac := range resolved {
			byHop[hop] = mac
		}
	}
	for target, hop := range targetHops {
		byTarget[target] = byHop[hop] // nil means this neighbor did not answer
	}
	return byTarget, nil
}

// resolveARPBatch maintains one bounded reader while up to 128 ARP requests
// are outstanding. Silent hosts cost one batch timeout rather than one timeout
// per host. Each actual send is paced before it reaches the backend.
func resolveARPBatch(parent context.Context, io packetio.PacketIO, sourceMAC net.HardwareAddr, sourceIP netip.Addr, hops []netip.Addr, timeout time.Duration, limiter *probeLimiter) (map[netip.Addr]net.HardwareAddr, error) {
	if timeout < 200*time.Millisecond {
		timeout = 200 * time.Millisecond
	}
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	resolved := make(map[netip.Addr]net.HardwareAddr, len(hops))
	pending := make(map[netip.Addr]bool, len(hops))
	for _, hop := range hops {
		pending[hop] = true
	}
	var mu sync.Mutex
	all := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		var storage [65535]byte
		buf := [][]byte{storage[:]}
		for {
			buf[0] = storage[:]
			n, err := io.ReceiveBatch(ctx, buf)
			if n > 0 {
				if hop, ok := arpReplySource(buf[0]); ok {
					if mac, valid := packet.ARPReplyMAC(buf[0], hop, sourceIP); valid {
						mu.Lock()
						if pending[hop] {
							delete(pending, hop)
							resolved[hop] = mac
							if len(pending) == 0 {
								close(all)
							}
						}
						mu.Unlock()
					}
				}
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	for _, hop := range hops {
		if err := limiter.WaitFor(ctx, hop); err != nil {
			cancel()
			<-done
			return nil, err
		}
		frame, err := packet.ARPRequest(sourceMAC, sourceIP, hop)
		if err != nil {
			cancel()
			<-done
			return nil, err
		}
		if n, err := io.SendBatch(ctx, [][]byte{frame}); err != nil || n != 1 {
			cancel()
			<-done
			return nil, fmt.Errorf("send ARP %s: %d/1 frames: %v", hop, n, err)
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var readErr error
	readerFinished := false
	select {
	case <-all:
	case readErr = <-done:
		readerFinished = true
	case <-timer.C:
	case <-parent.Done():
	}
	cancel()
	if !readerFinished {
		readErr = <-done
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	if readErr != nil && !errors.Is(readErr, context.Canceled) {
		return nil, readErr
	}
	return resolved, nil
}

func arpReplySource(frame []byte) (netip.Addr, bool) {
	if len(frame) < 42 {
		return netip.Addr{}, false
	}
	offset := 12
	ethType := binary.BigEndian.Uint16(frame[offset : offset+2])
	if ethType == 0x8100 || ethType == 0x88a8 {
		offset += 4
	}
	if len(frame) < offset+30 || binary.BigEndian.Uint16(frame[offset:offset+2]) != 0x0806 {
		return netip.Addr{}, false
	}
	a := frame[offset+2:]
	if len(a) < 28 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(a[14:18])), true
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
