//go:build darwin

package scan

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/matusso/nyxr/internal/packetio"
)

// macOS can transmit with a different Ethernet source than the interface
// reports (Wi-Fi private addresses), and unprivileged arp(8) shows no entries.
const kernelNeighborProbes = true

// observeKernelNeighbors lets the OS stack resolve each hop: one empty UDP
// datagram per hop leaves through the kernel, and its outgoing frame on io
// reveals both the Ethernet source the interface really transmits with and
// the hop's MAC. This needs neither ARP-table access nor a raw ARP reply.
// Hops whose frame is not observed before the timeout are left out.
func observeKernelNeighbors(parent context.Context, io packetio.PacketIO, device string, source netip.Addr, hops []netip.Addr, timeout time.Duration, limiter *probeLimiter) (net.HardwareAddr, map[netip.Addr]net.HardwareAddr, error) {
	if timeout < 200*time.Millisecond {
		timeout = 200 * time.Millisecond
	}
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	ports := make(map[uint16]netip.Addr, len(hops))
	conns := make([]*net.UDPConn, 0, len(hops))
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	for _, hop := range hops {
		conn, err := dialKernelProbe(device, source, hop)
		if err != nil {
			continue // that hop stays unresolved
		}
		conns = append(conns, conn)
		ports[uint16(conn.LocalAddr().(*net.UDPAddr).Port)] = hop
	}
	if len(conns) == 0 {
		return nil, nil, nil
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	var mu sync.Mutex
	var wire net.HardwareAddr
	resolved := make(map[netip.Addr]net.HardwareAddr, len(conns))
	done := make(chan error, 1)
	go func() {
		var storage [65535]byte
		buf := [][]byte{storage[:]}
		for {
			buf[0] = storage[:]
			n, err := io.ReceiveBatch(ctx, buf)
			if n > 0 {
				if port, src, dst, ok := kernelProbeFrame(buf[0], source); ok {
					if hop, mine := ports[port]; mine {
						mu.Lock()
						if wire == nil {
							wire = src
						}
						resolved[hop] = dst
						all := len(resolved) == len(conns)
						mu.Unlock()
						if all {
							cancel()
						}
					}
				}
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	for _, conn := range conns {
		hop := ports[uint16(conn.LocalAddr().(*net.UDPAddr).Port)]
		if err := limiter.WaitFor(ctx, hop); err != nil {
			break
		}
		_, _ = conn.Write(nil) // an unroutable hop simply stays unresolved
	}
	readErr := <-done
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	if readErr != nil && !errors.Is(readErr, context.Canceled) && !errors.Is(readErr, context.DeadlineExceeded) {
		return nil, nil, readErr
	}
	return wire, resolved, nil
}

// kernelProbeFrame matches an outgoing IPv4/UDP frame from local and returns
// its UDP source port with the frame's Ethernet source and destination.
func kernelProbeFrame(frame []byte, local netip.Addr) (uint16, net.HardwareAddr, net.HardwareAddr, bool) {
	offset := 12
	if len(frame) < offset+2 {
		return 0, nil, nil, false
	}
	ethType := binary.BigEndian.Uint16(frame[offset : offset+2])
	if ethType == 0x8100 || ethType == 0x88a8 {
		offset += 4
		if len(frame) < offset+2 {
			return 0, nil, nil, false
		}
		ethType = binary.BigEndian.Uint16(frame[offset : offset+2])
	}
	ip := frame[offset+2:]
	if ethType != 0x0800 || len(ip) < 20 || ip[0]>>4 != 4 || ip[9] != 17 {
		return 0, nil, nil, false
	}
	ihl := int(ip[0]&15) * 4
	src := local.As4()
	if ihl < 20 || len(ip) < ihl+8 || string(ip[12:16]) != string(src[:]) {
		return 0, nil, nil, false
	}
	dst, from := make(net.HardwareAddr, 6), make(net.HardwareAddr, 6)
	copy(dst, frame[:6])
	copy(from, frame[6:12])
	if dst[0]&1 != 0 || isZeroMAC(dst) || from[0]&1 != 0 || isZeroMAC(from) {
		return 0, nil, nil, false
	}
	return binary.BigEndian.Uint16(ip[ihl : ihl+2]), from, dst, true
}

// dialKernelProbe pins a discard-port UDP socket to device with TTL 1, so the
// datagram can only leave through the scanned interface toward hop.
func dialKernelProbe(device string, source, hop netip.Addr) (*net.UDPConn, error) {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{LocalAddr: &net.UDPAddr{IP: source.AsSlice()}, Control: func(_, _ string, c syscall.RawConn) error {
		var optErr error
		if err := c.Control(func(fd uintptr) {
			optErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, iface.Index)
			if optErr == nil {
				optErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, 1)
			}
		}); err != nil {
			return err
		}
		return optErr
	}}
	conn, err := d.Dial("udp4", netip.AddrPortFrom(hop, 9).String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}
