//go:build linux

package packetio

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Socket buffers sized for bursts of tens of thousands of small frames. The
// kernel default (~208 KiB) holds only a few hundred, and every frame the host
// sends or receives is also queued here, so replies were dropped under load.
const (
	liveRcvBuf = 8 << 20
	liveSndBuf = 4 << 20
	// pollMillis bounds how long a blocked call takes to notice ctx.
	pollMillis = 10
)

// Linux live I/O uses AF_PACKET with recvmmsg/sendmmsg, so one syscall moves
// a whole batch the way one BPF read does on macOS. ReceiveBatch fills
// caller-owned buffers; callers should reuse both the buffers and their
// decoder per RX worker.
type live struct {
	fd      int
	ifindex int
	rx, tx  atomic.Uint64
	statsMu sync.Mutex
	dropped uint64
}

// mmsghdr mirrors struct mmsghdr; Go pads it to the kernel's array stride.
type mmsghdr struct {
	hdr unix.Msghdr
	len uint32
}

func OpenLive(device string) (PacketIO, error) {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: iface.Index}); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	// FORCE needs CAP_NET_ADMIN; otherwise the request is capped at rmem_max.
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, liveRcvBuf) != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, liveRcvBuf)
	}
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, liveSndBuf) != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, liveSndBuf)
	}
	return &live{fd: fd, ifindex: iface.Index}, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// wait blocks until fd is ready for events, ctx ends, or pollMillis passes.
func (l *live) wait(ctx context.Context, events int16) error {
	fds := []unix.PollFd{{Fd: int32(l.fd), Events: events}}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := unix.Poll(fds, pollMillis)
		if err == unix.EINTR || (err == nil && n == 0) {
			continue
		}
		return err
	}
}

func (l *live) ReceiveBatch(ctx context.Context, buffers [][]byte) (int, error) {
	if len(buffers) == 0 {
		return 0, nil
	}
	iovs := make([]unix.Iovec, len(buffers))
	msgs := make([]mmsghdr, len(buffers))
	for i, buf := range buffers {
		if len(buf) == 0 {
			return 0, errors.New("receive buffer is empty")
		}
		iovs[i].Base = &buf[0]
		iovs[i].SetLen(len(buf))
		msgs[i].hdr.Iov = &iovs[i]
		msgs[i].hdr.SetIovlen(1)
	}
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		r, _, errno := unix.Syscall6(unix.SYS_RECVMMSG, uintptr(l.fd), uintptr(unsafe.Pointer(&msgs[0])), uintptr(len(msgs)), unix.MSG_DONTWAIT, 0, 0)
		switch errno {
		case 0:
			n := int(r)
			for i := range n {
				buffers[i] = buffers[i][:min(int(msgs[i].len), len(buffers[i]))]
			}
			l.rx.Add(uint64(n))
			return n, nil
		case unix.EAGAIN, unix.EINTR:
			if err := l.wait(ctx, unix.POLLIN); err != nil {
				return 0, err
			}
		default:
			return 0, errno
		}
	}
}

func (l *live) SendBatch(ctx context.Context, frames [][]byte) (int, error) {
	if len(frames) == 0 {
		return 0, nil
	}
	iovs := make([]unix.Iovec, len(frames))
	addrs := make([]unix.RawSockaddrLinklayer, len(frames))
	msgs := make([]mmsghdr, len(frames))
	for i, frame := range frames {
		if len(frame) < 14 {
			return 0, errors.New("Ethernet frame is truncated")
		}
		addrs[i] = unix.RawSockaddrLinklayer{Family: unix.AF_PACKET, Protocol: htons(binary.BigEndian.Uint16(frame[12:14])), Ifindex: int32(l.ifindex), Halen: 6}
		copy(addrs[i].Addr[:], frame[:6])
		iovs[i].Base = &frame[0]
		iovs[i].SetLen(len(frame))
		msgs[i].hdr.Name = (*byte)(unsafe.Pointer(&addrs[i]))
		msgs[i].hdr.Namelen = unix.SizeofSockaddrLinklayer
		msgs[i].hdr.Iov = &iovs[i]
		msgs[i].hdr.SetIovlen(1)
	}
	sent := 0
	for sent < len(msgs) {
		if err := ctx.Err(); err != nil {
			return sent, err
		}
		r, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(l.fd), uintptr(unsafe.Pointer(&msgs[sent])), uintptr(len(msgs)-sent), 0, 0, 0)
		switch errno {
		case 0:
			sent += int(r)
			l.tx.Add(uint64(r))
		// A full socket or device queue is backpressure, not a failed probe.
		case unix.EAGAIN:
			if err := l.wait(ctx, unix.POLLOUT); err != nil {
				return sent, err
			}
		case unix.ENOBUFS:
			// The socket still polls writable while the device queue drains.
			time.Sleep(100 * time.Microsecond)
		case unix.EINTR:
		default:
			return sent, errno
		}
	}
	return sent, nil
}

// Stats adds the kernel's socket drop counter, which resets on each read.
func (l *live) Stats() Stats {
	l.statsMu.Lock()
	defer l.statsMu.Unlock()
	if s, err := unix.GetsockoptTpacketStats(l.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS); err == nil {
		l.dropped += uint64(s.Drops)
	}
	return Stats{Received: l.rx.Load(), Sent: l.tx.Load(), Dropped: l.dropped}
}
func (l *live) Close() error { return syscall.Close(l.fd) }
