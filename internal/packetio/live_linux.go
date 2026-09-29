//go:build linux

package packetio

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

// Linux live I/O uses AF_PACKET. ReceiveBatch fills caller-owned buffers;
// callers should reuse both the buffers and their decoder per RX worker.
type live struct {
	fd      int
	ifindex int
	rx, tx  atomic.Uint64
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
	_ = syscall.SetNonblock(fd, true)
	return &live{fd: fd, ifindex: iface.Index}, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func (l *live) ReceiveBatch(ctx context.Context, buffers [][]byte) (int, error) {
	count := 0
	for i, buf := range buffers {
		if len(buf) == 0 {
			return count, errors.New("receive buffer is empty")
		}
		for {
			if err := ctx.Err(); err != nil {
				return count, err
			}
			n, _, err := syscall.Recvfrom(l.fd, buf, syscall.MSG_DONTWAIT)
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				if count > 0 {
					return count, nil
				}
				time.Sleep(time.Millisecond)
				continue
			}
			if err == syscall.EINTR {
				continue
			}
			if err != nil {
				return count, err
			}
			buffers[i] = buf[:n]
			count++
			l.rx.Add(1)
			break
		}
	}
	return count, nil
}

func (l *live) SendBatch(ctx context.Context, frames [][]byte) (int, error) {
	for i, frame := range frames {
		if err := ctx.Err(); err != nil {
			return i, err
		}
		if err := syscall.Sendto(l.fd, frame, 0, &syscall.SockaddrLinklayer{Ifindex: l.ifindex, Protocol: htons(syscall.ETH_P_ALL)}); err != nil {
			return i, err
		}
		l.tx.Add(1)
	}
	return len(frames), nil
}

func (l *live) Stats() Stats { return Stats{Received: l.rx.Load(), Sent: l.tx.Load()} }
func (l *live) Close() error { return syscall.Close(l.fd) }
