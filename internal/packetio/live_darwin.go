//go:build darwin

package packetio

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// BPF supplies Ethernet frames in aligned records. One descriptor owns its
// receive buffer, so callers must not call ReceiveBatch concurrently.
type bpfLive struct {
	fd       int
	data     []byte
	offset   int
	received atomic.Uint64
	sent     atomic.Uint64
}

func bpfIoctl(fd int, request uintptr, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

func OpenLive(device string) (PacketIO, error) {
	if device == "" || len(device) >= 16 {
		return nil, errors.New("BPF requires an interface name shorter than 16 bytes")
	}
	var fd int
	var err error
	for i := 0; i < 256; i++ {
		fd, err = syscall.Open(fmt.Sprintf("/dev/bpf%d", i), syscall.O_RDWR|syscall.O_NONBLOCK, 0)
		if err == nil {
			break
		}
		if errors.Is(err, syscall.EBUSY) {
			continue
		}
		if errors.Is(err, syscall.ENOENT) && i == 0 {
			return nil, fmt.Errorf("BPF devices unavailable: %w", err)
		}
		return nil, fmt.Errorf("open BPF device: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("no free BPF device: %w", err)
	}
	closeOnError := func(err error) (PacketIO, error) { _ = syscall.Close(fd); return nil, err }
	// ifreq begins with IFNAMSIZ bytes; the union remains zeroed.
	var ifreq [32]byte
	copy(ifreq[:16], device)
	if err := bpfIoctl(fd, syscall.BIOCSETIF, unsafe.Pointer(&ifreq[0])); err != nil {
		return closeOnError(fmt.Errorf("bind BPF to %s: %w", device, err))
	}
	var dlt uint32
	if err := bpfIoctl(fd, syscall.BIOCGDLT, unsafe.Pointer(&dlt)); err != nil {
		return closeOnError(err)
	}
	if dlt != 1 {
		return closeOnError(fmt.Errorf("interface %s has link type %d, expected Ethernet", device, dlt))
	}
	one := uint32(1)
	if err := bpfIoctl(fd, syscall.BIOCIMMEDIATE, unsafe.Pointer(&one)); err != nil {
		return closeOnError(err)
	}
	if err := bpfIoctl(fd, syscall.BIOCSHDRCMPLT, unsafe.Pointer(&one)); err != nil {
		return closeOnError(err)
	}
	var size uint32
	if err := bpfIoctl(fd, syscall.BIOCGBLEN, unsafe.Pointer(&size)); err != nil {
		return closeOnError(err)
	}
	if size == 0 || size > 1<<20 {
		return closeOnError(fmt.Errorf("invalid BPF buffer size %d", size))
	}
	return &bpfLive{fd: fd, data: make([]byte, size), offset: int(size)}, nil
}

func (b *bpfLive) ReceiveBatch(ctx context.Context, buffers [][]byte) (int, error) {
	count := 0
	for count < len(buffers) {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		if b.offset >= len(b.data) {
			n, err := syscall.Read(b.fd, b.data[:cap(b.data)])
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				if count != 0 {
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
			b.data, b.offset = b.data[:n], 0
			continue
		}
		frame, advance, ok := bpfRecord(b.data[b.offset:])
		if !ok {
			b.offset = len(b.data)
			continue
		}
		b.offset += advance
		if len(buffers[count]) < len(frame) {
			return count, fmt.Errorf("receive buffer too small for %d-byte frame", len(frame))
		}
		buffers[count] = buffers[count][:copy(buffers[count], frame)]
		count++
		b.received.Add(1)
	}
	return count, nil
}

// bpfRecord decodes one record. Userland bpf_hdr on macOS uses a 32-bit
// timeval even for 64-bit processes: tstamp (8), caplen, datalen, hdrlen.
func bpfRecord(h []byte) (frame []byte, advance int, ok bool) {
	if len(h) < 18 {
		return nil, 0, false
	}
	caplen := int(binary.NativeEndian.Uint32(h[8:12]))
	hdrlen := int(binary.NativeEndian.Uint16(h[16:18]))
	if hdrlen < 18 || caplen < 14 || hdrlen+caplen > len(h) {
		return nil, 0, false
	}
	return h[hdrlen : hdrlen+caplen], (hdrlen + caplen + 3) &^ 3, true
}

func (b *bpfLive) SendBatch(ctx context.Context, frames [][]byte) (int, error) {
	for i, frame := range frames {
		if err := ctx.Err(); err != nil {
			return i, err
		}
		n, err := syscall.Write(b.fd, frame)
		if err != nil {
			return i, err
		}
		if n != len(frame) {
			return i, os.ErrInvalid
		}
		b.sent.Add(1)
	}
	return len(frames), nil
}

func (b *bpfLive) Stats() Stats {
	var kernel [2]uint32
	if err := bpfIoctl(b.fd, syscall.BIOCGSTATS, unsafe.Pointer(&kernel[0])); err == nil {
		return Stats{Received: b.received.Load(), Sent: b.sent.Load(), Dropped: uint64(kernel[1])}
	}
	return Stats{Received: b.received.Load(), Sent: b.sent.Load()}
}
func (b *bpfLive) Close() error { return syscall.Close(b.fd) }
