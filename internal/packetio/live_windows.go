//go:build windows

package packetio

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Npcap is loaded at runtime, keeping cross-builds cgo-free. The device is
// an Npcap adapter name such as \\Device\\NPF_{GUID}.
var wpcap = syscall.NewLazyDLL("wpcap.dll")
var (
	pcapOpen     = wpcap.NewProc("pcap_open_live")
	pcapNext     = wpcap.NewProc("pcap_next_ex")
	pcapSend     = wpcap.NewProc("pcap_sendpacket")
	pcapStats    = wpcap.NewProc("pcap_stats")
	pcapClose    = wpcap.NewProc("pcap_close")
	pcapLink     = wpcap.NewProc("pcap_datalink")
	pcapError    = wpcap.NewProc("pcap_geterr")
	pcapNonblock = wpcap.NewProc("pcap_setnonblock")
)

type pcapHeader struct {
	seconds, micros  int32
	captured, length uint32
}

type npcapLive struct {
	handle         uintptr
	mu             sync.Mutex
	received, sent uint64
}

func OpenLive(device string) (PacketIO, error) {
	if device == "" {
		return nil, errors.New("Npcap adapter name is required")
	}
	if err := wpcap.Load(); err != nil {
		return nil, fmt.Errorf("Npcap wpcap.dll unavailable: %w", err)
	}
	name, err := syscall.BytePtrFromString(device)
	if err != nil {
		return nil, err
	}
	var errbuf [256]byte
	handle, _, _ := pcapOpen.Call(uintptr(unsafe.Pointer(name)), 65535, 0, 100, uintptr(unsafe.Pointer(&errbuf[0])))
	if handle == 0 {
		return nil, fmt.Errorf("Npcap open %s: %s", device, cString(errbuf[:]))
	}
	link, _, _ := pcapLink.Call(handle)
	if link != 1 {
		pcapClose.Call(handle)
		return nil, fmt.Errorf("Npcap adapter %s has link type %d, expected Ethernet", device, link)
	}
	ret, _, _ := pcapNonblock.Call(handle, 1, uintptr(unsafe.Pointer(&errbuf[0])))
	if int32(ret) != 0 {
		pcapClose.Call(handle)
		return nil, fmt.Errorf("Npcap nonblocking mode: %s", cString(errbuf[:]))
	}
	return &npcapLive{handle: handle}, nil
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func (n *npcapLive) error() error {
	p, _, _ := pcapError.Call(n.handle)
	if p == 0 {
		return errors.New("Npcap operation failed")
	}
	b := make([]byte, 0, 128)
	for i := uintptr(0); i < 256; i++ {
		c := *(*byte)(unsafe.Pointer(p + i))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return fmt.Errorf("Npcap: %s", string(b))
}

func (n *npcapLive) ReceiveBatch(ctx context.Context, buffers [][]byte) (int, error) {
	count := 0
	for count < len(buffers) {
		if err := ctx.Err(); err != nil {
			return count, err
		}
		var hdr *pcapHeader
		var data *byte
		n.mu.Lock()
		result, _, _ := pcapNext.Call(n.handle, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data)))
		switch int32(result) {
		case 0:
			n.mu.Unlock()
			if count != 0 {
				return count, nil
			}
			time.Sleep(time.Millisecond)
			continue
		case 1:
			if hdr == nil || data == nil || hdr.captured > uint32(len(buffers[count])) {
				n.mu.Unlock()
				return count, errors.New("Npcap frame exceeds receive buffer")
			}
			copy(buffers[count], unsafe.Slice(data, hdr.captured))
			n.received++
			n.mu.Unlock()
			buffers[count] = buffers[count][:hdr.captured]
			count++
		default:
			err := n.error()
			n.mu.Unlock()
			return count, err
		}
	}
	return count, nil
}

func (n *npcapLive) SendBatch(ctx context.Context, frames [][]byte) (int, error) {
	for i, frame := range frames {
		if err := ctx.Err(); err != nil {
			return i, err
		}
		if len(frame) == 0 {
			return i, errors.New("empty Ethernet frame")
		}
		n.mu.Lock()
		ret, _, _ := pcapSend.Call(n.handle, uintptr(unsafe.Pointer(&frame[0])), uintptr(len(frame)))
		if int32(ret) != 0 {
			err := n.error()
			n.mu.Unlock()
			return i, err
		}
		n.sent++
		n.mu.Unlock()
	}
	return len(frames), nil
}

func (n *npcapLive) Stats() Stats {
	n.mu.Lock()
	defer n.mu.Unlock()
	var raw [3]uint32
	ret, _, _ := pcapStats.Call(n.handle, uintptr(unsafe.Pointer(&raw[0])))
	if int32(ret) == 0 {
		return Stats{Received: n.received, Sent: n.sent, Dropped: uint64(raw[1])}
	}
	return Stats{Received: n.received, Sent: n.sent}
}
func (n *npcapLive) Close() error { pcapClose.Call(n.handle); return nil }
