// Package lab supplies deterministic fake responders for scanner tests.
package lab

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/matusso/nyxr/internal/packetio"
)

type Behavior struct {
	Latency          time.Duration
	DropFirst        int
	DropEvery        int  // 1 drops every request; 2 drops every second request.
	Duplicates       int  // Extra copies after the first reply.
	ProtocolMismatch bool // Corrupt a DNS transaction token or TCP ACK.
	ICMPLimit        int  // Maximum ICMP errors; zero means unlimited.
}

func dropped(n, every int) bool { return every > 0 && n%every == 0 }

type UDPResponder struct {
	conn           *net.UDPConn
	behavior       Behavior
	mu             sync.Mutex
	received, sent int
	done           chan struct{}
}

func NewUDPResponder(b Behavior) (*UDPResponder, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	r := &UDPResponder{conn: conn, behavior: b, done: make(chan struct{})}
	go r.serve()
	return r, nil
}

func (r *UDPResponder) Port() uint16 { return uint16(r.conn.LocalAddr().(*net.UDPAddr).Port) }
func (r *UDPResponder) Counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.received, r.sent
}
// Close stops reading, lets an in-flight reply burst finish, then closes the
// socket, so Counts is final once Close returns.
func (r *UDPResponder) Close() error {
	r.conn.SetReadDeadline(time.Now())
	<-r.done
	return r.conn.Close()
}

func (r *UDPResponder) serve() {
	defer close(r.done)
	var buf [4096]byte
	for {
		n, peer, err := r.conn.ReadFromUDP(buf[:])
		if err != nil {
			return
		}
		r.mu.Lock()
		r.received++
		count := r.received
		r.mu.Unlock()
		if count <= r.behavior.DropFirst || dropped(count, r.behavior.DropEvery) {
			continue
		}
		if r.behavior.Latency > 0 {
			time.Sleep(r.behavior.Latency)
		}
		response := append([]byte(nil), buf[:n]...)
		if len(response) >= 12 {
			response[2] |= 0x80
		}
		if r.behavior.ProtocolMismatch && len(response) >= 2 {
			response[0] ^= 0xff
		}
		for i := 0; i <= r.behavior.Duplicates; i++ {
			if _, err := r.conn.WriteToUDP(response, peer); err != nil {
				return
			}
			r.mu.Lock()
			r.sent++
			r.mu.Unlock()
		}
	}
}

// SYNResponder implements the packet I/O boundary without a privileged NIC.
// Mode is open, closed, icmp, or silent. ICMP mode sends destination-unreachable
// quotations and can cap them to model gateway rate limiting.
type SYNResponder struct {
	Behavior                   Behavior
	Mode                       string
	frames                     chan []byte
	mu                         sync.Mutex
	received, sent, icmp, lost int
}

func NewSYNResponder(mode string, b Behavior) *SYNResponder {
	return &SYNResponder{Mode: mode, Behavior: b, frames: make(chan []byte, 128)}
}

func (r *SYNResponder) Counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.received, r.sent
}
func (r *SYNResponder) Stats() packetio.Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return packetio.Stats{Received: uint64(r.received), Sent: uint64(r.sent), Dropped: uint64(r.lost)}
}
func (r *SYNResponder) Close() error { return nil }

func (r *SYNResponder) ReceiveBatch(ctx context.Context, buffers [][]byte) (int, error) {
	select {
	case frame := <-r.frames:
		copy(buffers[0], frame)
		buffers[0] = buffers[0][:len(frame)]
		return 1, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (r *SYNResponder) SendBatch(ctx context.Context, frames [][]byte) (int, error) {
	for _, request := range frames {
		r.mu.Lock()
		r.sent++
		count := r.sent
		allowICMP := r.Behavior.ICMPLimit == 0 || r.icmp < r.Behavior.ICMPLimit
		if r.Mode == "icmp" && allowICMP {
			r.icmp++
		}
		r.mu.Unlock()
		if count <= r.Behavior.DropFirst || dropped(count, r.Behavior.DropEvery) || r.Mode == "silent" || (r.Mode == "icmp" && !allowICMP) {
			r.mu.Lock()
			r.lost++
			r.mu.Unlock()
			continue
		}
		if r.Behavior.Latency > 0 {
			time.Sleep(r.Behavior.Latency)
		}
		var reply []byte
		if r.Mode == "icmp" {
			reply = icmpQuote(request)
		} else {
			reply = tcpReply(request, r.Mode == "open", r.Behavior.ProtocolMismatch)
		}
		for i := 0; i <= r.Behavior.Duplicates; i++ {
			select {
			case r.frames <- append([]byte(nil), reply...):
				r.mu.Lock()
				r.received++
				r.mu.Unlock()
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}
	}
	return len(frames), nil
}

func tcpReply(request []byte, open, mismatch bool) []byte {
	reply := append([]byte(nil), request...)
	copy(reply[:6], request[6:12])
	copy(reply[6:12], request[:6])
	copy(reply[26:30], request[30:34])
	copy(reply[30:34], request[26:30])
	copy(reply[34:36], request[36:38])
	copy(reply[36:38], request[34:36])
	ack := binary.BigEndian.Uint32(request[38:42]) + 1
	if mismatch {
		ack++
	}
	binary.BigEndian.PutUint32(reply[42:46], ack)
	if open {
		reply[47] = 0x12
	} else {
		reply[47] = 0x14
	}
	return reply
}

func icmpQuote(request []byte) []byte {
	eth := &layers.Ethernet{SrcMAC: append(net.HardwareAddr(nil), request[:6]...), DstMAC: append(net.HardwareAddr(nil), request[6:12]...), EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: net.IP{request[30], request[31], request[32], request[33]}, DstIP: net.IP{request[26], request[27], request[28], request[29]}}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(3, 13)}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, icmp, gopacket.Payload(request[14:42])); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
