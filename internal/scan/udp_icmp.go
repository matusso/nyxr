package scan

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
)

// A raw ICMP listener is optional: unprivileged scans still use UDP socket
// errors. One listener per address family serves the entire bounded campaign.
type udpICMPObserver struct {
	mu      sync.RWMutex
	waiters map[udpFlow]chan icmpUDPError
	conns   []net.PacketConn
	v4, v6  bool
	wg      sync.WaitGroup
}

type udpFlow struct {
	source, target         netip.Addr
	sourcePort, targetPort uint16
}

type icmpUDPError struct {
	flow     udpFlow
	length   uint16
	checksum uint16
	state    string
	reason   string
}

func openUDPICMP(targets []netip.Addr) *udpICMPObserver {
	o := &udpICMPObserver{waiters: make(map[udpFlow]chan icmpUDPError)}
	var need4, need6 bool
	for _, target := range targets {
		need4 = need4 || target.Is4()
		need6 = need6 || target.Is6()
	}
	for _, spec := range []struct {
		needed           bool
		network, address string
		v6               bool
	}{{need4, "ip4:icmp", "0.0.0.0", false}, {need6, "ip6:ipv6-icmp", "::", true}} {
		if !spec.needed {
			continue
		}
		conn, err := net.ListenPacket(spec.network, spec.address)
		if err != nil { // Raw sockets generally require privileges.
			continue
		}
		o.conns = append(o.conns, conn)
		if spec.v6 {
			o.v6 = true
		} else {
			o.v4 = true
		}
		o.wg.Add(1)
		go o.read(conn)
	}
	return o
}

func (o *udpICMPObserver) available(target netip.Addr) bool {
	return o != nil && ((target.Is4() && o.v4) || (target.Is6() && o.v6))
}

func (o *udpICMPObserver) register(flow udpFlow) <-chan icmpUDPError {
	if !o.available(flow.target) {
		return nil
	}
	ch := make(chan icmpUDPError, 8)
	o.mu.Lock()
	o.waiters[flow] = ch
	o.mu.Unlock()
	return ch
}

func (o *udpICMPObserver) unregister(flow udpFlow) {
	if o == nil {
		return
	}
	o.mu.Lock()
	delete(o.waiters, flow)
	o.mu.Unlock()
}

func (o *udpICMPObserver) Close() {
	if o == nil {
		return
	}
	for _, conn := range o.conns {
		_ = conn.Close()
	}
	o.wg.Wait()
}

func (o *udpICMPObserver) read(conn net.PacketConn) {
	defer o.wg.Done()
	var buf [2048]byte
	for {
		n, _, err := conn.ReadFrom(buf[:])
		if err != nil {
			return
		}
		if event, ok := parseICMPUDP(buf[:n]); ok {
			o.dispatch(event)
		}
	}
}

func (o *udpICMPObserver) dispatch(event icmpUDPError) {
	o.mu.RLock()
	ch := o.waiters[event.flow]
	if ch != nil {
		select {
		case ch <- event:
		default:
		}
	}
	o.mu.RUnlock()
}

// parseICMPUDP accepts raw IPv4/IPv6 ICMP messages with or without an outer
// IP header. The quote must contain an unfragmented original IP header and
// the full eight-byte UDP header. Routers may send the error, so the quoted
// addresses and ports, rather than the router's address, identify the probe.
func parseICMPUDP(raw []byte) (icmpUDPError, bool) {
	if len(raw) >= 20 && raw[0]>>4 == 4 {
		h := int(raw[0]&15) * 4
		if h < 20 || len(raw) < h+8 || raw[9] != 1 {
			return icmpUDPError{}, false
		}
		raw = raw[h:]
	} else if len(raw) >= 40 && raw[0]>>4 == 6 {
		if raw[6] != 58 {
			return icmpUDPError{}, false
		}
		raw = raw[40:]
	}
	if len(raw) < 8 {
		return icmpUDPError{}, false
	}
	var event icmpUDPError
	var quote []byte
	switch raw[0] {
	case 3: // ICMPv4 destination unreachable
		if len(raw) < 8+20 {
			return icmpUDPError{}, false
		}
		quote = raw[8:]
		if quote[0]>>4 != 4 {
			return icmpUDPError{}, false
		}
		if raw[1] == 3 {
			event.state, event.reason = "closed", "ICMPv4 port unreachable (quoted UDP probe)"
		} else {
			event.state, event.reason = "filtered", "ICMPv4 destination unreachable (quoted UDP probe)"
		}
	case 1: // ICMPv6 destination unreachable
		if len(raw) < 8+40 {
			return icmpUDPError{}, false
		}
		quote = raw[8:]
		if quote[0]>>4 != 6 {
			return icmpUDPError{}, false
		}
		if raw[1] == 4 {
			event.state, event.reason = "closed", "ICMPv6 port unreachable (quoted UDP probe)"
		} else {
			event.state, event.reason = "filtered", "ICMPv6 destination unreachable (quoted UDP probe)"
		}
	default:
		return icmpUDPError{}, false
	}
	var udp []byte
	if quote[0]>>4 == 4 {
		h := int(quote[0]&15) * 4
		if h < 20 || len(quote) < h+8 || quote[9] != 17 || binary.BigEndian.Uint16(quote[6:8])&0x3fff != 0 {
			return icmpUDPError{}, false
		}
		event.flow.source = netip.AddrFrom4([4]byte(quote[12:16]))
		event.flow.target = netip.AddrFrom4([4]byte(quote[16:20]))
		udp = quote[h:]
	} else {
		if len(quote) < 48 || quote[6] != 17 {
			return icmpUDPError{}, false
		}
		event.flow.source = netip.AddrFrom16([16]byte(quote[8:24]))
		event.flow.target = netip.AddrFrom16([16]byte(quote[24:40]))
		udp = quote[40:]
	}
	event.flow.sourcePort = binary.BigEndian.Uint16(udp[:2])
	event.flow.targetPort = binary.BigEndian.Uint16(udp[2:4])
	event.length = binary.BigEndian.Uint16(udp[4:6])
	event.checksum = binary.BigEndian.Uint16(udp[6:8])
	return event, event.flow.sourcePort != 0 && event.flow.targetPort != 0 && event.length >= 8
}

func udpChecksum(flow udpFlow, request []byte) uint16 {
	var sum uint32
	add := func(data []byte) {
		for len(data) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
		}
		if len(data) != 0 {
			sum += uint32(data[0]) << 8
		}
	}
	add(flow.source.AsSlice())
	add(flow.target.AsSlice())
	length := uint16(len(request) + 8)
	// Both pseudoheaders contribute the UDP protocol number and length. The
	// IPv6 length is 32-bit, but a UDP datagram fits in its lower 16 bits.
	sum += 17 + uint32(length)
	var header [8]byte
	binary.BigEndian.PutUint16(header[:2], flow.sourcePort)
	binary.BigEndian.PutUint16(header[2:4], flow.targetPort)
	binary.BigEndian.PutUint16(header[4:6], length)
	add(header[:])
	add(request)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	result := ^uint16(sum)
	if result == 0 {
		return 0xffff
	}
	return result
}
