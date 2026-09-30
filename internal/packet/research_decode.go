package packet

import (
	"encoding/binary"
	"net/netip"
)

// ResearchDecoded retains only fields needed to correlate a research probe.
// Fragmented replies are ignored because this path never reassembles them.
type ResearchDecoded struct {
	Source, Destination  netip.Addr
	Protocol             uint8
	SourcePort, DestPort uint16
	TCPFlags             uint8
	TCPAck               uint32
	SCTPChunk            uint8
	SCTPTag              uint32
	ICMPType, ICMPCode   uint8
	ICMPID, ICMPSeq      uint16
	Quote                ResearchQuote
}

type ResearchQuote struct {
	Source, Destination  netip.Addr
	Protocol             uint8
	ID                   uint16
	FlowLabel            uint32
	SourcePort, DestPort uint16
	Sequence             uint32
	Valid                bool
}

// DecodeResearch accepts Ethernet/VLAN and bounded IPv6 extension chains.
// Malformed, truncated and noninitial fragments never become observations.
func DecodeResearch(frame []byte) (ResearchDecoded, bool) {
	var p ResearchDecoded
	if len(frame) < 14 {
		return p, false
	}
	at := 14
	eth := binary.BigEndian.Uint16(frame[12:14])
	for i := 0; i < 2 && (eth == 0x8100 || eth == 0x88a8); i++ {
		if len(frame) < at+4 {
			return p, false
		}
		eth = binary.BigEndian.Uint16(frame[at+2 : at+4])
		at += 4
	}
	if eth == 0x0800 {
		var body []byte
		p.Source, p.Destination, p.Protocol, body, _, _ = parseResearchIP4(frame[at:])
		if !p.Source.IsValid() {
			return p, false
		}
		return parseResearchBody(p, body)
	}
	if eth == 0x86dd {
		var body []byte
		p.Source, p.Destination, p.Protocol, body = parseResearchIP6(frame[at:])
		if !p.Source.IsValid() {
			return p, false
		}
		return parseResearchBody(p, body)
	}
	return p, false
}

func parseResearchIP4(b []byte) (src, dst netip.Addr, proto uint8, body []byte, id uint16, valid bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return
	}
	hlen := int(b[0]&15) * 4
	if hlen < 20 || len(b) < hlen {
		return
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < hlen || length > len(b) || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		return
	}
	if internetChecksum(b[:hlen]) != 0 {
		return
	}
	src = netip.AddrFrom4([4]byte(b[12:16]))
	dst = netip.AddrFrom4([4]byte(b[16:20]))
	return src, dst, b[9], b[hlen:length], binary.BigEndian.Uint16(b[4:6]), true
}

func parseResearchIP6(b []byte) (src, dst netip.Addr, proto uint8, body []byte) {
	if len(b) < 40 || b[0]>>4 != 6 {
		return
	}
	length := int(binary.BigEndian.Uint16(b[4:6]))
	if len(b) < 40+length {
		return
	} // jumbograms unsupported
	b = b[:40+length]
	src = netip.AddrFrom16([16]byte(b[8:24]))
	dst = netip.AddrFrom16([16]byte(b[24:40]))
	next, at := b[6], 40
	for i := 0; i < 8; i++ {
		if next == 44 || next == 50 || next == 59 {
			return netip.Addr{}, netip.Addr{}, 0, nil
		}
		if next != 0 && next != 43 && next != 60 && next != 51 {
			return src, dst, next, b[at:]
		}
		if len(b) < at+2 {
			break
		}
		size := (int(b[at+1]) + 1) * 8
		if next == 51 {
			size = (int(b[at+1]) + 2) * 4
		}
		if size < 8 || len(b) < at+size {
			break
		}
		next, at = b[at], at+size
	}
	return netip.Addr{}, netip.Addr{}, 0, nil
}

func parseResearchBody(p ResearchDecoded, b []byte) (ResearchDecoded, bool) {
	switch p.Protocol {
	case 6:
		if len(b) < 20 || b[12]>>4 < 5 || int(b[12]>>4)*4 > len(b) {
			return p, false
		}
		p.SourcePort, p.DestPort = binary.BigEndian.Uint16(b[0:2]), binary.BigEndian.Uint16(b[2:4])
		p.TCPAck, p.TCPFlags = binary.BigEndian.Uint32(b[8:12]), b[13]
	case 17:
		if len(b) < 8 || binary.BigEndian.Uint16(b[4:6]) < 8 || int(binary.BigEndian.Uint16(b[4:6])) > len(b) {
			return p, false
		}
		p.SourcePort, p.DestPort = binary.BigEndian.Uint16(b[0:2]), binary.BigEndian.Uint16(b[2:4])
	case 132:
		if len(b) < 16 || !validSCTPCRC(b) {
			return p, false
		}
		p.SourcePort, p.DestPort = binary.BigEndian.Uint16(b[0:2]), binary.BigEndian.Uint16(b[2:4])
		p.SCTPTag, p.SCTPChunk = binary.BigEndian.Uint32(b[4:8]), b[12]
		if p.SCTPChunk == 2 && len(b) < 32 {
			return p, false
		}
	case 1, 58:
		if len(b) < 8 {
			return p, false
		}
		p.ICMPType, p.ICMPCode = b[0], b[1]
		p.ICMPID, p.ICMPSeq = binary.BigEndian.Uint16(b[4:6]), binary.BigEndian.Uint16(b[6:8])
		if (p.Protocol == 1 && p.ICMPType == 3) || (p.Protocol == 58 && (p.ICMPType == 1 || p.ICMPType == 4)) {
			p.Quote = parseResearchQuote(b[8:])
		}
	}
	return p, true
}

func parseResearchQuote(b []byte) ResearchQuote {
	var q ResearchQuote
	if len(b) == 0 {
		return q
	}
	var body []byte
	if b[0]>>4 == 4 {
		// ICMP may quote a truncated datagram; validate the quoted IP header
		// but do not require its declared total length to be present.
		if len(b) < 20 {
			return q
		}
		hlen := int(b[0]&15) * 4
		if hlen < 20 || len(b) < hlen || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
			return q
		}
		q.Source, q.Destination = netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20]))
		q.Protocol, q.ID = b[9], binary.BigEndian.Uint16(b[4:6])
		body = b[hlen:]
	} else if b[0]>>4 == 6 {
		var src, dst netip.Addr
		// Quotes can be shorter than the original IPv6 payload, so walk the
		// available extension bytes using a bounded synthetic payload length.
		if len(b) < 40 {
			return q
		}
		q.FlowLabel = uint32(b[1]&0x0f)<<16 | uint32(b[2])<<8 | uint32(b[3])
		copyB := append([]byte(nil), b...)
		binary.BigEndian.PutUint16(copyB[4:6], uint16(len(copyB)-40))
		src, dst, q.Protocol, body = parseResearchIP6(copyB)
		q.Source, q.Destination = src, dst
	} else {
		return q
	}
	if !q.Source.IsValid() {
		return q
	}
	if (q.Protocol == 6 || q.Protocol == 17 || q.Protocol == 132) && len(body) >= 4 {
		q.SourcePort, q.DestPort = binary.BigEndian.Uint16(body[:2]), binary.BigEndian.Uint16(body[2:4])
	}
	if q.Protocol == 6 && len(body) >= 8 {
		q.Sequence = binary.BigEndian.Uint32(body[4:8])
	}
	q.Valid = true
	return q
}
