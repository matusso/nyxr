package packet

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Decoded is a compact value copied from the reusable decoder state. It does
// not retain references into the input frame.
type Decoded struct {
	Source        netip.Addr `json:"source"`
	Destination   netip.Addr `json:"destination"`
	Protocol      string     `json:"protocol"`
	SourcePort    uint16     `json:"source_port,omitempty"`
	DestPort      uint16     `json:"dest_port,omitempty"`
	TCPFlags      uint8      `json:"tcp_flags,omitempty"`
	TCPSeq        uint32     `json:"tcp_seq,omitempty"`
	TCPAck        uint32     `json:"tcp_ack,omitempty"`
	TCPWindow     uint16     `json:"tcp_window,omitempty"`
	TCPOptions    [40]byte   `json:"-"` // owned copy; TCP's maximum option length
	TCPOptionsLen uint8      `json:"-"`
	IPVersion     uint8      `json:"ip_version,omitempty"`
	TTL           uint8      `json:"ttl,omitempty"`
	DF            bool       `json:"df,omitempty"`
	IPID          uint16     `json:"ip_id,omitempty"`
	Received      time.Time  `json:"-"`
	ICMPType      uint8      `json:"icmp_type,omitempty"`
	ICMPCode      uint8      `json:"icmp_code,omitempty"`
	Quote         QuotedTCP  `json:"-"`
	UDPQuote      QuotedUDP  `json:"-"`
}

// QuotedTCP holds the original packet header included in an ICMP error.
type QuotedTCP struct {
	Source, Destination  netip.Addr
	SourcePort, DestPort uint16
	Sequence             uint32
	Valid                bool
}

// QuotedUDP is the original UDP header included in an ICMP error.
type QuotedUDP struct {
	Source, Destination  netip.Addr
	SourcePort, DestPort uint16
	Length, Checksum     uint16
	Valid                bool
}

// Decoder belongs to one RX worker. It must not be shared concurrently.
// The hot path reuses both layer structs and the decoded-layer slice.
type Decoder struct {
	eth     layers.Ethernet
	vlan    layers.Dot1Q
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	icmp4   layers.ICMPv4
	icmp6   layers.ICMPv6
	payload gopacket.Payload
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
}

func NewDecoder() *Decoder {
	d := &Decoder{decoded: make([]gopacket.LayerType, 0, 8)}
	d.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&d.eth, &d.vlan, &d.ip4, &d.ip6, &d.tcp, &d.udp, &d.icmp4, &d.icmp6, &d.payload)
	d.parser.IgnoreUnsupported = true
	return d
}

func (d *Decoder) Decode(frame []byte) (Decoded, bool) {
	if fragmentedIPv6Frame(frame) {
		return Decoded{}, false
	}
	d.decoded = d.decoded[:0]
	if err := d.parser.DecodeLayers(frame, &d.decoded); err != nil {
		return Decoded{}, false
	}
	var result Decoded
	var hasIP bool
	var fragmented bool
	for _, typ := range d.decoded {
		switch typ {
		case layers.LayerTypeIPv4:
			result.IPVersion, result.TTL, result.DF, result.IPID = 4, d.ip4.TTL, d.ip4.Flags&layers.IPv4DontFragment != 0, d.ip4.Id
			result.Source, _ = netip.AddrFromSlice(d.ip4.SrcIP)
			result.Destination, _ = netip.AddrFromSlice(d.ip4.DstIP)
			hasIP = true
			fragmented = d.ip4.FragOffset != 0 || d.ip4.Flags&layers.IPv4MoreFragments != 0
		case layers.LayerTypeIPv6:
			result.IPVersion, result.TTL = 6, d.ip6.HopLimit
			result.Source, _ = netip.AddrFromSlice(d.ip6.SrcIP)
			result.Destination, _ = netip.AddrFromSlice(d.ip6.DstIP)
			hasIP = true
		case layers.LayerTypeTCP:
			result.Protocol = "tcp"
			result.SourcePort, result.DestPort = uint16(d.tcp.SrcPort), uint16(d.tcp.DstPort)
			result.TCPSeq, result.TCPAck = d.tcp.Seq, d.tcp.Ack
			result.TCPWindow = d.tcp.Window
			headerLen := int(d.tcp.DataOffset) * 4
			if headerLen < 20 || headerLen > 60 || len(d.tcp.Contents) < headerLen {
				return Decoded{}, false
			}
			result.TCPOptionsLen = uint8(copy(result.TCPOptions[:], d.tcp.Contents[20:headerLen]))
			if d.tcp.ECE {
				result.TCPFlags |= 64
			}
			if d.tcp.CWR {
				result.TCPFlags |= 128
			}
			if d.tcp.FIN {
				result.TCPFlags |= 1
			}
			if d.tcp.SYN {
				result.TCPFlags |= 2
			}
			if d.tcp.RST {
				result.TCPFlags |= 4
			}
			if d.tcp.PSH {
				result.TCPFlags |= 8
			}
			if d.tcp.ACK {
				result.TCPFlags |= 16
			}
			if d.tcp.URG {
				result.TCPFlags |= 32
			}
		case layers.LayerTypeUDP:
			result.Protocol = "udp"
			result.SourcePort, result.DestPort = uint16(d.udp.SrcPort), uint16(d.udp.DstPort)
		case layers.LayerTypeICMPv4:
			result.Protocol = "icmp"
			result.ICMPType = uint8(d.icmp4.TypeCode.Type())
			result.ICMPCode = uint8(d.icmp4.TypeCode.Code())
			result.Quote = parseQuotedTCP(d.icmp4.Payload)
			if result.ICMPType == 3 {
				result.UDPQuote = parseQuotedUDP(d.icmp4.Payload)
			}
		case layers.LayerTypeICMPv6:
			result.Protocol = "icmp6"
			result.ICMPType = uint8(d.icmp6.TypeCode.Type())
			result.ICMPCode = uint8(d.icmp6.TypeCode.Code())
			if result.ICMPType == 1 && len(d.icmp6.Payload) >= 4 {
				result.UDPQuote = parseQuotedUDP(d.icmp6.Payload[4:])
			}
		}
	}
	return result, hasIP && !fragmented && result.Protocol != ""
}

func parseQuotedUDP(raw []byte) QuotedUDP {
	var q QuotedUDP
	var udp []byte
	if len(raw) >= 20 && raw[0]>>4 == 4 {
		hlen := int(raw[0]&15) * 4
		if hlen < 20 || len(raw) < hlen+8 || raw[9] != 17 || binary.BigEndian.Uint16(raw[6:8])&0x3fff != 0 {
			return q
		}
		q.Source = netip.AddrFrom4([4]byte(raw[12:16]))
		q.Destination = netip.AddrFrom4([4]byte(raw[16:20]))
		udp = raw[hlen:]
	} else if len(raw) >= 48 && raw[0]>>4 == 6 && raw[6] == 17 {
		q.Source = netip.AddrFrom16([16]byte(raw[8:24]))
		q.Destination = netip.AddrFrom16([16]byte(raw[24:40]))
		udp = raw[40:]
	} else {
		return q
	}
	q.SourcePort = binary.BigEndian.Uint16(udp[:2])
	q.DestPort = binary.BigEndian.Uint16(udp[2:4])
	q.Length = binary.BigEndian.Uint16(udp[4:6])
	q.Checksum = binary.BigEndian.Uint16(udp[6:8])
	q.Valid = q.SourcePort != 0 && q.DestPort != 0 && q.Length >= 8
	return q
}

// Discovery does not reassemble IPv6 fragments. Refuse the entire packet,
// including its first fragment, before the parser can expose a TCP/UDP header.
func fragmentedIPv6Frame(frame []byte) bool {
	if len(frame) < 14 {
		return false
	}
	offset := 12
	ethType := binary.BigEndian.Uint16(frame[offset : offset+2])
	if ethType == 0x8100 || ethType == 0x88a8 {
		if len(frame) < 18 {
			return false
		}
		offset += 4
		ethType = binary.BigEndian.Uint16(frame[offset : offset+2])
	}
	if ethType != 0x86dd {
		return false
	}
	ip := frame[offset+2:]
	if len(ip) < 40 {
		return false
	}
	next, at := ip[6], 40
	for i := 0; i < 8; i++ {
		if next == 44 {
			return true
		}
		if next != 0 && next != 43 && next != 60 && next != 51 {
			return false
		}
		if len(ip) < at+2 {
			return true
		}
		length := (int(ip[at+1]) + 1) * 8
		if next == 51 {
			length = (int(ip[at+1]) + 2) * 4
		}
		if len(ip) < at+length {
			return true
		}
		next, at = ip[at], at+length
	}
	return true // excessive extension chain
}

// ICMPv4 quotes at least an IPv4 header and eight transport bytes. Require
// enough bytes for the TCP sequence token and reject later fragments.
func parseQuotedTCP(raw []byte) QuotedTCP {
	if len(raw) < 28 || raw[0]>>4 != 4 || raw[9] != 6 {
		return QuotedTCP{}
	}
	hlen := int(raw[0]&15) * 4
	if hlen < 20 || len(raw) < hlen+8 || raw[6]&0x1f != 0 || raw[7] != 0 {
		return QuotedTCP{}
	}
	var q QuotedTCP
	q.Source = netip.AddrFrom4([4]byte(raw[12:16]))
	q.Destination = netip.AddrFrom4([4]byte(raw[16:20]))
	q.SourcePort = uint16(raw[hlen])<<8 | uint16(raw[hlen+1])
	q.DestPort = uint16(raw[hlen+2])<<8 | uint16(raw[hlen+3])
	q.Sequence = uint32(raw[hlen+4])<<24 | uint32(raw[hlen+5])<<16 | uint32(raw[hlen+6])<<8 | uint32(raw[hlen+7])
	q.Valid = true
	return q
}
