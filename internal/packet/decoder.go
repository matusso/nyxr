package packet

import (
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Decoded is a compact value copied from the reusable decoder state. It does
// not retain references into the input frame.
type Decoded struct {
	Source      netip.Addr `json:"source"`
	Destination netip.Addr `json:"destination"`
	Protocol    string     `json:"protocol"`
	SourcePort  uint16     `json:"source_port,omitempty"`
	DestPort    uint16     `json:"dest_port,omitempty"`
	TCPFlags    uint8      `json:"tcp_flags,omitempty"`
	ICMPType    uint8      `json:"icmp_type,omitempty"`
}

// Decoder belongs to one RX worker. It must not be shared concurrently.
// The hot path reuses both layer structs and the decoded-layer slice.
type Decoder struct {
	eth     layers.Ethernet
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
		&d.eth, &d.ip4, &d.ip6, &d.tcp, &d.udp, &d.icmp4, &d.icmp6, &d.payload)
	d.parser.IgnoreUnsupported = true
	return d
}

func (d *Decoder) Decode(frame []byte) (Decoded, bool) {
	d.decoded = d.decoded[:0]
	if err := d.parser.DecodeLayers(frame, &d.decoded); err != nil {
		return Decoded{}, false
	}
	var result Decoded
	var hasIP bool
	for _, typ := range d.decoded {
		switch typ {
		case layers.LayerTypeIPv4:
			result.Source, _ = netip.AddrFromSlice(d.ip4.SrcIP)
			result.Destination, _ = netip.AddrFromSlice(d.ip4.DstIP)
			hasIP = true
		case layers.LayerTypeIPv6:
			result.Source, _ = netip.AddrFromSlice(d.ip6.SrcIP)
			result.Destination, _ = netip.AddrFromSlice(d.ip6.DstIP)
			hasIP = true
		case layers.LayerTypeTCP:
			result.Protocol = "tcp"
			result.SourcePort, result.DestPort = uint16(d.tcp.SrcPort), uint16(d.tcp.DstPort)
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
		case layers.LayerTypeICMPv6:
			result.Protocol = "icmp6"
			result.ICMPType = uint8(d.icmp6.TypeCode.Type())
		}
	}
	return result, hasIP && result.Protocol != ""
}
