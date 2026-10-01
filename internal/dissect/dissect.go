// Package dissect turns a captured Ethernet frame into a layer-by-layer,
// human-readable breakdown: every header field with its value, a short note
// on what the field means, and the bytes it occupies in the frame. It backs
// the interactive packet browser and is independent of any terminal code.
package dissect

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/matusso/nyxr/internal/capture"
)

// Field is one decoded header field. Offset and Length locate it in the frame;
// Length is zero when the field has no fixed position (a derived value).
type Field struct {
	Name, Value, Note string
	Indent            int // nesting under the previous field (flag bits, options)
	Offset, Length    int
}

// Layer is one protocol header (or the frame pseudo-layer).
type Layer struct {
	Name    string
	Summary string
	Offset  int
	Length  int
	Fields  []Field
}

// Tone classifies a packet for coloring: what its reply says about a port.
type Tone int

const (
	ToneNone   Tone = iota
	ToneOpen        // SYN-ACK, echo reply, UDP/DNS answers
	ToneClosed      // RST, ICMP port unreachable
	ToneFilter      // other ICMP errors
	ToneProbe       // SYN without ACK, echo request
	ToneError       // malformed or truncated
)

// Summary is the one-line view of a packet in the packet list.
type Summary struct {
	Number      int
	Elapsed     time.Duration // since the first packet in the capture
	Direction   capture.Direction
	Source      string
	Destination string
	Protocol    string
	Length      int
	Info        string
	Tone        Tone
}

// SearchText is the lower-cased text a filter matches against.
func (s Summary) SearchText() string {
	return strings.ToLower(strings.Join([]string{s.Protocol, s.Source, s.Destination, s.Info, s.Direction.String()}, " "))
}

// Packet is a summary plus the full layer breakdown.
type Packet struct {
	Summary
	Layers []Layer
}

func decode(data []byte) gopacket.Packet {
	return gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{NoCopy: true})
}

// Summarize builds only the list row for rec.
func Summarize(rec capture.Record, number int, first time.Time) Summary {
	return summarize(decode(rec.Data), rec, number, first)
}

// Dissect builds the list row and the full layer breakdown for rec.
func Dissect(rec capture.Record, number int, first time.Time) Packet {
	p := decode(rec.Data)
	pkt := Packet{Summary: summarize(p, rec, number, first)}
	pkt.Layers = append(pkt.Layers, frameLayer(rec, pkt.Summary))
	offset := 0
	all := p.Layers()
	for i, l := range all {
		n := len(l.LayerContents())
		failed := ""
		if _, ok := l.(*gopacket.DecodeFailure); ok {
			n = len(rec.Data) - offset
			if i > 0 {
				failed = layerName(all[i-1])
				if isTransport(all[i-1]) {
					n = min(n, len(all[i-1].LayerPayload())) // leave Ethernet padding to the trailer
				}
			}
		}
		if n == 0 && i+1 < len(all) {
			if _, ok := all[i+1].(*gopacket.DecodeFailure); ok {
				continue // gopacket keeps the header it failed to parse; the failure layer reports it
			}
		}
		layer := Layer{Offset: offset, Length: n}
		describe(&layer, l)
		if failed != "" && isTransport(all[i-1]) {
			layer.Name = "Data"
			layer.Summary = plural(n, "byte") + ", not valid " + guessedApp(all[i])
			layer.Fields = []Field{
				{Name: "Data", Value: printable(rec.Data[offset:offset+n], 48), Offset: offset, Length: n,
					Note: "application bytes; the port number suggested a protocol they do not parse as"},
				{Name: "Parser", Value: l.(*gopacket.DecodeFailure).Error().Error(), Note: "why the guessed protocol was rejected"},
			}
		} else if failed != "" {
			layer.Name = "Malformed " + failed
		}
		pkt.Layers = append(pkt.Layers, layer)
		offset += n
	}
	var names []string
	for _, l := range pkt.Layers[1:] {
		names = append(names, l.Name)
	}
	pkt.Layers[0].Fields = append(pkt.Layers[0].Fields, Field{Name: "Protocols", Value: strings.Join(names, " › "),
		Note: "layers in this frame, outermost first"})
	if offset < len(rec.Data) {
		pkt.Layers = append(pkt.Layers, Layer{
			Name: "Trailer", Summary: plural(len(rec.Data)-offset, "byte"), Offset: offset, Length: len(rec.Data) - offset,
			Fields: []Field{{Name: "Padding", Value: hexPreview(rec.Data[offset:], 16), Offset: offset, Length: len(rec.Data) - offset,
				Note: "Ethernet pads short frames to 60 bytes; not part of the IP packet"}},
		})
	}
	return pkt
}

func isTransport(l gopacket.Layer) bool {
	switch l.(type) {
	case *layers.TCP, *layers.UDP:
		return true
	}
	return false
}

// guessedApp names the application protocol gopacket tried from the port
// number, recovered from its error text ("DNS packet too short").
func guessedApp(l gopacket.Layer) string {
	if f, ok := l.(*gopacket.DecodeFailure); ok {
		if word, _, ok := strings.Cut(f.Error().Error(), " "); ok && word != "" {
			return word
		}
	}
	return "application data"
}

// builder appends fields with offsets relative to the layer start.
type builder struct{ l *Layer }

// Fields may reach past the layer (an ICMP error's quoted header lives in the
// following bytes); the renderer clamps ranges to the frame.
func (b builder) add(name, value, note string, off, n int) {
	start := b.l.Offset + off
	if off < 0 {
		start, n = 0, 0
	}
	b.l.Fields = append(b.l.Fields, Field{Name: name, Value: value, Note: note, Offset: start, Length: n})
}

func (b builder) sub(name, value, note string, off, n int) {
	b.add(name, value, note, off, n)
	b.l.Fields[len(b.l.Fields)-1].Indent = 1
}

func frameLayer(rec capture.Record, s Summary) Layer {
	l := Layer{Name: "Frame", Summary: fmt.Sprintf("#%d, %s captured", s.Number, plural(len(rec.Data), "byte")), Length: len(rec.Data)}
	b := builder{&l}
	b.add("Number", strconv.Itoa(s.Number), "position in the capture file", -1, 0)
	if !rec.Timestamp.IsZero() {
		b.add("Arrival time", rec.Timestamp.Local().Format("2006-01-02 15:04:05.000000000 MST"), "when the capturing host saw the frame", -1, 0)
		b.add("Since first packet", fmt.Sprintf("+%.6f s", s.Elapsed.Seconds()), "", -1, 0)
	}
	b.add("Captured length", plural(len(rec.Data), "byte"), "bytes stored in the file", -1, 0)
	if rec.Length > len(rec.Data) {
		b.add("Length on wire", plural(rec.Length, "byte"), "the frame was truncated to the snap length when captured", -1, 0)
	}
	switch rec.Direction {
	case capture.DirectionTX:
		b.add("Direction", "tx (outbound)", "sent by the capturing host (the scanner)", -1, 0)
	case capture.DirectionRX:
		b.add("Direction", "rx (inbound)", "received by the capturing host (the scanner)", -1, 0)
	}
	if rec.PacketID != 0 {
		b.add("nyxr packet ID", strconv.FormatUint(rec.PacketID, 10), "referenced by the scan's packet-evidence records", -1, 0)
	}
	if rec.Comment != "" {
		b.add("Comment", rec.Comment, "annotation stored in the pcapng file", -1, 0)
	}
	return l
}

func layerName(l gopacket.Layer) string {
	switch l.(type) {
	case *layers.Ethernet:
		return "Ethernet"
	case *layers.Dot1Q:
		return "802.1Q VLAN"
	case *layers.ARP:
		return "ARP"
	case *layers.IPv4:
		return "IPv4"
	case *layers.IPv6:
		return "IPv6"
	case *layers.TCP:
		return "TCP"
	case *layers.UDP:
		return "UDP"
	case *layers.ICMPv4:
		return "ICMP"
	case *layers.ICMPv6:
		return "ICMPv6"
	case *layers.DNS:
		return "DNS"
	case *gopacket.Payload:
		return "Data"
	case *gopacket.DecodeFailure:
		return "Malformed"
	}
	return l.LayerType().String()
}

func describe(l *Layer, layer gopacket.Layer) {
	l.Name = layerName(layer)
	b := builder{l}
	switch v := layer.(type) {
	case *layers.Ethernet:
		describeEthernet(b, v)
	case *layers.Dot1Q:
		l.Summary = fmt.Sprintf("VLAN %d, priority %d", v.VLANIdentifier, v.Priority)
		b.add("Priority (PCP)", strconv.Itoa(int(v.Priority)), "802.1p class of service, 0 (best effort) to 7", 0, 1)
		b.add("Drop eligible", yesNo(v.DropEligible), "may be dropped first under congestion", 0, 1)
		b.add("VLAN ID", strconv.Itoa(int(v.VLANIdentifier)), "virtual LAN the frame belongs to", 0, 2)
		b.add("EtherType", etherType(v.Type), "protocol carried inside the tag", 2, 2)
	case *layers.ARP:
		describeARP(b, v)
	case *layers.IPv4:
		describeIPv4(b, v)
	case *layers.IPv6:
		describeIPv6(b, v)
	case *layers.TCP:
		describeTCP(b, v)
	case *layers.UDP:
		l.Summary = fmt.Sprintf("%d → %d, %s", v.SrcPort, v.DstPort, plural(len(v.Payload), "byte"))
		b.add("Source port", portText("udp", uint16(v.SrcPort)), portNote("udp", uint16(v.SrcPort), "sender"), 0, 2)
		b.add("Destination port", portText("udp", uint16(v.DstPort)), portNote("udp", uint16(v.DstPort), "receiver"), 2, 2)
		b.add("Length", plural(int(v.Length), "byte"), "UDP header (8 bytes) + data", 4, 2)
		csNote := "covers header, data and an IP pseudo-header"
		if v.Checksum == 0 {
			csNote = "0 means the sender skipped the checksum (allowed on IPv4 only)"
		}
		b.add("Checksum", fmt.Sprintf("0x%04x", v.Checksum), csNote, 6, 2)
	case *layers.ICMPv4:
		describeICMPv4(b, v)
	case *layers.ICMPv6:
		describeICMPv6(b, v)
	case *layers.ICMPv6Echo:
		l.Name = "ICMPv6 Echo"
		l.Summary = fmt.Sprintf("id %d, seq %d", v.Identifier, v.SeqNumber)
		b.add("Identifier", strconv.Itoa(int(v.Identifier)), "matches a reply to its request", 0, 2)
		b.add("Sequence", strconv.Itoa(int(v.SeqNumber)), "counts pings within one session", 2, 2)
	case *layers.ICMPv6NeighborSolicitation:
		l.Name = "Neighbor Solicitation"
		l.Summary = "who has " + v.TargetAddress.String() + "?"
		b.add("Target address", v.TargetAddress.String(), "the IPv6 address whose MAC is wanted (IPv6's ARP request)", 4, 16)
		describeNDPOptions(b, v.Options, 20)
	case *layers.ICMPv6NeighborAdvertisement:
		l.Name = "Neighbor Advertisement"
		l.Summary = v.TargetAddress.String() + " is here"
		b.add("Flags", ndpFlags(v.Flags), "R = sender is a router, S = reply to a solicitation, O = override cached entry", 0, 1)
		b.add("Target address", v.TargetAddress.String(), "the IPv6 address being announced (IPv6's ARP reply)", 4, 16)
		describeNDPOptions(b, v.Options, 20)
	case *layers.DNS:
		describeDNS(b, v)
	case *gopacket.Payload:
		data := []byte(*v)
		l.Summary = plural(len(data), "byte")
		b.add("Data", printable(data, 48), "application bytes; nyxr does not dissect this protocol", 0, len(data))
		if len(data) > 0 {
			b.add("Hex", hexPreview(data, 24), "", 0, len(data))
		}
	case *gopacket.DecodeFailure:
		l.Summary = "could not be decoded"
		b.add("Error", v.Error().Error(), "the header is truncated or invalid; remaining bytes are shown raw", 0, l.Length)
	default:
		describeGeneric(b, layer)
	}
	if l.Summary == "" && l.Length > 0 {
		l.Summary = plural(l.Length, "byte")
	}
}

func describeEthernet(b builder, v *layers.Ethernet) {
	b.l.Summary = fmt.Sprintf("%s → %s", v.SrcMAC, v.DstMAC)
	b.add("Destination", v.DstMAC.String(), macNote(v.DstMAC, "receiver"), 0, 6)
	b.add("Source", v.SrcMAC.String(), macNote(v.SrcMAC, "sender"), 6, 6)
	if v.EthernetType == layers.EthernetTypeLLC {
		b.add("Length", strconv.Itoa(int(v.Length)), "802.3 frame: this field is a length, not a type", 12, 2)
		return
	}
	b.add("EtherType", etherType(v.EthernetType), "which protocol the frame carries", 12, 2)
}

func macNote(mac net.HardwareAddr, role string) string {
	switch {
	case len(mac) == 6 && mac.String() == "ff:ff:ff:ff:ff:ff":
		return "broadcast: every host on the LAN segment receives it"
	case len(mac) > 0 && mac[0]&1 != 0:
		return "multicast group address"
	case len(mac) > 0 && mac[0]&2 != 0:
		return role + "'s NIC (locally administered, often random or virtual)"
	}
	return role + "'s network card on this hop (the router's MAC for remote hosts)"
}

func etherType(t layers.EthernetType) string {
	name := map[layers.EthernetType]string{
		layers.EthernetTypeIPv4: "IPv4", layers.EthernetTypeIPv6: "IPv6", layers.EthernetTypeARP: "ARP",
		layers.EthernetTypeDot1Q: "802.1Q VLAN", layers.EthernetTypeQinQ: "802.1ad QinQ", layers.EthernetTypeLinkLayerDiscovery: "LLDP",
	}[t]
	if name == "" {
		name = t.String()
	}
	return fmt.Sprintf("0x%04x (%s)", uint16(t), name)
}

func describeARP(b builder, v *layers.ARP) {
	spa, tpa := ipString(v.SourceProtAddress), ipString(v.DstProtAddress)
	sha := net.HardwareAddr(v.SourceHwAddress).String()
	op, note := strconv.Itoa(int(v.Operation)), ""
	switch v.Operation {
	case layers.ARPRequest:
		op, note = "1 (request)", "asks the LAN: who has "+tpa+"?"
		b.l.Summary = "who has " + tpa + "? tell " + spa
	case layers.ARPReply:
		op, note = "2 (reply)", tpa+" learns that "+spa+" is at "+sha
		b.l.Summary = spa + " is at " + sha
	}
	b.add("Hardware type", strconv.Itoa(int(v.AddrType)), "1 = Ethernet", 0, 2)
	b.add("Protocol type", fmt.Sprintf("0x%04x", uint16(v.Protocol)), "0x0800 = resolving IPv4 addresses", 2, 2)
	b.add("Address sizes", fmt.Sprintf("%d / %d", v.HwAddressSize, v.ProtAddressSize), "MAC and IP address lengths in bytes", 4, 2)
	b.add("Operation", op, note, 6, 2)
	b.add("Sender MAC", sha, "", 8, 6)
	b.add("Sender IP", spa, "", 14, 4)
	b.add("Target MAC", net.HardwareAddr(v.DstHwAddress).String(), "all zeros in a request: unknown, that is the question", 18, 6)
	b.add("Target IP", tpa, "", 24, 4)
}

func ipString(b []byte) string {
	if a, ok := netip.AddrFromSlice(b); ok {
		return a.String()
	}
	return fmt.Sprintf("%x", b)
}

func describeIPv4(b builder, v *layers.IPv4) {
	b.l.Summary = fmt.Sprintf("%s → %s, TTL %d", v.SrcIP, v.DstIP, v.TTL)
	b.add("Version", strconv.Itoa(int(v.Version)), "", 0, 1)
	hl := int(v.IHL) * 4
	hlNote := "IHL × 4; the minimum is 20"
	if hl > 20 {
		hlNote = "IHL × 4; more than 20 means IP options follow"
	}
	b.add("Header length", plural(hl, "byte"), hlNote, 0, 1)
	b.add("DSCP / ECN", fmt.Sprintf("%d / %d", v.TOS>>2, v.TOS&3), "QoS class for routers / congestion signal bits", 1, 1)
	b.add("Total length", plural(int(v.Length), "byte"), "IP header + everything after it", 2, 2)
	b.add("Identification", fmt.Sprintf("0x%04x (%d)", v.Id, v.Id), "ties the fragments of one datagram together", 4, 2)
	var flags []string
	if v.Flags&layers.IPv4DontFragment != 0 {
		flags = append(flags, "DF")
	}
	if v.Flags&layers.IPv4MoreFragments != 0 {
		flags = append(flags, "MF")
	}
	if v.Flags&layers.IPv4EvilBit != 0 {
		flags = append(flags, "reserved")
	}
	b.add("Flags", orNone(strings.Join(flags, ", ")), "DF = don't fragment, MF = more fragments follow", 6, 1)
	fragNote := "not a fragment"
	if v.FragOffset != 0 || v.Flags&layers.IPv4MoreFragments != 0 {
		fragNote = "this packet is a fragment; offset counts 8-byte units"
	}
	b.add("Fragment offset", strconv.Itoa(int(v.FragOffset)), fragNote, 6, 2)
	b.add("TTL", strconv.Itoa(int(v.TTL)), ttlNote(v.TTL), 8, 1)
	b.add("Protocol", fmt.Sprintf("%d (%s)", v.Protocol, ipProto(v.Protocol)), "the transport header that follows", 9, 1)
	b.add("Header checksum", fmt.Sprintf("0x%04x", v.Checksum), "covers the IP header only; often 0 on sent packets (NIC offload)", 10, 2)
	b.add("Source", v.SrcIP.String(), addrNote(v.SrcIP), 12, 4)
	b.add("Destination", v.DstIP.String(), addrNote(v.DstIP), 16, 4)
	off := 20
	for _, o := range v.Options {
		n := int(o.OptionLength)
		if n == 0 {
			n = 1
		}
		b.sub("Option", fmt.Sprintf("type %d, %d bytes", o.OptionType, n), "", off, n)
		off += n
	}
}

func ttlNote(ttl uint8) string {
	base := "hops left before a router discards the packet"
	switch {
	case ttl <= 64:
		return fmt.Sprintf("%s; likely Linux/macOS/BSD (starts at 64), ~%d hops away", base, 64-int(ttl))
	case ttl <= 128:
		return fmt.Sprintf("%s; likely Windows (starts at 128), ~%d hops away", base, 128-int(ttl))
	default:
		return fmt.Sprintf("%s; likely network gear (starts at 255), ~%d hops away", base, 255-int(ttl))
	}
}

func addrNote(ip net.IP) string {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ""
	}
	a = a.Unmap()
	switch {
	case a.IsLoopback():
		return "loopback (this host)"
	case a.IsLinkLocalUnicast():
		return "link-local: valid only on this LAN segment"
	case a.IsMulticast():
		return "multicast group"
	case a.IsPrivate():
		return "private address (RFC 1918 / ULA)"
	case a.Is4() && a.As4()[0] == 255:
		return "broadcast"
	}
	return ""
}

func ipProto(p layers.IPProtocol) string {
	switch p {
	case layers.IPProtocolTCP:
		return "TCP"
	case layers.IPProtocolUDP:
		return "UDP"
	case layers.IPProtocolICMPv4:
		return "ICMP"
	case layers.IPProtocolICMPv6:
		return "ICMPv6"
	case layers.IPProtocolSCTP:
		return "SCTP"
	case layers.IPProtocolIPv6Fragment:
		return "IPv6 fragment"
	case layers.IPProtocolIPv6HopByHop:
		return "hop-by-hop options"
	}
	return p.String()
}

func describeIPv6(b builder, v *layers.IPv6) {
	b.l.Summary = fmt.Sprintf("%s → %s, hop limit %d", v.SrcIP, v.DstIP, v.HopLimit)
	b.add("Version", strconv.Itoa(int(v.Version)), "", 0, 1)
	b.add("Traffic class", strconv.Itoa(int(v.TrafficClass)), "QoS class (DSCP + ECN), like IPv4's TOS", 0, 2)
	b.add("Flow label", fmt.Sprintf("0x%05x", v.FlowLabel), "lets routers keep packets of one flow on one path", 1, 3)
	b.add("Payload length", plural(int(v.Length), "byte"), "everything after the fixed 40-byte header", 4, 2)
	b.add("Next header", fmt.Sprintf("%d (%s)", v.NextHeader, ipProto(v.NextHeader)), "the header that follows: transport or extension", 6, 1)
	b.add("Hop limit", strconv.Itoa(int(v.HopLimit)), ttlNote(v.HopLimit), 7, 1)
	b.add("Source", v.SrcIP.String(), addrNote(v.SrcIP), 8, 16)
	b.add("Destination", v.DstIP.String(), addrNote(v.DstIP), 24, 16)
}

// tcpFlags lists the set flags, SYN and ACK first.
func tcpFlags(v *layers.TCP) []string {
	var f []string
	for _, x := range []struct {
		on   bool
		name string
	}{{v.SYN, "SYN"}, {v.ACK, "ACK"}, {v.FIN, "FIN"}, {v.RST, "RST"}, {v.PSH, "PSH"}, {v.URG, "URG"}, {v.ECE, "ECE"}, {v.CWR, "CWR"}, {v.NS, "NS"}} {
		if x.on {
			f = append(f, x.name)
		}
	}
	return f
}

var flagMeaning = map[string]string{
	"SYN": "synchronize: opens a connection and picks the starting sequence number",
	"ACK": "the acknowledgment number is valid",
	"FIN": "the sender has no more data; closes its half of the connection",
	"RST": "reset: abort the connection, or refuse it when nothing listens",
	"PSH": "push: hand the data to the application right away",
	"URG": "the urgent pointer is valid",
	"ECE": "ECN echo: the path signalled congestion",
	"CWR": "congestion window reduced in response to ECE",
	"NS":  "ECN nonce (experimental)",
}

func tcpMeaning(v *layers.TCP) (string, Tone) {
	switch {
	case v.SYN && v.ACK:
		return "connection accepted: something listens on the source port (open)", ToneOpen
	case v.SYN:
		return "connection request: a client or scanner asks to open the destination port", ToneProbe
	case v.RST:
		return "reset: the port refused the connection (closed) or a connection was aborted", ToneClosed
	case v.FIN:
		return "closing: the sender finished sending", ToneNone
	case len(v.Payload) > 0:
		return "data segment of an established connection", ToneNone
	}
	return "acknowledgment only, no data", ToneNone
}

func describeTCP(b builder, v *layers.TCP) {
	flags := tcpFlags(v)
	b.l.Summary = fmt.Sprintf("%d → %d [%s], %s", v.SrcPort, v.DstPort, strings.Join(flags, ","), plural(len(v.Payload), "byte"))
	b.add("Source port", portText("tcp", uint16(v.SrcPort)), portNote("tcp", uint16(v.SrcPort), "sender"), 0, 2)
	b.add("Destination port", portText("tcp", uint16(v.DstPort)), portNote("tcp", uint16(v.DstPort), "receiver"), 2, 2)
	b.add("Sequence number", strconv.FormatUint(uint64(v.Seq), 10), "number of this segment's first byte; a SYN picks a random start", 4, 4)
	ackNote := "next byte expected from the peer"
	if !v.ACK {
		ackNote = "ignored: the ACK flag is not set"
	}
	b.add("Acknowledgment", strconv.FormatUint(uint64(v.Ack), 10), ackNote, 8, 4)
	hl := int(v.DataOffset) * 4
	hlNote := "data offset × 4; 20 = no options"
	if hl > 20 {
		hlNote = "data offset × 4; more than 20 means TCP options follow"
	}
	b.add("Header length", plural(hl, "byte"), hlNote, 12, 1)
	meaning, _ := tcpMeaning(v)
	b.add("Flags", orNone(strings.Join(flags, ", ")), meaning, 12, 2)
	for _, f := range flags {
		b.sub(f, "set", flagMeaning[f], 13, 1)
	}
	b.add("Window", strconv.Itoa(int(v.Window)), "receive buffer space the sender offers (scaled when window scaling is on)", 14, 2)
	b.add("Checksum", fmt.Sprintf("0x%04x", v.Checksum), "covers header, data and an IP pseudo-header", 16, 2)
	if v.URG {
		b.add("Urgent pointer", strconv.Itoa(int(v.Urgent)), "end of urgent data", 18, 2)
	}
	off := 20
	for _, o := range v.Options {
		n := int(o.OptionLength)
		if o.OptionType == layers.TCPOptionKindNop || o.OptionType == layers.TCPOptionKindEndList {
			n = 1
		}
		name, value, note := tcpOption(o)
		b.sub(name, value, note, off, n)
		off += n
	}
}

func tcpOption(o layers.TCPOption) (name, value, note string) {
	d := o.OptionData
	switch o.OptionType {
	case layers.TCPOptionKindMSS:
		if len(d) == 2 {
			return "MSS", strconv.Itoa(int(d[0])<<8 | int(d[1])), "largest segment the sender accepts; 1460 = Ethernet MTU 1500 minus headers"
		}
	case layers.TCPOptionKindWindowScale:
		if len(d) == 1 {
			return "Window scale", fmt.Sprintf("%d (×%d)", d[0], 1<<min(d[0], 14)), "multiplier for the window field"
		}
	case layers.TCPOptionKindSACKPermitted:
		return "SACK permitted", "yes", "the sender can acknowledge non-contiguous blocks"
	case layers.TCPOptionKindSACK:
		return "SACK", plural(len(d)/8, "block"), "byte ranges received out of order"
	case layers.TCPOptionKindTimestamps:
		if len(d) == 8 {
			val := uint32(d[0])<<24 | uint32(d[1])<<16 | uint32(d[2])<<8 | uint32(d[3])
			echo := uint32(d[4])<<24 | uint32(d[5])<<16 | uint32(d[6])<<8 | uint32(d[7])
			return "Timestamps", fmt.Sprintf("val %d, echo %d", val, echo), "round-trip measurement and wrapped-sequence protection"
		}
	case layers.TCPOptionKindNop:
		return "NOP", "", "padding to align the next option"
	case layers.TCPOptionKindEndList:
		return "End of options", "", ""
	}
	return "Option " + strconv.Itoa(int(o.OptionType)), hexPreview(d, 16), ""
}

func portText(proto string, port uint16) string {
	if name := ServiceName(proto, port); name != "" {
		return fmt.Sprintf("%d (%s)", port, name)
	}
	return strconv.Itoa(int(port))
}

func portNote(proto string, port uint16, role string) string {
	switch {
	case ServiceName(proto, port) != "":
		return role + "'s port; well-known for " + ServiceName(proto, port) + " (by number only)"
	case port >= 49152:
		return role + "'s port; ephemeral: picked by the client's OS for this connection"
	case port >= 1024:
		return role + "'s port; registered/user range"
	}
	return role + "'s port; system range (0-1023)"
}

type icmpInfo struct{ name, note string }

var icmp4Types = map[uint8]icmpInfo{
	0:  {"echo reply", "answer to a ping: the host is up"},
	3:  {"destination unreachable", "a router or the host could not deliver the packet"},
	4:  {"source quench", "deprecated congestion signal"},
	5:  {"redirect", "a router suggests a better gateway"},
	8:  {"echo request", "ping: asks the host to answer"},
	9:  {"router advertisement", ""},
	10: {"router solicitation", ""},
	11: {"time exceeded", "the TTL reached zero in transit (how traceroute finds hops)"},
	12: {"parameter problem", "a header field was invalid"},
	13: {"timestamp request", ""},
	14: {"timestamp reply", "the host is up"},
}

var icmp4Unreach = map[uint8]icmpInfo{
	0:  {"network unreachable", "no route to the destination network"},
	1:  {"host unreachable", "the last router could not reach the host (often: host down)"},
	2:  {"protocol unreachable", "the host does not support this IP protocol"},
	3:  {"port unreachable", "nothing listens on that UDP port: closed"},
	4:  {"fragmentation needed", "too big and DF set; used for path MTU discovery"},
	9:  {"network prohibited", "administratively filtered"},
	10: {"host prohibited", "administratively filtered"},
	13: {"administratively prohibited", "a firewall rejected the packet: filtered"},
}

func icmp4Name(t, c uint8) icmpInfo {
	if t == 3 {
		if i, ok := icmp4Unreach[c]; ok {
			return i
		}
		return icmpInfo{fmt.Sprintf("unreachable (code %d)", c), "the packet could not be delivered"}
	}
	if t == 11 && c == 1 {
		return icmpInfo{"reassembly time exceeded", "fragments did not all arrive in time"}
	}
	if i, ok := icmp4Types[t]; ok {
		return i
	}
	return icmpInfo{fmt.Sprintf("type %d code %d", t, c), ""}
}

func describeICMPv4(b builder, v *layers.ICMPv4) {
	t, c := v.TypeCode.Type(), v.TypeCode.Code()
	info := icmp4Name(t, c)
	b.l.Summary = info.name
	b.add("Type", fmt.Sprintf("%d (%s)", t, icmp4Types[t].name), icmp4Types[t].note, 0, 1)
	b.add("Code", fmt.Sprintf("%d", c), codeNote(t == 3, info), 1, 1)
	b.add("Checksum", fmt.Sprintf("0x%04x", v.Checksum), "covers the ICMP message", 2, 2)
	switch t {
	case 0, 8, 13, 14:
		b.add("Identifier", strconv.Itoa(int(v.Id)), "matches a reply to its request", 4, 2)
		b.add("Sequence", strconv.Itoa(int(v.Seq)), "counts pings within one session", 6, 2)
		b.l.Summary += fmt.Sprintf(", id %d, seq %d", v.Id, v.Seq)
	case 3, 11, 12:
		if q := quoted(v.Payload); q != "" {
			b.add("Quoted packet", q, "header of the packet that caused this error", 8, len(v.Payload))
			b.l.Summary += ": " + q
		}
	}
}

func codeNote(unreach bool, info icmpInfo) string {
	if unreach {
		return info.name + ": " + info.note
	}
	return ""
}

var icmp6Types = map[uint8]icmpInfo{
	1:   {"destination unreachable", "the packet could not be delivered"},
	2:   {"packet too big", "used for path MTU discovery"},
	3:   {"time exceeded", "the hop limit reached zero in transit"},
	4:   {"parameter problem", "a header field was invalid"},
	128: {"echo request", "ping: asks the host to answer"},
	129: {"echo reply", "answer to a ping: the host is up"},
	130: {"multicast listener query", ""},
	131: {"multicast listener report", ""},
	133: {"router solicitation", "asks local routers to announce themselves"},
	134: {"router advertisement", "a router announces prefixes and itself as gateway"},
	135: {"neighbor solicitation", "who has this IPv6 address? (IPv6's ARP request)"},
	136: {"neighbor advertisement", "this IPv6 address is at my MAC (IPv6's ARP reply)"},
	137: {"redirect", "a router suggests a better next hop"},
	143: {"MLDv2 report", "the host joins or leaves multicast groups"},
}

var icmp6Unreach = map[uint8]icmpInfo{
	0: {"no route", "no route to the destination"},
	1: {"administratively prohibited", "a firewall rejected the packet: filtered"},
	3: {"address unreachable", "the host could not be reached (often: host down)"},
	4: {"port unreachable", "nothing listens on that UDP port: closed"},
}

func icmp6Name(t, c uint8) icmpInfo {
	if t == 1 {
		if i, ok := icmp6Unreach[c]; ok {
			return i
		}
	}
	if i, ok := icmp6Types[t]; ok {
		return i
	}
	return icmpInfo{fmt.Sprintf("type %d code %d", t, c), ""}
}

func describeICMPv6(b builder, v *layers.ICMPv6) {
	t, c := v.TypeCode.Type(), v.TypeCode.Code()
	info := icmp6Name(t, c)
	b.l.Summary = info.name
	b.add("Type", fmt.Sprintf("%d (%s)", t, icmp6Types[t].name), icmp6Types[t].note, 0, 1)
	b.add("Code", strconv.Itoa(int(c)), codeNote(t == 1, info), 1, 1)
	b.add("Checksum", fmt.Sprintf("0x%04x", v.Checksum), "covers the message and an IPv6 pseudo-header", 2, 2)
	if t >= 1 && t <= 4 && len(v.Payload) > 4 {
		if q := quoted(v.Payload[4:]); q != "" {
			b.add("Quoted packet", q, "header of the packet that caused this error", 8, len(v.Payload)-4)
			b.l.Summary += ": " + q
		}
	}
}

func ndpFlags(f uint8) string {
	var s []string
	if f&0x80 != 0 {
		s = append(s, "R")
	}
	if f&0x40 != 0 {
		s = append(s, "S")
	}
	if f&0x20 != 0 {
		s = append(s, "O")
	}
	return orNone(strings.Join(s, ", "))
}

func describeNDPOptions(b builder, opts layers.ICMPv6Options, off int) {
	for _, o := range opts {
		n := len(o.Data) + 2
		switch o.Type {
		case layers.ICMPv6OptSourceAddress:
			b.sub("Source link-layer", net.HardwareAddr(o.Data).String(), "the sender's MAC", off, n)
		case layers.ICMPv6OptTargetAddress:
			b.sub("Target link-layer", net.HardwareAddr(o.Data).String(), "the MAC that owns the target address", off, n)
		default:
			b.sub("Option "+strconv.Itoa(int(o.Type)), hexPreview(o.Data, 16), "", off, n)
		}
		off += n
	}
}

// quoted summarizes the IP + transport header embedded in an ICMP error.
func quoted(raw []byte) string {
	var src, dst netip.Addr
	var proto byte
	var rest []byte
	switch {
	case len(raw) >= 20 && raw[0]>>4 == 4:
		hl := int(raw[0]&15) * 4
		if hl < 20 || len(raw) < hl {
			return ""
		}
		src, dst = netip.AddrFrom4([4]byte(raw[12:16])), netip.AddrFrom4([4]byte(raw[16:20]))
		proto, rest = raw[9], raw[hl:]
	case len(raw) >= 40 && raw[0]>>4 == 6:
		src, dst = netip.AddrFrom16([16]byte(raw[8:24])), netip.AddrFrom16([16]byte(raw[24:40]))
		proto, rest = raw[6], raw[40:]
	default:
		return ""
	}
	name := strings.ToLower(ipProto(layers.IPProtocol(proto)))
	if (proto == 6 || proto == 17) && len(rest) >= 4 {
		sp, dp := uint16(rest[0])<<8|uint16(rest[1]), uint16(rest[2])<<8|uint16(rest[3])
		return fmt.Sprintf("%s %s → %s", name, netip.AddrPortFrom(src, sp), netip.AddrPortFrom(dst, dp))
	}
	return fmt.Sprintf("%s %s → %s", name, src, dst)
}

var dnsRcodes = map[layers.DNSResponseCode]icmpInfo{
	0: {"no error", ""}, 1: {"format error", "the server could not parse the query"},
	2: {"server failure", "the server could not answer"}, 3: {"NXDOMAIN", "the name does not exist"},
	4: {"not implemented", ""}, 5: {"refused", "the server declined to answer"},
}

func describeDNS(b builder, v *layers.DNS) {
	kind := "query"
	if v.QR {
		kind = "response"
	}
	var q string
	if len(v.Questions) > 0 {
		q = v.Questions[0].Type.String() + " " + string(v.Questions[0].Name)
	}
	b.l.Summary = strings.TrimSpace(kind + " " + q)
	b.add("Transaction ID", fmt.Sprintf("0x%04x", v.ID), "pairs a response with its query", 0, 2)
	b.add("Type", kind, "QR bit: 0 = query, 1 = response", 2, 1)
	b.add("Opcode", v.OpCode.String(), "0 = standard query", 2, 1)
	var flags []string
	for _, f := range []struct {
		on   bool
		name string
	}{{v.AA, "AA"}, {v.TC, "TC"}, {v.RD, "RD"}, {v.RA, "RA"}} {
		if f.on {
			flags = append(flags, f.name)
		}
	}
	b.add("Flags", orNone(strings.Join(flags, ", ")), "AA authoritative, TC truncated (retry over TCP), RD recursion desired, RA recursion available", 2, 2)
	if v.QR {
		rc := dnsRcodes[v.ResponseCode]
		if rc.name == "" {
			rc.name = v.ResponseCode.String()
		}
		b.add("Response code", rc.name, rc.note, 3, 1)
	}
	b.add("Counts", fmt.Sprintf("%d questions, %d answers, %d authority, %d additional", v.QDCount, v.ANCount, v.NSCount, v.ARCount), "", 4, 8)
	for _, qn := range v.Questions {
		b.sub("Question", fmt.Sprintf("%s %s %s", qn.Name, qn.Type, qn.Class), "name, record type and class asked for", -1, 0)
	}
	for _, sec := range []struct {
		name string
		rrs  []layers.DNSResourceRecord
	}{{"Answer", v.Answers}, {"Authority", v.Authorities}, {"Additional", v.Additionals}} {
		for _, rr := range sec.rrs {
			b.sub(sec.name, fmt.Sprintf("%s %s %s (TTL %ds)", rr.Name, rr.Type, rrData(rr), rr.TTL), "TTL = seconds a resolver may cache it", -1, 0)
		}
	}
}

func rrData(rr layers.DNSResourceRecord) string {
	switch rr.Type {
	case layers.DNSTypeA, layers.DNSTypeAAAA:
		return rr.IP.String()
	case layers.DNSTypeCNAME:
		return string(rr.CNAME)
	case layers.DNSTypeNS:
		return string(rr.NS)
	case layers.DNSTypePTR:
		return string(rr.PTR)
	case layers.DNSTypeMX:
		return fmt.Sprintf("%d %s", rr.MX.Preference, rr.MX.Name)
	case layers.DNSTypeTXT:
		var parts []string
		for _, t := range rr.TXTs {
			parts = append(parts, strconv.Quote(string(t)))
		}
		return strings.Join(parts, " ")
	case layers.DNSTypeSRV:
		return fmt.Sprintf("%d %d %d %s", rr.SRV.Priority, rr.SRV.Weight, rr.SRV.Port, rr.SRV.Name)
	}
	return plural(len(rr.Data), "byte")
}

// describeGeneric lists the exported fields of a layer nyxr has no dedicated
// description for, so nothing gopacket decoded is hidden.
func describeGeneric(b builder, layer gopacket.Layer) {
	v := reflect.Indirect(reflect.ValueOf(layer))
	if v.Kind() != reflect.Struct {
		return
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() || f.Anonymous || f.Name == "Contents" || f.Name == "Payload" {
			continue
		}
		value := fmt.Sprintf("%v", v.Field(i).Interface())
		if len(value) > 96 {
			value = value[:96] + "…"
		}
		b.add(f.Name, value, "", -1, 0)
	}
}

func summarize(p gopacket.Packet, rec capture.Record, number int, first time.Time) Summary {
	s := Summary{Number: number, Direction: rec.Direction, Length: rec.Length}
	if s.Length == 0 {
		s.Length = len(rec.Data)
	}
	if !first.IsZero() && !rec.Timestamp.IsZero() {
		s.Elapsed = rec.Timestamp.Sub(first)
	}
	if eth, ok := p.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
		s.Source, s.Destination, s.Protocol = eth.SrcMAC.String(), eth.DstMAC.String(), "Ethernet"
		s.Info = "EtherType " + etherType(eth.EthernetType)
	}
	if ip, ok := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok && ip.SrcIP != nil {
		s.Source, s.Destination, s.Protocol = ip.SrcIP.String(), ip.DstIP.String(), "IPv4"
		s.Info = "protocol " + ipProto(ip.Protocol)
		if ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0 {
			s.Info = fmt.Sprintf("fragment offset %d", int(ip.FragOffset)*8)
		}
	} else if ip, ok := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok && ip.SrcIP != nil {
		s.Source, s.Destination, s.Protocol = ip.SrcIP.String(), ip.DstIP.String(), "IPv6"
		s.Info = "next header " + ipProto(ip.NextHeader)
	}
	all := p.Layers()
	for i, l := range all {
		switch v := l.(type) {
		case *layers.ARP:
			s.Protocol = "ARP"
			b := builder{&Layer{Length: 28}}
			describeARP(b, v)
			s.Info = b.l.Summary
		case *layers.TCP:
			s.Protocol = "TCP"
			flags := strings.Join(tcpFlags(v), ",")
			s.Info = fmt.Sprintf("%d → %d [%s] Seq=%d", v.SrcPort, v.DstPort, flags, v.Seq)
			if v.ACK {
				s.Info += fmt.Sprintf(" Ack=%d", v.Ack)
			}
			s.Info += fmt.Sprintf(" Win=%d Len=%d", v.Window, len(v.Payload))
			_, s.Tone = tcpMeaning(v)
		case *layers.UDP:
			s.Protocol = "UDP"
			s.Info = fmt.Sprintf("%d → %d Len=%d", v.SrcPort, v.DstPort, len(v.Payload))
		case *layers.ICMPv4:
			s.Protocol = "ICMP"
			t, c := v.TypeCode.Type(), v.TypeCode.Code()
			s.Info = icmp4Name(t, c).name
			switch t {
			case 0, 8:
				s.Info += fmt.Sprintf(" id=%d seq=%d", v.Id, v.Seq)
			case 3, 11, 12:
				if q := quoted(v.Payload); q != "" {
					s.Info += " (" + q + ")"
				}
			}
			s.Tone = icmpTone(t == 0 || t == 14, t == 8, t == 3 && c == 3, t == 3 || t == 11)
		case *layers.ICMPv6:
			s.Protocol = "ICMPv6"
			t, c := v.TypeCode.Type(), v.TypeCode.Code()
			s.Info = icmp6Name(t, c).name
			if t >= 1 && t <= 4 && len(v.Payload) > 4 {
				if q := quoted(v.Payload[4:]); q != "" {
					s.Info += " (" + q + ")"
				}
			}
			s.Tone = icmpTone(t == 129, t == 128, t == 1 && c == 4, t == 1 || t == 3)
		case *layers.ICMPv6NeighborSolicitation:
			s.Info += " for " + v.TargetAddress.String()
		case *layers.ICMPv6NeighborAdvertisement:
			s.Info += " " + v.TargetAddress.String()
		case *layers.ICMPv6Echo:
			s.Info += fmt.Sprintf(" id=%d seq=%d", v.Identifier, v.SeqNumber)
		case *layers.DNS:
			s.Protocol = "DNS"
			s.Info = dnsInfo(v)
			if v.QR {
				s.Tone = ToneOpen
			}
		case *gopacket.DecodeFailure:
			if i > 0 && isTransport(all[i-1]) {
				s.Info += " (not valid " + guessedApp(v) + ")"
				continue
			}
			s.Info = "malformed: " + v.Error().Error()
			s.Tone = ToneError
		}
	}
	if s.Protocol == "" {
		s.Protocol = "?"
	}
	return s
}

func icmpTone(reply, request, closed, filtered bool) Tone {
	switch {
	case reply:
		return ToneOpen
	case request:
		return ToneProbe
	case closed:
		return ToneClosed
	case filtered:
		return ToneFilter
	}
	return ToneNone
}

func dnsInfo(v *layers.DNS) string {
	var b strings.Builder
	if v.QR {
		b.WriteString("response")
	} else {
		b.WriteString("query")
	}
	for _, q := range v.Questions {
		fmt.Fprintf(&b, " %s %s", q.Type, q.Name)
	}
	if v.QR && v.ResponseCode != 0 {
		b.WriteString(" " + dnsRcodes[v.ResponseCode].name)
	}
	for i, a := range v.Answers {
		if i == 3 {
			fmt.Fprintf(&b, " …+%d", len(v.Answers)-3)
			break
		}
		fmt.Fprintf(&b, " %s %s", a.Type, rrData(a))
	}
	return b.String()
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func printable(data []byte, max int) string {
	var b strings.Builder
	for i, c := range data {
		if i == max {
			b.WriteString("…")
			break
		}
		if c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		} else {
			b.WriteByte('.')
		}
	}
	return b.String()
}

func hexPreview(data []byte, max int) string {
	var b strings.Builder
	for i, c := range data {
		if i == max {
			b.WriteString(" …")
			break
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%02x", c)
	}
	return b.String()
}
