package dissect

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/matusso/nyxr/internal/capture"
)

var (
	macA = net.HardwareAddr{2, 0, 0, 0, 0, 1}
	macB = net.HardwareAddr{2, 0, 0, 0, 0, 2}
	ipA  = net.IP{192, 0, 2, 1}
	ipB  = net.IP{192, 0, 2, 10}
)

func frame(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func ipv4(proto layers.IPProtocol, src, dst net.IP) *layers.IPv4 {
	return &layers.IPv4{Version: 4, IHL: 5, TTL: 117, Protocol: proto, SrcIP: src, DstIP: dst, Flags: layers.IPv4DontFragment}
}

func field(t *testing.T, p Packet, layer, name string) Field {
	t.Helper()
	for _, l := range p.Layers {
		if l.Name != layer {
			continue
		}
		for _, f := range l.Fields {
			if f.Name == name {
				return f
			}
		}
	}
	t.Fatalf("no %s field %q in %+v", layer, name, p.Layers)
	return Field{}
}

func TestDissectTCPSynAck(t *testing.T) {
	ip := ipv4(layers.IPProtocolTCP, ipB, ipA)
	tcp := &layers.TCP{SrcPort: 22, DstPort: 51000, SYN: true, ACK: true, Seq: 100, Ack: 1, Window: 64240,
		Options: []layers.TCPOption{{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}}}
	tcp.SetNetworkLayerForChecksum(ip)
	data := frame(t, &layers.Ethernet{SrcMAC: macB, DstMAC: macA, EthernetType: layers.EthernetTypeIPv4}, ip, tcp)
	ts := time.Unix(100, 0)
	p := Dissect(capture.Record{Data: data, Timestamp: ts.Add(1500 * time.Millisecond), Direction: capture.DirectionRX, PacketID: 7}, 3, ts)

	if p.Protocol != "TCP" || p.Source != "192.0.2.10" || p.Tone != ToneOpen || p.Elapsed != 1500*time.Millisecond {
		t.Fatalf("summary %+v", p.Summary)
	}
	if !strings.Contains(p.Info, "22 → 51000 [SYN,ACK]") {
		t.Fatalf("info %q", p.Info)
	}
	names := []string{}
	for _, l := range p.Layers {
		names = append(names, l.Name)
	}
	if strings.Join(names, ",") != "Frame,Ethernet,IPv4,TCP,Trailer" {
		t.Fatalf("layers %v", names)
	}
	if f := field(t, p, "Frame", "Direction"); !strings.Contains(f.Value, "rx") {
		t.Fatalf("direction %+v", f)
	}
	if f := field(t, p, "Frame", "nyxr packet ID"); f.Value != "7" {
		t.Fatalf("packet id %+v", f)
	}
	ttl := field(t, p, "IPv4", "TTL")
	if ttl.Value != "117" || !strings.Contains(ttl.Note, "Windows") || ttl.Offset != 14+8 || ttl.Length != 1 {
		t.Fatalf("ttl %+v", ttl)
	}
	if f := field(t, p, "IPv4", "Flags"); f.Value != "DF" {
		t.Fatalf("ip flags %+v", f)
	}
	flags := field(t, p, "TCP", "Flags")
	if flags.Value != "SYN, ACK" || !strings.Contains(flags.Note, "open") {
		t.Fatalf("tcp flags %+v", flags)
	}
	if f := field(t, p, "TCP", "Source port"); f.Value != "22 (ssh)" || f.Offset != 34 || f.Length != 2 {
		t.Fatalf("source port %+v", f)
	}
	if f := field(t, p, "TCP", "MSS"); f.Value != "1460" || f.Indent != 1 || f.Offset != 54 {
		t.Fatalf("mss %+v", f)
	}
	for _, l := range p.Layers[1:] {
		for _, f := range l.Fields {
			if f.Length > 0 && f.Offset+f.Length > len(data) {
				t.Fatalf("%s.%s range %d+%d outside %d-byte frame", l.Name, f.Name, f.Offset, f.Length, len(data))
			}
		}
	}
}

func TestDissectICMPPortUnreachableQuotesUDP(t *testing.T) {
	quotedIP := ipv4(layers.IPProtocolUDP, ipA, ipB)
	udp := &layers.UDP{SrcPort: 50001, DstPort: 161}
	udp.SetNetworkLayerForChecksum(quotedIP)
	inner := frame(t, quotedIP, udp)
	data := frame(t, &layers.Ethernet{SrcMAC: macB, DstMAC: macA, EthernetType: layers.EthernetTypeIPv4},
		ipv4(layers.IPProtocolICMPv4, ipB, ipA),
		&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(3, 3)}, gopacket.Payload(inner))
	p := Dissect(capture.Record{Data: data}, 1, time.Time{})
	if p.Tone != ToneClosed || !strings.Contains(p.Info, "port unreachable (udp 192.0.2.1:50001 → 192.0.2.10:161)") {
		t.Fatalf("summary %+v", p.Summary)
	}
	if f := field(t, p, "ICMP", "Code"); !strings.Contains(f.Note, "closed") {
		t.Fatalf("code note %+v", f)
	}
	if f := field(t, p, "ICMP", "Quoted packet"); f.Length != len(inner) {
		t.Fatalf("quoted %+v, want %d bytes", f, len(inner))
	}
}

func TestDissectARPAndDNS(t *testing.T) {
	arp := frame(t, &layers.Ethernet{SrcMAC: macA, DstMAC: layers.EthernetBroadcast, EthernetType: layers.EthernetTypeARP},
		&layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
			Operation: layers.ARPRequest, SourceHwAddress: macA, SourceProtAddress: ipA, DstHwAddress: make([]byte, 6), DstProtAddress: ipB})
	p := Dissect(capture.Record{Data: arp}, 1, time.Time{})
	if p.Protocol != "ARP" || p.Info != "who has 192.0.2.10? tell 192.0.2.1" {
		t.Fatalf("arp %+v", p.Summary)
	}
	if f := field(t, p, "Ethernet", "Destination"); !strings.Contains(f.Note, "broadcast") {
		t.Fatalf("broadcast note %+v", f)
	}

	ip := ipv4(layers.IPProtocolUDP, ipB, ipA)
	udp := &layers.UDP{SrcPort: 53, DstPort: 40000}
	udp.SetNetworkLayerForChecksum(ip)
	dns := &layers.DNS{ID: 0x1234, QR: true, RD: true, RA: true,
		Questions: []layers.DNSQuestion{{Name: []byte("example.test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
		Answers: []layers.DNSResourceRecord{{Name: []byte("example.test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN,
			TTL: 300, IP: net.IP{192, 0, 2, 99}}}}
	p = Dissect(capture.Record{Data: frame(t, &layers.Ethernet{SrcMAC: macB, DstMAC: macA, EthernetType: layers.EthernetTypeIPv4}, ip, udp, dns)}, 1, time.Time{})
	if p.Protocol != "DNS" || p.Info != "response A example.test A 192.0.2.99" {
		t.Fatalf("dns %+v", p.Summary)
	}
	if f := field(t, p, "DNS", "Answer"); !strings.Contains(f.Value, "192.0.2.99 (TTL 300s)") {
		t.Fatalf("answer %+v", f)
	}
}

func TestDissectPortGuessThatIsNotTheProtocol(t *testing.T) {
	ip := ipv4(layers.IPProtocolUDP, ipB, ipA)
	udp := &layers.UDP{SrcPort: 53, DstPort: 40000}
	udp.SetNetworkLayerForChecksum(ip)
	data := frame(t, &layers.Ethernet{SrcMAC: macB, DstMAC: macA, EthernetType: layers.EthernetTypeIPv4}, ip, udp, gopacket.Payload{1, 2, 3})
	p := Dissect(capture.Record{Data: data}, 1, time.Time{})
	if p.Tone == ToneError || !strings.Contains(p.Info, "not valid DNS") {
		t.Fatalf("summary %+v", p.Summary)
	}
	if d := p.Layers[len(p.Layers)-2]; d.Name != "Data" || d.Length != 3 {
		t.Fatalf("payload layer %+v", d)
	}
	if f := field(t, p, "Frame", "Protocols"); f.Value != "Ethernet › IPv4 › UDP › Data" {
		t.Fatalf("protocols %q", f.Value)
	}
}

func TestDissectTruncatedFrame(t *testing.T) {
	p := Dissect(capture.Record{Data: []byte{1, 2, 3}}, 1, time.Time{})
	if p.Tone != ToneError || !strings.HasPrefix(p.Info, "malformed") {
		t.Fatalf("summary %+v", p.Summary)
	}
	if p.Layers[len(p.Layers)-1].Length != 3 {
		t.Fatalf("failure layer should cover the bytes: %+v", p.Layers)
	}
}
