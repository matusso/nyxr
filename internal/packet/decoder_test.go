package packet

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func frame(t testing.TB, ipv6 bool) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{1, 2, 3, 4, 5, 6}, DstMAC: net.HardwareAddr{6, 5, 4, 3, 2, 1}}
	var stack []gopacket.SerializableLayer
	if ipv6 {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP,
			SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
		udp := &layers.UDP{SrcPort: 1234, DstPort: 53}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		stack = []gopacket.SerializableLayer{eth, ip, udp, gopacket.Payload{1, 2, 3}}
	} else {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
			SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
		tcp := &layers.TCP{SrcPort: 443, DstPort: 49152, SYN: true, ACK: true}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		stack = []gopacket.SerializableLayer{eth, ip, tcp}
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, stack...); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDiscoveryRejectsFragmentedAndExtensionFrames(t *testing.T) {
	base4 := append([]byte(nil), frame(t, false)...)
	binary.BigEndian.PutUint16(base4[20:22], 0x2000) // IPv4 more-fragments flag
	if got, ok := NewDecoder().Decode(base4); ok {
		t.Fatalf("fragmented IPv4 packet classified as %+v", got)
	}
	base6 := append([]byte(nil), frame(t, true)...)
	for _, tc := range []struct{ next, flags byte }{{0, 0}, {44, 1}} {
		packet := make([]byte, len(base6)+8)
		copy(packet[:54], base6[:54])
		copy(packet[62:], base6[54:])
		packet[20] = tc.next // IPv6 next header
		binary.BigEndian.PutUint16(packet[18:20], binary.BigEndian.Uint16(base6[18:20])+8)
		packet[54] = 17 // UDP follows extension header
		if tc.next == 44 {
			packet[56] = tc.flags
		}
		got, ok := NewDecoder().Decode(packet)
		if tc.next == 0 && (!ok || got.Protocol != "udp") {
			t.Fatalf("safe IPv6 extension packet lost: %+v, %v", got, ok)
		}
		if tc.next == 44 && ok {
			t.Fatalf("IPv6 fragment classified as %+v", got)
		}
	}
}

func TestDecoderReuse(t *testing.T) {
	d := NewDecoder()
	for _, tc := range []struct {
		v6     bool
		proto  string
		source string
		port   uint16
	}{
		{false, "tcp", "192.0.2.1", 443}, {true, "udp", "2001:db8::1", 1234}, {false, "tcp", "192.0.2.1", 443},
	} {
		got, ok := d.Decode(frame(t, tc.v6))
		if !ok || got.Protocol != tc.proto || got.Source.String() != tc.source || got.SourcePort != tc.port {
			t.Fatalf("decode: %+v, %v", got, ok)
		}
	}
	if _, ok := d.Decode([]byte{1, 2, 3}); ok {
		t.Fatal("accepted short frame")
	}
}

func TestParseQuotedUDP(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		header := make([]byte, 48)
		if v6 {
			header[0], header[6] = 0x60, 17
			copy(header[8:24], net.ParseIP("2001:db8::1").To16())
			copy(header[24:40], net.ParseIP("2001:db8::2").To16())
		} else {
			header[0], header[9] = 0x45, 17
			copy(header[12:16], net.ParseIP("192.0.2.1").To4())
			copy(header[16:20], net.ParseIP("192.0.2.2").To4())
			header = header[:28]
		}
		udp := header[len(header)-8:]
		binary.BigEndian.PutUint16(udp[:2], 50000)
		binary.BigEndian.PutUint16(udp[2:4], 53)
		binary.BigEndian.PutUint16(udp[4:6], 20)
		binary.BigEndian.PutUint16(udp[6:8], 0xabcd)
		q := parseQuotedUDP(header)
		if !q.Valid || q.SourcePort != 50000 || q.DestPort != 53 || q.Length != 20 || q.Checksum != 0xabcd {
			t.Fatalf("v6=%v: %+v", v6, q)
		}
		if parseQuotedUDP(header[:len(header)-1]).Valid {
			t.Fatal("accepted truncated UDP quote")
		}
	}
}

func TestDecoderICMPv6QuotedUDP(t *testing.T) {
	quote := make([]byte, 48)
	quote[0], quote[6] = 0x60, 17
	copy(quote[8:24], net.ParseIP("2001:db8::1").To16())
	copy(quote[24:40], net.ParseIP("2001:db8::2").To16())
	binary.BigEndian.PutUint16(quote[40:42], 50000)
	binary.BigEndian.PutUint16(quote[42:44], 5683)
	binary.BigEndian.PutUint16(quote[44:46], 20)
	binary.BigEndian.PutUint16(quote[46:48], 0xabcd)
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv6}
	ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolICMPv6,
		SrcIP: net.ParseIP("2001:db8::ff"), DstIP: net.ParseIP("2001:db8::1")}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(1, 4)}
	if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	payload := append(make([]byte, 4), quote...)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, icmp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	got, ok := NewDecoder().Decode(buf.Bytes())
	if !ok || got.Protocol != "icmp6" || !got.UDPQuote.Valid || got.UDPQuote.DestPort != 5683 {
		t.Fatalf("got %+v, %v", got, ok)
	}
}

func BenchmarkDecodeTCP(b *testing.B) {
	packet := frame(b, false)
	d := NewDecoder()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := d.Decode(packet); !ok {
			b.Fatal("decode failed")
		}
	}
}
