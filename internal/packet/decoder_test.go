package packet

import (
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
