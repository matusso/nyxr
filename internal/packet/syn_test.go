package packet

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestSYNTemplateRoundTripAndChecksums(t *testing.T) {
	src := netip.MustParseAddr("192.0.2.10")
	dst := netip.MustParseAddr("198.51.100.20")
	tmpl, err := NewSYNTemplate(net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.HardwareAddr{6, 5, 4, 3, 2, 1}, src, 50000)
	if err != nil {
		t.Fatal(err)
	}
	decoder := NewDecoder()
	for _, tc := range []struct {
		port uint16
		seq  uint32
	}{{80, 0x12345678}, {443, 0xffeeddcc}} {
		frame := tmpl.Frame(dst, tc.port, tc.seq)
		got, ok := decoder.Decode(frame)
		if !ok || got.Source != src || got.Destination != dst || got.DestPort != tc.port || got.TCPSeq != tc.seq || got.TCPFlags != 2 {
			t.Fatalf("decoded SYN = %+v, ok=%v", got, ok)
		}
		if internetChecksum(frame[14:34]) != 0 {
			t.Fatal("invalid IPv4 checksum")
		}
		var pseudo [12]byte
		copy(pseudo[:8], frame[26:34])
		pseudo[9] = 6
		binary.BigEndian.PutUint16(pseudo[10:], 20)
		if foldChecksum(checksumWords(frame[34:54], checksumWords(pseudo[:], 0))) != 0 {
			t.Fatal("invalid TCP checksum")
		}
	}
}

func TestQuotedTCPRejectsTruncationAndFragments(t *testing.T) {
	request := make([]byte, 28)
	request[0], request[9] = 0x45, 6
	copy(request[12:16], []byte{192, 0, 2, 10})
	copy(request[16:20], []byte{198, 51, 100, 20})
	binary.BigEndian.PutUint16(request[20:22], 50000)
	binary.BigEndian.PutUint16(request[22:24], 443)
	binary.BigEndian.PutUint32(request[24:28], 0x12345678)
	q := parseQuotedTCP(request)
	if !q.Valid || q.SourcePort != 50000 || q.DestPort != 443 || q.Sequence != 0x12345678 {
		t.Fatalf("quote = %+v", q)
	}
	if parseQuotedTCP(request[:27]).Valid {
		t.Fatal("accepted truncated quote")
	}
	request[7] = 1
	if parseQuotedTCP(request).Valid {
		t.Fatal("accepted later fragment")
	}
}

func TestDecoderICMPErrorQuotesSYN(t *testing.T) {
	src := netip.MustParseAddr("192.0.2.10")
	dst := netip.MustParseAddr("198.51.100.20")
	tmpl, err := NewSYNTemplate(net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.HardwareAddr{6, 5, 4, 3, 2, 1}, src, 50000)
	if err != nil {
		t.Fatal(err)
	}
	quote := append([]byte(nil), tmpl.Frame(dst, 443, 0x12345678)[14:42]...)
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{6, 5, 4, 3, 2, 1}, DstMAC: net.HardwareAddr{1, 2, 3, 4, 5, 6}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: net.ParseIP("198.51.100.1"), DstIP: net.ParseIP("192.0.2.10")}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(3, 13)}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, icmp, gopacket.Payload(quote)); err != nil {
		t.Fatal(err)
	}
	got, ok := NewDecoder().Decode(buf.Bytes())
	if !ok || got.Protocol != "icmp" || got.ICMPType != 3 || got.ICMPCode != 13 || !got.Quote.Valid || got.Quote.Sequence != 0x12345678 {
		t.Fatalf("ICMP decode = %+v, ok=%v", got, ok)
	}
}
