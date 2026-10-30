package packet

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

func TestIPv6SYNTemplateChecksumsAndDecode(t *testing.T) {
	src, dst := netip.MustParseAddr("2001:db8:1::10"), netip.MustParseAddr("2001:db8:2::20")
	for _, fingerprint := range []bool{false, true} {
		tmpl, err := NewSYNTemplate(net.HardwareAddr{2, 1, 2, 3, 4, 5}, net.HardwareAddr{2, 6, 7, 8, 9, 10}, src, 50000)
		if err != nil {
			t.Fatal(err)
		}
		want := 74
		if fingerprint {
			tmpl.EnableFingerprint()
			want = MaxSYNFrame
		}
		f := tmpl.Frame(dst, 443, 0xdeadbeef)
		got, ok := NewDecoder().Decode(f)
		if !ok || len(f) != want || got.IPVersion != 6 || got.Source != src || got.Destination != dst || got.TTL != 64 ||
			got.DestPort != 443 || got.SourcePort != 50000 || got.TCPSeq != 0xdeadbeef || got.DF || got.IPID != 0 {
			t.Fatalf("IPv6 SYN fingerprint=%v: %+v %v", fingerprint, got, ok)
		}
		if binary.BigEndian.Uint16(f[18:20]) != uint16(want-54) || f[20] != 6 {
			t.Fatalf("IPv6 header: payload %d next %d", binary.BigEndian.Uint16(f[18:20]), f[20])
		}
		var pseudo [40]byte
		copy(pseudo[:32], f[22:54])
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(f)-54))
		pseudo[39] = 6
		if foldChecksum(checksumWords(f[54:], checksumWords(pseudo[:], 0))) != 0 {
			t.Fatal("invalid IPv6 TCP checksum")
		}
		if fingerprint && (got.TCPOptionsLen != 20 || binary.BigEndian.Uint16(got.TCPOptions[2:4]) != 1440 || binary.BigEndian.Uint32(got.TCPOptions[8:12]) != 0xdeadbeef || got.TCPFlags != 0xc2) {
			t.Fatalf("IPv6 fingerprint options: %x", got.TCPOptions[:got.TCPOptionsLen])
		}
	}
	for _, bad := range []netip.Addr{netip.MustParseAddr("fe80::1%en0"), netip.MustParseAddr("::ffff:192.0.2.1"), {}} {
		if _, err := NewSYNTemplate(net.HardwareAddr{2, 1, 2, 3, 4, 5}, net.HardwareAddr{2, 6, 7, 8, 9, 10}, bad, 50000); err == nil {
			t.Fatalf("accepted source %v", bad)
		}
	}
}

func ipv6Frame(nh byte, payload []byte) []byte {
	f := make([]byte, 54, 54+len(payload))
	binary.BigEndian.PutUint16(f[12:14], 0x86dd)
	f[14] = 0x60
	binary.BigEndian.PutUint16(f[18:20], uint16(len(payload)))
	f[20], f[21] = nh, 57
	copy(f[22:38], netip.MustParseAddr("2001:db8:2::20").AsSlice())
	copy(f[38:54], netip.MustParseAddr("2001:db8:1::10").AsSlice())
	return append(f, payload...)
}

func TestDecodeIPv6ExtensionHeadersAndICMPv6Quote(t *testing.T) {
	tcp := make([]byte, 24)
	binary.BigEndian.PutUint16(tcp[0:2], 443)
	binary.BigEndian.PutUint16(tcp[2:4], 50000)
	binary.BigEndian.PutUint32(tcp[8:12], 8)
	tcp[12], tcp[13] = 0x60, 0x12
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], []byte{2, 4, 5, 160})
	chain := append([]byte{43, 0, 1, 4, 0, 0, 0, 0, 60, 0, 0, 0, 0, 0, 0, 0}, []byte{6, 0, 1, 4, 0, 0, 0, 0}...)
	chain[8], chain[9] = 60, 0 // routing header: next=dest opts, len 0
	chain[10] = 0              // routing type 0, segments left 0
	got, ok := NewDecoder().Decode(ipv6Frame(0, append(chain, tcp...)))
	if !ok || got.Protocol != "tcp" || got.TCPFlags != 0x12 || got.TCPAck != 8 || got.TCPWindow != 65535 || got.TTL != 57 ||
		got.TCPOptionsLen != 4 || got.SourcePort != 443 {
		t.Fatalf("extension chain: %+v %v", got, ok)
	}
	if _, ok := NewDecoder().Decode(ipv6Frame(44, append([]byte{6, 0, 0, 0, 0, 0, 0, 1}, tcp...))); ok {
		t.Fatal("decoded a fragment")
	}

	syn, _ := NewSYNTemplate(net.HardwareAddr{2, 1, 2, 3, 4, 5}, net.HardwareAddr{2, 6, 7, 8, 9, 10}, netip.MustParseAddr("2001:db8:1::10"), 50000)
	quoted := syn.Frame(netip.MustParseAddr("2001:db8:2::20"), 443, 77)[14:]
	icmp := append([]byte{1, 4, 0, 0, 0, 0, 0, 0}, quoted...)
	got, ok = NewDecoder().Decode(ipv6Frame(58, icmp))
	q := got.Quote
	if !ok || got.Protocol != "icmp6" || got.ICMPType != 1 || got.ICMPCode != 4 || !q.Valid || q.Sequence != 77 || q.SourcePort != 50000 || q.DestPort != 443 || !q.Source.Is6() {
		t.Fatalf("ICMPv6 quote: %+v %v", got, ok)
	}
	got, ok = NewDecoder().Decode(ipv6Frame(0, append([]byte{58, 0, 1, 4, 0, 0, 0, 0}, icmp...)))
	if !ok || got.Protocol != "icmp6" || !got.Quote.Valid || got.Quote.Sequence != 77 {
		t.Fatalf("ICMPv6 behind hop-by-hop: %+v %v", got, ok)
	}
	if got, _ := NewDecoder().Decode(ipv6Frame(58, icmp[:8+40+6])); got.Quote.Valid {
		t.Fatal("quote without a TCP sequence was accepted")
	}
}

func TestNeighborAdvertisementTarget(t *testing.T) {
	target := netip.MustParseAddr("fe80::1")
	icmp := make([]byte, 32)
	icmp[0] = 136
	copy(icmp[8:24], target.AsSlice())
	frame := ipv6Frame(58, icmp)
	if got, ok := NeighborAdvertisementTarget(frame); !ok || got != target {
		t.Fatalf("target %v %v", got, ok)
	}
	icmp[0] = 135
	if _, ok := NeighborAdvertisementTarget(ipv6Frame(58, icmp)); ok {
		t.Fatal("solicitation read as advertisement")
	}
}
