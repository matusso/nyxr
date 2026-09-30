package packet

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

func forgeBase(v6 bool, proto uint8) ForgeSpec {
	src, dst := "192.0.2.10", "198.51.100.20"
	if v6 {
		src, dst = "2001:db8::10", "2001:db8::20"
	}
	return ForgeSpec{SourceMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DestinationMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
		SourceIP: netip.MustParseAddr(src), DestinationIP: netip.MustParseAddr(dst), Protocol: proto,
		SourcePort: 50000, DestPort: 443, TCPFlags: 2, Sequence: 0x12345678, Window: 64240, HopLimit: 64, ID: 0x12345678}
}

func TestForgeTransportRoundTrip(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, proto := range []uint8{6, 17, 132} {
			s := forgeBase(v6, proto)
			if proto == 6 {
				s.TCPOptions = []byte{2, 4, 5, 180}
			}
			if proto == 17 {
				s.Payload = []byte{1, 2, 3, 4, 5}
			}
			frames, err := ForgeFrames(s)
			if err != nil || len(frames) != 1 {
				t.Fatalf("v6=%v proto=%d: %v", v6, proto, err)
			}
			p, ok := DecodeResearch(frames[0])
			if !ok || p.Source != s.SourceIP || p.Destination != s.DestinationIP || p.Protocol != proto || p.SourcePort != s.SourcePort || p.DestPort != s.DestPort {
				t.Fatalf("v6=%v proto=%d: %+v, %v", v6, proto, p, ok)
			}
			if proto == 6 && (!v6) {
				ip := frames[0][14:]
				if internetChecksum(ip[:20]) != 0 || ip[20+12]>>4 != 6 {
					t.Fatal("bad IPv4/TCP header")
				}
			}
			if proto == 132 {
				at := 14 + 20
				if v6 {
					at = 14 + 40
				}
				payload := append([]byte(nil), frames[0][at:]...)
				want := binary.LittleEndian.Uint32(payload[8:12])
				clear(payload[8:12])
				if want != sctpCRC(payload) {
					t.Fatal("bad SCTP CRC32c")
				}
			}
		}
	}
}

func TestForgeIPv6ExtensionsAndFragments(t *testing.T) {
	s := forgeBase(true, 17)
	s.Payload = make([]byte, 32)
	s.DSCP = 63
	s.IPv6Extensions = []IPv6Extension{{Type: 0, Data: make([]byte, 6)}, {Type: 60, Data: make([]byte, 6)}}
	frames, err := ForgeFrames(s)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := DecodeResearch(frames[0]); !ok || p.Protocol != 17 {
		t.Fatalf("extension decode: %+v %v", p, ok)
	}
	if frames[0][14]&0x0f != 0x0f || frames[0][15]&0xf0 != 0xc0 {
		t.Fatal("incorrect IPv6 traffic class")
	}
	if uint32(frames[0][15]&0x0f)<<16|uint32(frames[0][16])<<8|uint32(frames[0][17]) != s.ID&0xfffff {
		t.Fatal("incorrect IPv6 flow label")
	}
	s.FragmentSize = 16
	s.Experiment = true
	frames, err = ForgeFrames(s)
	if err != nil || len(frames) < 2 {
		t.Fatalf("fragments: %d %v", len(frames), err)
	}
	for _, frame := range frames {
		if _, ok := DecodeResearch(frame); ok {
			t.Fatal("classified fragment")
		}
	}
}

func TestForgePolicyAndMalformedControls(t *testing.T) {
	s := forgeBase(false, 6)
	bad := uint16(0xdead)
	s.TransportChecksum = &bad
	if _, err := ForgeFrames(s); err == nil {
		t.Fatal("unguarded checksum override")
	}
	s.Malformed = true
	s.Experiment = true
	frames, err := ForgeFrames(s)
	if err != nil || binary.BigEndian.Uint16(frames[0][14+20+16:14+20+18]) != bad {
		t.Fatalf("override: %v", err)
	}
	s.VLANTags = []VLANTag{{ID: 100, Priority: 5}}
	frames, err = ForgeFrames(s)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := DecodeResearch(frames[0]); !ok || p.Protocol != 6 {
		t.Fatalf("VLAN: %+v %v", p, ok)
	}
	s.FragmentSize = 8
	frames, err = ForgeFrames(s)
	if err != nil || len(frames) < 2 {
		t.Fatal("fragment builder")
	}
	for _, frame := range frames {
		if _, ok := DecodeResearch(frame); ok {
			t.Fatal("classified IPv4 fragment")
		}
	}
	s = forgeBase(false, 6)
	s.TCPOptions = []byte{2, 1, 0, 0}
	if _, err := ForgeFrames(s); err == nil {
		t.Fatal("accepted malformed TCP option in safe mode")
	}
	s.Malformed, s.Experiment = true, true
	if _, err := ForgeFrames(s); err != nil {
		t.Fatalf("research malformed option: %v", err)
	}
}

func TestDecodeSCTPReplyRequiresCRC(t *testing.T) {
	s := forgeBase(false, 132)
	frames, err := ForgeFrames(s)
	if err != nil {
		t.Fatal(err)
	}
	reply := append([]byte(nil), frames[0]...)
	copy(reply[:6], s.SourceMAC)
	copy(reply[6:12], s.DestinationMAC)
	copy(reply[26:30], frames[0][30:34])
	copy(reply[30:34], frames[0][26:30])
	binary.BigEndian.PutUint16(reply[24:26], 0)
	binary.BigEndian.PutUint16(reply[24:26], internetChecksum(reply[14:34]))
	copy(reply[34:36], frames[0][36:38])
	copy(reply[36:38], frames[0][34:36])
	binary.BigEndian.PutUint32(reply[38:42], s.Sequence)
	reply[46] = 2 // INIT ACK
	clear(reply[42:46])
	binary.LittleEndian.PutUint32(reply[42:46], sctpCRC(reply[34:]))
	if p, ok := DecodeResearch(reply); !ok || p.Protocol != 132 || p.SCTPTag != s.Sequence || p.SCTPChunk != 2 {
		t.Fatalf("SCTP INIT ACK: %+v %v", p, ok)
	}
	reply[53] ^= 1
	if _, ok := DecodeResearch(reply); ok {
		t.Fatal("bad SCTP CRC accepted")
	}
}
