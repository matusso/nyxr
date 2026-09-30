package scan

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/packet"
)

func researchSent(proto uint8) packet.ForgeSpec {
	return packet.ForgeSpec{SourceMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DestinationMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
		SourceIP: netip.MustParseAddr("192.0.2.10"), DestinationIP: netip.MustParseAddr("198.51.100.20"), Protocol: proto,
		SourcePort: 50000, DestPort: 443, TCPFlags: 2, Sequence: 0x12345678, Window: 64240, HopLimit: 64, ID: 0x5678, Experiment: true}
}

func TestResearchCorrelationRejectsUnrelated(t *testing.T) {
	s := researchSent(6)
	p := packet.ResearchDecoded{Source: s.DestinationIP, Destination: s.SourceIP, Protocol: 6, SourcePort: s.DestPort, DestPort: s.SourcePort, TCPFlags: 0x12, TCPAck: s.Sequence + 1}
	if state, _, _, ok := matchResearch(p, s); !ok || state != "open" {
		t.Fatal("matching SYN/ACK lost")
	}
	p.TCPAck--
	if _, _, _, ok := matchResearch(p, s); ok {
		t.Fatal("stale TCP acknowledgment accepted")
	}
	p.TCPAck++
	p.Source = netip.MustParseAddr("198.51.100.21")
	if _, _, _, ok := matchResearch(p, s); ok {
		t.Fatal("unrelated target accepted")
	}
	s.Protocol = 132
	p = packet.ResearchDecoded{Source: s.DestinationIP, Destination: s.SourceIP, Protocol: 132, SourcePort: s.DestPort, DestPort: s.SourcePort, SCTPChunk: 2, SCTPTag: s.Sequence}
	if state, _, _, ok := matchResearch(p, s); !ok || state != "open" {
		t.Fatal("matching SCTP INIT ACK lost")
	}
	p.SCTPTag++
	if _, _, _, ok := matchResearch(p, s); ok {
		t.Fatal("unrelated SCTP tag accepted")
	}
	s.Protocol = 47
	s.RawProtocol = true
	s.SourcePort = 0
	s.DestPort = 0
	p = packet.ResearchDecoded{Source: s.DestinationIP, Destination: s.SourceIP, Protocol: 1, ICMPType: 3, ICMPCode: 2,
		Quote: packet.ResearchQuote{Source: s.SourceIP, Destination: s.DestinationIP, Protocol: 47, ID: uint16(s.ID), Valid: true}}
	if state, _, _, ok := matchResearch(p, s); !ok || state != "protocol-unreachable" {
		t.Fatal("matching protocol unreachable lost")
	}
	p.Quote.ID++
	if _, _, _, ok := matchResearch(p, s); ok {
		t.Fatal("wrong quoted IP ID accepted")
	}
}

func TestResearchRawSendObservations(t *testing.T) {
	for _, flags := range []uint8{2, 0x29} {
		fake := &fakePacketIO{frames: make(chan []byte, 4)}
		cfg := config.Config{Targets: []netip.Addr{netip.MustParseAddr("198.51.100.20")}, AllowTargets: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
			Ports: []uint16{443}, TCP: true, Profile: "research", TCPMode: "forge", Timeout: 10 * time.Millisecond, Rate: 5, Workers: 1,
			Interface: "test0", NextHopMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, Research: &config.ResearchConfig{Kind: "tcp", TCPFlags: flags}}
		var got []Observation
		err := runResearchWithIO(context.Background(), cfg, func(o Observation) error { got = append(got, o); return nil }, fake,
			net.HardwareAddr{2, 0, 0, 0, 0, 1}, netip.MustParseAddr("192.0.2.10"), nil, nil)
		if err != nil || len(got) != 1 || got[0].State != "no-response" || got[0].PacketsTX != 1 || fake.sent != 1 {
			t.Fatalf("flags=%x observations=%+v err=%v", flags, got, err)
		}
	}
}

func TestResearchICMPQuoteFixture(t *testing.T) {
	s := researchSent(47)
	s.RawProtocol = true
	s.SourcePort = 0
	s.DestPort = 0
	frames, err := packet.ForgeFrames(s)
	if err != nil {
		t.Fatal(err)
	}
	quote := frames[0][14:]
	reply := researchSent(1)
	reply.SourceIP, reply.DestinationIP = netip.MustParseAddr("198.51.100.1"), s.SourceIP
	reply.SourceMAC, reply.DestinationMAC = s.DestinationMAC, s.SourceMAC
	reply.Payload = append([]byte{3, 2, 0, 0, 0, 0, 0, 0}, quote...)
	reply.SourcePort, reply.DestPort = 0, 0
	raw, err := packet.ForgeFrames(reply)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := packet.DecodeResearch(raw[0])
	if !ok || !p.Quote.Valid || p.Quote.Protocol != 47 || p.Quote.ID != binary.BigEndian.Uint16(quote[4:6]) {
		t.Fatalf("quote decode %+v %v", p, ok)
	}
	if state, _, _, match := matchResearch(p, s); !match || state != "protocol-unreachable" {
		t.Fatalf("ICMP match %s %v", state, match)
	}
}

func TestResearchIPv6ICMPQuoteFixture(t *testing.T) {
	s := researchSent(17)
	s.SourceIP, s.DestinationIP = netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("2001:db8::20")
	frames, err := packet.ForgeFrames(s)
	if err != nil {
		t.Fatal(err)
	}
	reply := researchSent(58)
	reply.SourceIP, reply.DestinationIP = netip.MustParseAddr("2001:db8::1"), s.SourceIP
	reply.SourceMAC, reply.DestinationMAC = s.DestinationMAC, s.SourceMAC
	reply.SourcePort, reply.DestPort = 0, 0
	reply.Payload = append([]byte{1, 1, 0, 0, 0, 0, 0, 0}, frames[0][14:]...)
	raw, err := packet.ForgeFrames(reply)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := packet.DecodeResearch(raw[0])
	if !ok || !p.Quote.Valid || p.Quote.Protocol != 17 || p.Quote.SourcePort != s.SourcePort {
		t.Fatalf("IPv6 quote %+v %v", p, ok)
	}
	if state, _, _, matched := matchResearch(p, s); !matched || state != "administratively-prohibited" {
		t.Fatalf("IPv6 ICMP match %s %v", state, matched)
	}
	p.Quote.FlowLabel++
	if _, _, _, matched := matchResearch(p, s); matched {
		t.Fatal("wrong quoted IPv6 flow label accepted")
	}
}
