package main

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/ui"
)

var (
	scannerIP = netip.MustParseAddr("192.0.2.2")
	targetIP  = netip.MustParseAddr("192.0.2.10")
)

func tcpPacket(src, dst netip.Addr, sport, dport uint16, flags uint8) packet.Decoded {
	return packet.Decoded{Source: src, Destination: dst, Protocol: "tcp", SourcePort: sport, DestPort: dport, TCPFlags: flags}
}

func udpPacket(src, dst netip.Addr, sport, dport uint16) packet.Decoded {
	return packet.Decoded{Source: src, Destination: dst, Protocol: "udp", SourcePort: sport, DestPort: dport}
}

func TestCaptureAnalysisInfersPortStates(t *testing.T) {
	a := newCaptureAnalysis()
	for _, d := range []packet.Decoded{
		tcpPacket(scannerIP, targetIP, 40000, 22, tcpSYN),
		tcpPacket(targetIP, scannerIP, 22, 40000, tcpSYN|tcpACK),
		tcpPacket(scannerIP, targetIP, 40000, 22, tcpRST), // scanner tears down; not a closed port
		tcpPacket(scannerIP, targetIP, 40001, 23, tcpSYN),
		tcpPacket(targetIP, scannerIP, 23, 40001, tcpRST|tcpACK),
		tcpPacket(targetIP, scannerIP, 8080, 40002, tcpRST), // unsolicited reset is ignored
		udpPacket(scannerIP, targetIP, 50000, 53),
		udpPacket(targetIP, scannerIP, 53, 50000),
		udpPacket(scannerIP, targetIP, 50000, 53), // follow-up must not open the client port
		{Source: targetIP, Destination: scannerIP, Protocol: "icmp", ICMPType: 3, ICMPCode: 3,
			UDPQuote: packet.QuotedUDP{Source: scannerIP, Destination: targetIP, SourcePort: 50001, DestPort: 161, Valid: true}},
	} {
		a.add(d)
	}
	h := a.hosts[targetIP]
	if h == nil {
		t.Fatal("target host missing")
	}
	want := map[portKey]int{
		{"tcp", 22}: stateOpen, {"tcp", 23}: stateClosed, {"udp", 53}: stateOpen, {"udp", 161}: stateClosed,
	}
	if len(h.ports) != len(want) {
		t.Fatalf("ports %v, want %v", h.ports, want)
	}
	for k, state := range want {
		if f := h.ports[k]; f == nil || f.state != state {
			t.Fatalf("%v: got %+v, want state %d", k, f, state)
		}
	}
	if s := a.hosts[scannerIP]; s != nil {
		t.Fatalf("scanner reported as a target: %+v", s.ports)
	}
}

func TestDecodeReportPlain(t *testing.T) {
	a := newCaptureAnalysis()
	a.frames = 3
	for _, d := range []packet.Decoded{
		tcpPacket(scannerIP, targetIP, 40000, 443, tcpSYN),
		tcpPacket(targetIP, scannerIP, 443, 40000, tcpSYN|tcpACK),
	} {
		a.add(d)
	}
	got := decodeReport(ui.Plain(), "scan.pcapng", a, false)
	for _, want := range []string{
		"scan.pcapng\n",
		"3 frames • 2 decoded • 1 skipped",
		"1 responding",
		"192.0.2.10  1 open",
		"443/tcp  open   https    syn-ack",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("report missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\x1b[") || strings.Contains(got, "●") {
		t.Fatalf("plain report contains color or glyphs:\n%s", got)
	}
}

func TestDecodeCommandFixture(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"decode", "--all", "../../tests/pcaps/phase0.pcap"}, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{"10 frames • 8 decoded • 2 skipped", "192.0.2.1  1 open", "2001:db8::1  1 open", "filtered"} {
		if !strings.Contains(got, want) {
			t.Fatalf("decode output missing %q:\n%s", want, got)
		}
	}
}

func TestDecodeCommandJSON(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"decode", "--json", "../../tests/pcaps/phase0.pcap"}, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 8 {
		t.Fatalf("got %d JSON lines, want 8", len(lines))
	}
	var first packet.Decoded
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil || first.Protocol != "tcp" {
		t.Fatalf("first line %q: %v", lines[0], err)
	}
}
