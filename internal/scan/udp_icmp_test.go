package scan

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/matusso/nyxr/internal/probe"
)

func quotedICMP(v6 bool, code byte, flow udpFlow, payload []byte) []byte {
	ipLength := 20
	if v6 {
		ipLength = 40
	}
	packet := make([]byte, 8+ipLength+8)
	if v6 {
		packet[0], packet[1], packet[8] = 1, code, 0x60
		packet[14] = 17
		copy(packet[16:32], flow.source.AsSlice())
		copy(packet[32:48], flow.target.AsSlice())
	} else {
		packet[0], packet[1], packet[8] = 3, code, 0x45
		packet[17] = 17
		copy(packet[20:24], flow.source.AsSlice())
		copy(packet[24:28], flow.target.AsSlice())
	}
	udp := packet[8+ipLength:]
	binary.BigEndian.PutUint16(udp[:2], flow.sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], flow.targetPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(payload)+8))
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(flow, payload))
	return packet
}

func TestQuotedICMPUDP(t *testing.T) {
	for _, tc := range []struct {
		name           string
		v6             bool
		code           byte
		state          string
		source, target string
	}{
		{"v4-closed", false, 3, "closed", "192.0.2.1", "198.51.100.2"},
		{"v4-filtered", false, 13, "filtered", "192.0.2.1", "198.51.100.2"},
		{"v6-closed", true, 4, "closed", "2001:db8::1", "2001:db8::2"},
		{"v6-filtered", true, 1, "filtered", "2001:db8::1", "2001:db8::2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flow := udpFlow{netip.MustParseAddr(tc.source), netip.MustParseAddr(tc.target), 45678, 53}
			payload := []byte{1, 2, 3}
			raw := quotedICMP(tc.v6, tc.code, flow, payload)
			got, ok := parseICMPUDP(raw)
			if !ok || got.flow != flow || got.state != tc.state || got.checksum != udpChecksum(flow, payload) {
				t.Fatalf("got %+v, %v", got, ok)
			}
			if _, ok := parseICMPUDP(raw[:len(raw)-1]); ok {
				t.Fatal("accepted truncated quote")
			}
			bad := append([]byte(nil), raw...)
			bad[8+9] = 6 // TCP, not UDP (IPv4 only)
			if !tc.v6 {
				if _, ok := parseICMPUDP(bad); ok {
					t.Fatal("accepted TCP quote")
				}
			}
		})
	}
}

func TestUDPChecksumMatchesWireEncoding(t *testing.T) {
	for _, tc := range []struct{ source, target string }{{"192.0.2.1", "198.51.100.2"}, {"2001:db8::1", "2001:db8::2"}} {
		flow := udpFlow{source: netip.MustParseAddr(tc.source), target: netip.MustParseAddr(tc.target), sourcePort: 45678, targetPort: 53}
		payload := []byte{1, 2, 3}
		udp := &layers.UDP{SrcPort: layers.UDPPort(flow.sourcePort), DstPort: layers.UDPPort(flow.targetPort)}
		var ip gopacket.SerializableLayer
		if flow.source.Is4() {
			v4 := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: flow.source.AsSlice(), DstIP: flow.target.AsSlice()}
			ip = v4
			if err := udp.SetNetworkLayerForChecksum(v4); err != nil {
				t.Fatal(err)
			}
		} else {
			v6 := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP, SrcIP: flow.source.AsSlice(), DstIP: flow.target.AsSlice()}
			ip = v6
			if err := udp.SetNetworkLayerForChecksum(v6); err != nil {
				t.Fatal(err)
			}
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)); err != nil {
			t.Fatal(err)
		}
		at := 20
		if flow.source.Is6() {
			at = 40
		}
		wire := binary.BigEndian.Uint16(buf.Bytes()[at+6 : at+8])
		if got := udpChecksum(flow, payload); got != wire {
			t.Fatalf("%s: checksum %04x, wire %04x", flow.source, got, wire)
		}
	}
}

func TestUDPCampaignCorrelatesInjectedICMP(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	observer := &udpICMPObserver{waiters: make(map[udpFlow]chan icmpUDPError), v4: true}
	p := probe.Probe{Name: "dns-test", Payload: make([]byte, 12), Matcher: "dns"}
	go func() {
		var request [32]byte
		n, _, readErr := server.ReadFromUDP(request[:])
		if readErr != nil {
			return
		}
		observer.mu.RLock()
		var flow udpFlow
		for f := range observer.waiters {
			flow = f
		}
		observer.mu.RUnlock()
		if !flow.source.IsValid() {
			return
		}
		bad := quotedICMP(false, 3, flow, []byte{99})
		if event, ok := parseICMPUDP(bad); ok {
			observer.dispatch(event)
		}
		good := quotedICMP(false, 3, flow, request[:n])
		if event, ok := parseICMPUDP(good); ok {
			observer.dispatch(event)
		}
	}()
	got := probeUDPCampaignWithICMP(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"},
		time.Second, []probe.Probe{p}, 0, []byte("secret"), newProbeLimiter(0), observer)
	if got.State != "closed" || got.PacketsRX != 1 || got.Probe != "dns-test" {
		t.Fatalf("got %+v", got)
	}
}

func TestTFTPReplyFromTransferPort(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	transfer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer transfer.Close()
	go func() {
		var request [128]byte
		_, peer, e := server.ReadFromUDP(request[:])
		if e == nil {
			_, _ = transfer.WriteToUDP([]byte{0, 5, 0, 1, 'x', 0}, peer)
		}
	}()
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	p := probe.Probe{Name: "tftp", Payload: []byte{0, 1, 'x', 0, 'o', 'c', 't', 'e', 't', 0}, Matcher: "tftp", ExtractFields: []string{"tftp.error_code"}}
	got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"},
		time.Second, []probe.Probe{p}, 0, []byte("secret"), newProbeLimiter(0))
	if got.State != "open" || got.Confidence != 85 || got.Fields["tftp.error_code"] != "1" {
		t.Fatalf("got %+v", got)
	}
}

func TestUDPFeedbackRetryBonus(t *testing.T) {
	target := netip.MustParseAddr("192.0.2.8")
	f := newUDPFeedback()
	if f.retryBonus(target) != 0 {
		t.Fatal("unmeasured host gained a retry")
	}
	f.record(Observation{Target: target, State: "closed", Reason: "ICMP port unreachable"})
	if f.retryBonus(target) != 0 {
		t.Fatal("one ICMP is not evidence of limiting")
	}
	f.record(Observation{Target: target, State: "open|filtered"})
	if f.retryBonus(target) != 1 {
		t.Fatal("mixed ICMP and silence should gain one retry")
	}
	other := netip.MustParseAddr("192.0.2.9")
	f.record(Observation{Target: other, State: "open", PacketsTX: 2, PacketsRX: 1})
	if f.retryBonus(other) != 1 {
		t.Fatal("delayed reply should gain one retry")
	}
}
