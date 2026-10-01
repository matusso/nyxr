package scan

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/probe"
)

func TestTCPConnectOpenAndClosed(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	target := netip.MustParseAddr("127.0.0.1")
	var got []Observation
	cfg := config.Config{Targets: []netip.Addr{target}, Ports: []uint16{port}, TCP: true, Timeout: time.Second, Workers: 2}
	if err := Run(context.Background(), cfg, func(o Observation) error { got = append(got, o); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].State != "open" {
		t.Fatalf("got %+v", got)
	}
	listener.Close()
	closed := probeTCP(context.Background(), task{target: target, port: port, transport: "tcp"}, time.Second)
	if closed.State != "closed" {
		t.Fatalf("got %+v", closed)
	}
}

func TestUDPReply(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	go func() {
		var buf [64]byte
		n, addr, err := server.ReadFromUDP(buf[:])
		if err == nil && n > 0 {
			_, _ = server.WriteToUDP([]byte{1}, addr)
		}
	}()
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"}, time.Second, nil, 0, []byte("test-secret"), newProbeLimiter(0))
	if got.State != "open" || got.PacketsRX != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestUDPBACnetFallsBackWhenFirstProbeIsSilent(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	all, err := probe.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	selected := probe.ForPort(all, 47808)
	for i := range selected {
		selected[i].Ports = []uint16{port}
		selected[i].Timeout = 40 * time.Millisecond
	}
	go func() {
		var buf [64]byte
		for {
			n, addr, err := server.ReadFromUDP(buf[:])
			if err != nil {
				return
			}
			if n == 17 && buf[1] == 0x0a && buf[9] == 0x0c {
				response := []byte{0x81, 0x0a, 0, 9, 1, 0, 0x30, buf[8], 0x0c}
				_, _ = server.WriteToUDP(response, addr)
			}
		}
	}()
	got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"},
		time.Second, selected, 0, []byte("secret"), newProbeLimiter(0))
	if got.State != "open" || got.Service != "bacnet" || got.Probe != "bacnet-read-device" || got.Confidence != 100 {
		t.Fatalf("BACnet read response should confirm open port: %+v", got)
	}
}

func TestUDPBACnetForeignDeviceTableConfirmsOpen(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	all, err := probe.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	var fdt probe.Probe
	for _, p := range probe.ForPort(all, 47808) {
		if p.Matcher == "bacnet-fdt" {
			fdt = p
		}
	}
	if fdt.Name == "" {
		t.Fatal("FDT probe missing")
	}
	fdt.Ports = []uint16{port}
	go func() {
		var buf [16]byte
		n, addr, err := server.ReadFromUDP(buf[:])
		if err == nil && n == 4 && buf[1] == 6 {
			response := []byte{0x81, 0x07, 0, 14, 217, 75, 94, 18, 0x62, 0x2d, 0, 30, 0, 34}
			_, _ = server.WriteToUDP(response, addr)
		}
	}()
	got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"},
		time.Second, []probe.Probe{fdt}, 0, []byte("secret"), newProbeLimiter(0))
	if got.State != "open" || got.Service != "bacnet" || got.Probe != "bacnet-fdt" || got.Fields["bacnet.fdt_entries"] != "1" {
		t.Fatalf("FDT response should confirm BACnet open port: %+v", got)
	}
}

func TestUDPCampaignMatchesAfterStrayReply(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	go func() {
		var buf [64]byte
		n, addr, err := server.ReadFromUDP(buf[:])
		if err != nil {
			return
		}
		wrong := append([]byte(nil), buf[:n]...)
		wrong[0] ^= 1
		wrong[2] |= 0x80
		_, _ = server.WriteToUDP(wrong, addr)
		valid := append([]byte(nil), buf[:n]...)
		valid[2] |= 0x80
		_, _ = server.WriteToUDP(valid, addr)
	}()
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	p := probe.Probe{Name: "dns-test", Payload: make([]byte, 12), Matcher: "dns"}
	got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"}, time.Second, []probe.Probe{p}, 0, []byte("secret"), newProbeLimiter(0))
	if got.State != "open" || got.Confidence != 100 || got.PacketsRX != 2 {
		t.Fatalf("got %+v", got)
	}
}

func TestMatchRecentAcceptsDelayedProbeResponse(t *testing.T) {
	p := probe.Probe{Name: "dns-a", Payload: make([]byte, 12), Matcher: "dns"}
	first := probe.Prepare(p, 0x1234)
	second := probe.Prepare(p, 0x5678)
	response := append([]byte(nil), first...)
	response[2] |= 0x80
	recent := []sentProbe{{probe: p, request: first}, {probe: p, request: second}}
	matched, ok := matchRecent(recent, response)
	if !ok || string(matched.request) != string(first) {
		t.Fatal("late response did not match the earlier request")
	}
}

func TestUDPCampaignRetriesNoResponse(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	received := make(chan int, 1)
	go func() {
		var buf [16]byte
		count := 0
		for count < 2 {
			if _, _, err := server.ReadFromUDP(buf[:]); err != nil {
				break
			}
			count++
		}
		received <- count
	}()
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	p := probe.Probe{Name: "silent", Payload: []byte{1}, Matcher: "any", Retries: 1}
	got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"}, 20*time.Millisecond, []probe.Probe{p}, 0, []byte("secret"), newProbeLimiter(0))
	if got.State != "open|filtered" || got.PacketsTX != 2 || len(got.ProbesAttempted) != 2 {
		t.Fatalf("got %+v", got)
	}
	select {
	case count := <-received:
		if count != 2 {
			t.Fatalf("server received %d probes", count)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive both retries")
	}
}

func TestUDPCampaignCapsCombinedRetries(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	p := probe.Probe{Name: "silent", Payload: []byte{1}, Matcher: "any", Retries: 5}
	got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: uint16(server.LocalAddr().(*net.UDPAddr).Port), transport: "udp"},
		5*time.Millisecond, []probe.Probe{p}, 5, []byte("secret"), newProbeLimiter(0))
	if got.State != "open|filtered" || got.PacketsTX != 6 {
		t.Fatalf("got %+v", got)
	}
}

func TestChecksum(t *testing.T) {
	msg := []byte{8, 0, 0, 0, 0, 1, 0, 1}
	c := checksum(msg)
	msg[2], msg[3] = byte(c>>8), byte(c)
	if checksum(msg) != 0 {
		t.Fatalf("invalid checksum: %x", msg)
	}
}

func TestICMPv6Checksum(t *testing.T) {
	source := net.ParseIP("2001:db8::1")
	destination := net.ParseIP("2001:db8::2")
	message := []byte{128, 0, 0, 0, 0x12, 0x34, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8}
	binary.BigEndian.PutUint16(message[2:4], icmp6Checksum(source, destination, message))
	if got := icmp6Checksum(source, destination, message); got != 0 {
		t.Fatalf("ICMPv6 pseudoheader checksum failed: %04x", got)
	}
	message[15] ^= 1
	if got := icmp6Checksum(source, destination, message); got == 0 {
		t.Fatal("payload change was not detected")
	}
}

func TestEchoReplyRequiresMatchingToken(t *testing.T) {
	request := []byte{128, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	reply := append([]byte(nil), request...)
	reply[0] = 129
	if !matchesEchoReply(reply, 129, request) {
		t.Fatal("valid echo reply rejected")
	}
	withHeader := make([]byte, 40+len(reply))
	withHeader[0], withHeader[6] = 0x60, 58
	copy(withHeader[40:], reply)
	if !matchesEchoReply(withHeader, 129, request) {
		t.Fatal("IPv6 header reply rejected")
	}
	reply[15] ^= 1
	if matchesEchoReply(reply, 129, request) {
		t.Fatal("wrong token accepted")
	}
	if matchesEchoReply(reply[:15], 129, request) {
		t.Fatal("truncated reply accepted")
	}
}
