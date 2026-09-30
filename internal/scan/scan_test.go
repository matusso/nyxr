package scan

import (
	"context"
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

func TestChecksum(t *testing.T) {
	msg := []byte{8, 0, 0, 0, 0, 1, 0, 1}
	c := checksum(msg)
	msg[2], msg[3] = byte(c>>8), byte(c)
	if checksum(msg) != 0 {
		t.Fatalf("invalid checksum: %x", msg)
	}
}
