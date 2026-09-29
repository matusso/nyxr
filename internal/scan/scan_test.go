package scan

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/config"
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
	got := probeUDP(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"}, time.Second)
	if got.State != "open" || got.PacketsRX != 1 {
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
