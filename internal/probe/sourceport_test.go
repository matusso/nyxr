package probe

import (
	"context"
	"net"
	"testing"
)

func TestDialUDPSourcePort(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	held, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Skipf("UDP unavailable: %v", err)
	}
	sport := uint16(held.LocalAddr().(*net.UDPAddr).Port)

	// A socket without shared binding owns the port: fall back to ephemeral.
	conn, granted, err := DialUDP(context.Background(), peer, sport)
	if err != nil || granted || conn.LocalAddr().(*net.UDPAddr).Port == int(sport) {
		t.Fatalf("held port: granted=%v err=%v", granted, err)
	}
	_ = conn.Close()
	_ = held.Close()

	// Free port: granted, and shared by two connections to different peers.
	a, okA, errA := DialUDP(context.Background(), peer, sport)
	b, okB, errB := DialUDP(context.Background(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 9}, sport)
	if errA != nil || errB != nil || !okA || !okB {
		t.Fatalf("shared source port: %v %v %v %v", okA, errA, okB, errB)
	}
	_ = a.Close()
	_ = b.Close()
	// Same address and port as the target: never connect a socket to itself.
	self, granted, err := DialUDP(context.Background(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(sport)}, sport)
	if err != nil || granted || self.LocalAddr().String() == self.RemoteAddr().String() {
		t.Fatalf("self-connection: granted=%v err=%v", granted, err)
	}
	_ = self.Close()
}
