package scan

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/packet"
)

func TestARPNeighborMatchesReply(t *testing.T) {
	local, target := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20")
	localMAC := net.HardwareAddr{2, 1, 2, 3, 4, 5}
	targetMAC := net.HardwareAddr{2, 6, 7, 8, 9, 10}
	request, err := packet.ARPRequest(localMAC, local, target)
	if err != nil {
		t.Fatal(err)
	}
	reply := append([]byte(nil), request...)
	copy(reply[:6], localMAC)
	copy(reply[6:12], targetMAC)
	binary.BigEndian.PutUint16(reply[20:22], 2)
	copy(reply[22:28], targetMAC)
	copy(reply[28:32], target.AsSlice())
	copy(reply[32:38], localMAC)
	copy(reply[38:42], local.AsSlice())
	fake := &fakePacketIO{frames: make(chan []byte, 2)}
	fake.frames <- request // outbound request must be ignored
	fake.frames <- reply
	got, err := arpNeighbor(context.Background(), fake, localMAC, local, target, 100*time.Millisecond)
	if err != nil || string(got) != string(targetMAC) || fake.sent != 1 {
		t.Fatalf("ARP result: %v, sent %d, %v", got, fake.sent, err)
	}
}

func TestNDPNeighborMatchesReply(t *testing.T) {
	local, target := netip.MustParseAddr("2001:db8:1::10"), netip.MustParseAddr("2001:db8:1::20")
	localMAC := net.HardwareAddr{2, 1, 2, 3, 4, 5}
	targetMAC := net.HardwareAddr{2, 6, 7, 8, 9, 10}
	request, err := packet.NeighborSolicitation(localMAC, local, target)
	if err != nil {
		t.Fatal(err)
	}
	reply := append([]byte(nil), request...)
	copy(reply[:6], localMAC)
	copy(reply[6:12], targetMAC)
	copy(reply[22:38], target.AsSlice())
	copy(reply[38:54], local.AsSlice())
	reply[54] = 136
	reply[78], reply[79] = 2, 1
	copy(reply[80:86], targetMAC)
	reply[56], reply[57] = 0, 0
	binary.BigEndian.PutUint16(reply[56:58], testICMPv6Checksum(reply[22:38], reply[38:54], reply[54:]))
	fake := &fakePacketIO{frames: make(chan []byte, 2)}
	fake.frames <- request
	fake.frames <- reply
	got, err := ndpNeighbor(context.Background(), fake, localMAC, local, target, 100*time.Millisecond)
	if err != nil || string(got) != string(targetMAC) || fake.sent != 1 {
		t.Fatalf("NDP result: %v, sent %d, %v", got, fake.sent, err)
	}
}

func testICMPv6Checksum(source, destination, message []byte) uint16 {
	var pseudo [40]byte
	copy(pseudo[:16], source)
	copy(pseudo[16:32], destination)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(message)))
	pseudo[39] = 58
	var sum uint32
	for _, data := range [][]byte{pseudo[:], message} {
		for len(data) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
		}
		if len(data) == 1 {
			sum += uint32(data[0]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}
