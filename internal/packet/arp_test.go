package packet

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

func TestARPRequestAndReplyValidation(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.10")
	neighbor := netip.MustParseAddr("192.0.2.1")
	localMAC := net.HardwareAddr{2, 1, 2, 3, 4, 5}
	neighborMAC := net.HardwareAddr{2, 6, 7, 8, 9, 10}
	request, err := ARPRequest(localMAC, local, neighbor)
	if err != nil || len(request) != 42 || request[0] != 0xff || binary.BigEndian.Uint16(request[20:22]) != 1 {
		t.Fatalf("ARP request: %x, %v", request, err)
	}
	if _, ok := ARPReplyMAC(request, neighbor, local); ok {
		t.Fatal("request accepted as reply")
	}
	reply := append([]byte(nil), request...)
	copy(reply[:6], localMAC)
	copy(reply[6:12], neighborMAC)
	binary.BigEndian.PutUint16(reply[20:22], 2)
	copy(reply[22:28], neighborMAC)
	copy(reply[28:32], neighbor.AsSlice())
	copy(reply[32:38], localMAC)
	copy(reply[38:42], local.AsSlice())
	if got, ok := ARPReplyMAC(reply, neighbor, local); !ok || string(got) != string(neighborMAC) {
		t.Fatalf("valid reply rejected: %v, %v", got, ok)
	}
	reply[28] ^= 1
	if _, ok := ARPReplyMAC(reply, neighbor, local); ok {
		t.Fatal("unrelated neighbor accepted")
	}
}
