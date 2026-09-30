package packet

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

func TestNeighborSolicitationAndAdvertisement(t *testing.T) {
	local := netip.MustParseAddr("2001:db8:1::10")
	target := netip.MustParseAddr("2001:db8:1::20")
	localMAC := net.HardwareAddr{2, 1, 2, 3, 4, 5}
	targetMAC := net.HardwareAddr{2, 6, 7, 8, 9, 10}
	request, err := NeighborSolicitation(localMAC, local, target)
	if err != nil || len(request) != 86 || request[54] != 135 || request[21] != 255 ||
		icmpv6Checksum(request[22:38], request[38:54], request[54:]) != 0 {
		t.Fatalf("NDP request: %x, %v", request, err)
	}
	reply := append([]byte(nil), request...)
	copy(reply[:6], localMAC)
	copy(reply[6:12], targetMAC)
	copy(reply[22:38], target.AsSlice())
	copy(reply[38:54], local.AsSlice())
	reply[54], reply[55] = 136, 0
	copy(reply[62:78], target.AsSlice())
	reply[78], reply[79] = 2, 1
	copy(reply[80:86], targetMAC)
	reply[56], reply[57] = 0, 0
	binary.BigEndian.PutUint16(reply[56:58], icmpv6Checksum(reply[22:38], reply[38:54], reply[54:]))
	if got, ok := NeighborAdvertisementMAC(reply, target, local); !ok || string(got) != string(targetMAC) {
		t.Fatalf("valid NDP advertisement rejected: %v, %v", got, ok)
	}
	reply[81] ^= 1
	if _, ok := NeighborAdvertisementMAC(reply, target, local); ok {
		t.Fatal("malformed advertisement accepted")
	}
}
