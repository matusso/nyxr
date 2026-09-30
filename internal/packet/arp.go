package packet

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

// ARPRequest creates a broadcast Ethernet ARP request for one IPv4 neighbor.
func ARPRequest(sourceMAC net.HardwareAddr, sourceIP, neighbor netip.Addr) ([]byte, error) {
	if len(sourceMAC) != 6 || sourceMAC[0]&1 != 0 || !sourceIP.Is4() || !neighbor.Is4() {
		return nil, errors.New("ARP requires a unicast source MAC and IPv4 addresses")
	}
	frame := make([]byte, 42)
	for i := 0; i < 6; i++ {
		frame[i] = 0xff
	}
	copy(frame[6:12], sourceMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	binary.BigEndian.PutUint16(frame[14:16], 1) // Ethernet
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)
	frame[18], frame[19] = 6, 4
	binary.BigEndian.PutUint16(frame[20:22], 1) // request
	copy(frame[22:28], sourceMAC)
	src, dst := sourceIP.As4(), neighbor.As4()
	copy(frame[28:32], src[:])
	copy(frame[38:42], dst[:])
	return frame, nil
}

// ARPReplyMAC accepts only a reply for the requested neighbor and local IP.
func ARPReplyMAC(frame []byte, neighbor, local netip.Addr) (net.HardwareAddr, bool) {
	if len(frame) < 42 || !neighbor.Is4() || !local.Is4() {
		return nil, false
	}
	offset := 12
	ethType := binary.BigEndian.Uint16(frame[offset : offset+2])
	if ethType == 0x8100 || ethType == 0x88a8 {
		if len(frame) < 46 {
			return nil, false
		}
		offset += 4
		ethType = binary.BigEndian.Uint16(frame[offset : offset+2])
	}
	if ethType != 0x0806 {
		return nil, false
	}
	a := frame[offset+2:]
	if len(a) < 28 || binary.BigEndian.Uint16(a[0:2]) != 1 ||
		binary.BigEndian.Uint16(a[2:4]) != 0x0800 || a[4] != 6 || a[5] != 4 ||
		binary.BigEndian.Uint16(a[6:8]) != 2 {
		return nil, false
	}
	src, dst := neighbor.As4(), local.As4()
	if string(a[14:18]) != string(src[:]) || string(a[24:28]) != string(dst[:]) ||
		string(frame[6:12]) != string(a[8:14]) || string(frame[:6]) != string(a[18:24]) ||
		a[8]&1 != 0 || isZeroEthernet(a[8:14]) {
		return nil, false
	}
	mac := make(net.HardwareAddr, 6)
	copy(mac, a[8:14])
	return mac, true
}

func isZeroEthernet(mac []byte) bool {
	for _, octet := range mac {
		if octet != 0 {
			return false
		}
	}
	return true
}
