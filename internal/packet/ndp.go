package packet

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

// NeighborSolicitation builds an Ethernet/IPv6/ICMPv6 NS frame. The target
// must be on the selected link; routers do not forward neighbor discovery.
func NeighborSolicitation(sourceMAC net.HardwareAddr, sourceIP, target netip.Addr) ([]byte, error) {
	if len(sourceMAC) != 6 || sourceMAC[0]&1 != 0 || !sourceIP.Is6() || !target.Is6() ||
		sourceIP.IsUnspecified() || target.IsMulticast() {
		return nil, errors.New("NDP requires a unicast Ethernet MAC and IPv6 source/target")
	}
	destination := netip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 0})
	t := target.As16()
	d := destination.As16()
	copy(d[13:16], t[13:16])
	frame := make([]byte, 14+40+32)
	copy(frame[:6], []byte{0x33, 0x33, 0xff, t[13], t[14], t[15]})
	copy(frame[6:12], sourceMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
	ip := frame[14:54]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], 32)
	ip[6], ip[7] = 58, 255
	src := sourceIP.As16()
	copy(ip[8:24], src[:])
	copy(ip[24:40], d[:])
	icmp := frame[54:]
	icmp[0] = 135
	copy(icmp[8:24], t[:])
	icmp[24], icmp[25] = 1, 1 // source link-layer address option
	copy(icmp[26:32], sourceMAC)
	binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(src[:], d[:], icmp))
	return frame, nil
}

// NeighborAdvertisementMAC validates the target address and target link-layer
// option. An advertisement without a MAC option cannot resolve a neighbor.
func NeighborAdvertisementMAC(frame []byte, target, local netip.Addr) (net.HardwareAddr, bool) {
	if len(frame) < 14+40+32 || !target.Is6() || !local.Is6() {
		return nil, false
	}
	offset := 12
	ethType := binary.BigEndian.Uint16(frame[offset : offset+2])
	if ethType == 0x8100 || ethType == 0x88a8 {
		if len(frame) < 14+4+40+32 {
			return nil, false
		}
		offset += 4
		ethType = binary.BigEndian.Uint16(frame[offset : offset+2])
	}
	if ethType != 0x86dd {
		return nil, false
	}
	ip := frame[offset+2:]
	if ip[0]>>4 != 6 || ip[6] != 58 || ip[7] != 255 {
		return nil, false
	}
	length := int(binary.BigEndian.Uint16(ip[4:6]))
	if length < 32 || len(ip) < 40+length {
		return nil, false
	}
	icmp := ip[40 : 40+length]
	t := target.As16()
	l := local.As16()
	if icmp[0] != 136 || icmp[1] != 0 || string(icmp[8:24]) != string(t[:]) ||
		string(ip[8:24]) != string(t[:]) || string(ip[24:40]) != string(l[:]) ||
		icmpv6Checksum(ip[8:24], ip[24:40], icmp) != 0 {
		return nil, false
	}
	for options := icmp[24:]; len(options) >= 2; {
		length := int(options[1]) * 8
		if length == 0 || length > len(options) {
			return nil, false
		}
		if options[0] == 2 && length >= 8 && options[2]&1 == 0 && !isZeroEthernet(options[2:8]) && string(options[2:8]) == string(frame[6:12]) {
			mac := append(net.HardwareAddr(nil), options[2:8]...)
			return mac, true
		}
		options = options[length:]
	}
	return nil, false
}

func icmpv6Checksum(source, destination, message []byte) uint16 {
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
