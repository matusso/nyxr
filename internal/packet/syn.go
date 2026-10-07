package packet

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

// SYNTemplate owns one reusable Ethernet/IPv4/TCP frame per transmit worker.
// The Ethernet and invariant IP/TCP fields are set once; Frame fills target,
// destination port, sequence token and checksums without allocating.
type SYNTemplate struct {
	frame  [74]byte
	length int
}

func NewSYNTemplate(srcMAC, dstMAC net.HardwareAddr, source netip.Addr, sourcePort uint16) (*SYNTemplate, error) {
	if len(srcMAC) != 6 || len(dstMAC) != 6 || !source.Is4() || sourcePort == 0 {
		return nil, errors.New("SYN template requires Ethernet MACs, IPv4 source and source port")
	}
	t := &SYNTemplate{length: 54}
	b := t.frame[:]
	copy(b[:6], dstMAC)
	copy(b[6:12], srcMAC)
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	b[14], b[15] = 0x45, 0
	binary.BigEndian.PutUint16(b[16:18], 40)
	binary.BigEndian.PutUint16(b[20:22], 0x4000) // don't fragment
	b[22], b[23] = 64, 6
	src := source.As4()
	copy(b[26:30], src[:])
	binary.BigEndian.PutUint16(b[34:36], sourcePort)
	b[46], b[47] = 0x50, 0x02 // 20-byte header, SYN
	binary.BigEndian.PutUint16(b[48:50], 64240)
	return t, nil
}

// EnableFingerprint offers MSS, SACK, timestamps and window scaling in a
// fixed native probe profile. ECE+CWR requests RFC 3168 ECN negotiation.
// Ordinary discovery keeps its original option-free SYN.
func (t *SYNTemplate) EnableFingerprint() {
	t.length = 74
	b := t.frame[:]
	binary.BigEndian.PutUint16(b[16:18], 60)
	b[46], b[47] = 0xa0, 0xc2
	copy(b[54:], []byte{2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 7})
}

func (t *SYNTemplate) Frame(target netip.Addr, port uint16, seq uint32) []byte {
	b := t.frame[:t.length]
	dst := target.As4()
	copy(b[30:34], dst[:])
	binary.BigEndian.PutUint16(b[18:20], uint16(seq))
	binary.BigEndian.PutUint16(b[36:38], port)
	binary.BigEndian.PutUint32(b[38:42], seq)
	if t.length == 74 {
		binary.BigEndian.PutUint32(b[62:66], seq)
	}
	binary.BigEndian.PutUint16(b[24:26], 0)
	binary.BigEndian.PutUint16(b[24:26], internetChecksum(b[14:34]))
	binary.BigEndian.PutUint16(b[50:52], 0)
	var pseudo [12]byte
	copy(pseudo[:8], b[26:34])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(t.length-34))
	sum := checksumWords(pseudo[:], 0)
	sum = checksumWords(b[34:], sum)
	binary.BigEndian.PutUint16(b[50:52], foldChecksum(sum))
	return b
}

// SetDestination changes the destination Ethernet address for the next frame.
// Each TX worker owns its template, so no synchronization is required.
func (t *SYNTemplate) SetDestination(mac net.HardwareAddr) error {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return errors.New("SYN destination requires a unicast Ethernet MAC")
	}
	copy(t.frame[:6], mac)
	return nil
}

func checksumWords(b []byte, sum uint32) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) != 0 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

func foldChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}

func internetChecksum(b []byte) uint16 { return foldChecksum(checksumWords(b, 0)) }
