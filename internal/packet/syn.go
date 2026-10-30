package packet

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

// MaxSYNFrame is the largest frame a SYNTemplate builds: Ethernet, IPv6 and
// a TCP header carrying the 20-byte fingerprint option profile.
const MaxSYNFrame = 94

// SYNTemplate owns one reusable Ethernet/IPv4/TCP or Ethernet/IPv6/TCP frame
// per transmit worker. The Ethernet and invariant IP/TCP fields are set once;
// Frame fills target, destination port, sequence token and checksums without
// allocating.
type SYNTemplate struct {
	frame  [MaxSYNFrame]byte
	length int
	tcp    int // TCP header offset: 34 for IPv4, 54 for IPv6
}

func NewSYNTemplate(srcMAC, dstMAC net.HardwareAddr, source netip.Addr, sourcePort uint16) (*SYNTemplate, error) {
	if len(srcMAC) != 6 || len(dstMAC) != 6 || !source.IsValid() || source.Is4In6() || source.Zone() != "" || sourcePort == 0 {
		return nil, errors.New("SYN template requires Ethernet MACs, an unscoped IPv4 or IPv6 source and source port")
	}
	t := &SYNTemplate{length: 54, tcp: 34}
	b := t.frame[:]
	copy(b[:6], dstMAC)
	copy(b[6:12], srcMAC)
	if source.Is4() {
		binary.BigEndian.PutUint16(b[12:14], 0x0800)
		b[14], b[15] = 0x45, 0
		binary.BigEndian.PutUint16(b[16:18], 40)
		binary.BigEndian.PutUint16(b[20:22], 0x4000) // don't fragment
		b[22], b[23] = 64, 6
		src := source.As4()
		copy(b[26:30], src[:])
	} else {
		// IPv6 has no DF or IP ID; the flow label stays zero.
		t.length, t.tcp = 74, 54
		binary.BigEndian.PutUint16(b[12:14], 0x86dd)
		b[14] = 0x60
		binary.BigEndian.PutUint16(b[18:20], 20)
		b[20], b[21] = 6, 64
		src := source.As16()
		copy(b[22:38], src[:])
	}
	tcp := b[t.tcp:]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	tcp[12], tcp[13] = 0x50, 0x02 // 20-byte header, SYN
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	return t, nil
}

// EnableFingerprint offers MSS, SACK, timestamps and window scaling in a
// fixed native probe profile. ECE+CWR requests RFC 3168 ECN negotiation.
// Ordinary discovery keeps its original option-free SYN. IPv6 advertises the
// MSS of a 1500-byte link after its 40-byte header.
func (t *SYNTemplate) EnableFingerprint() {
	t.length = t.tcp + 40
	b := t.frame[:]
	mss := []byte{5, 180}
	if t.tcp == 34 {
		binary.BigEndian.PutUint16(b[16:18], 60)
	} else {
		binary.BigEndian.PutUint16(b[18:20], 40)
		mss = []byte{5, 160}
	}
	tcp := b[t.tcp:]
	tcp[12], tcp[13] = 0xa0, 0xc2
	copy(tcp[20:], []byte{2, 4, mss[0], mss[1], 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 7})
}

func (t *SYNTemplate) Frame(target netip.Addr, port uint16, seq uint32) []byte {
	b := t.frame[:t.length]
	tcp := b[t.tcp:]
	var pseudo [40]byte
	var header []byte
	if t.tcp == 34 {
		dst := target.As4()
		copy(b[30:34], dst[:])
		binary.BigEndian.PutUint16(b[18:20], uint16(seq))
		binary.BigEndian.PutUint16(b[24:26], 0)
		binary.BigEndian.PutUint16(b[24:26], internetChecksum(b[14:34]))
		copy(pseudo[:8], b[26:34])
		pseudo[9] = 6
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcp)))
		header = pseudo[:12]
	} else {
		dst := target.As16()
		copy(b[38:54], dst[:])
		copy(pseudo[:32], b[22:54])
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(tcp)))
		pseudo[39] = 6
		header = pseudo[:]
	}
	binary.BigEndian.PutUint16(tcp[2:4], port)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	if len(tcp) == 40 {
		binary.BigEndian.PutUint32(tcp[28:32], seq)
	}
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[16:18], foldChecksum(checksumWords(tcp, checksumWords(header, 0))))
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
