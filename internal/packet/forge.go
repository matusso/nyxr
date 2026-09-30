package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"net/netip"
)

// ForgeSpec describes one Ethernet/IP datagram. A nil checksum or length
// override means that the corresponding field is calculated.
// Deliberately invalid values require Malformed and are guarded by config.
type ForgeSpec struct {
	SourceMAC, DestinationMAC net.HardwareAddr
	VLANTags                  []VLANTag
	SourceIP, DestinationIP   netip.Addr
	Protocol                  uint8
	RawProtocol               bool // bypass structured transport encoding for IP protocol experiments
	SourcePort, DestPort      uint16
	TCPFlags                  uint8
	TCPOptions                []byte
	Sequence                  uint32
	Window                    uint16
	Payload                   []byte
	HopLimit                  uint8
	DSCP                      uint8
	ID                        uint32
	DontFragment              bool
	FragmentSize              int // IP payload bytes per fragment; multiple of eight
	IPv4Options               []byte
	IPv6Extensions            []IPv6Extension
	TransportChecksum         *uint16
	CorruptChecksum           bool
	IPChecksum                *uint16
	IPLengthOverride          *uint16
	UDPLengthOverride         *uint16
	Malformed                 bool
	Experiment                bool // required for arbitrary flags, raw protocols or fragments
}

type VLANTag struct {
	ID           uint16
	Priority     uint8
	DropEligible bool
}

// IPv6Extension permits bounded hop-by-hop (0), routing (43), and destination
// (60) headers. Data is the body after the two-byte next/length prefix.
type IPv6Extension struct {
	Type uint8
	Data []byte
}

// ForgeFrames returns complete Ethernet frames. Each frame owns its bytes.
// IPv4 fragments are emitted in offset order; IPv6 uses a fragment header.
func ForgeFrames(s ForgeSpec) ([][]byte, error) {
	if len(s.SourceMAC) != 6 || len(s.DestinationMAC) != 6 || s.SourceMAC[0]&1 != 0 || s.DestinationMAC[0]&1 != 0 || isZeroHardware(s.SourceMAC) || isZeroHardware(s.DestinationMAC) {
		return nil, errors.New("forge requires unicast Ethernet MAC addresses")
	}
	if !s.SourceIP.IsValid() || !s.DestinationIP.IsValid() || s.SourceIP.Is4() != s.DestinationIP.Is4() || s.SourceIP.IsUnspecified() || s.SourceIP.IsMulticast() || s.DestinationIP.IsUnspecified() || s.DestinationIP.IsMulticast() {
		return nil, errors.New("forge requires unicast IP addresses of the same family")
	}
	if s.HopLimit == 0 || s.DSCP > 63 || len(s.Payload) > 65507 {
		return nil, errors.New("forge hop limit, DSCP or payload is out of range")
	}
	if s.FragmentSize != 0 && (s.FragmentSize < 8 || s.FragmentSize%8 != 0 || s.DontFragment) {
		return nil, errors.New("fragment size must be a multiple of eight and cannot use don't-fragment")
	}
	if (s.FragmentSize != 0 || s.RawProtocol || (s.Protocol == 6 && s.TCPFlags != 2) || s.Malformed) && !s.Experiment {
		return nil, errors.New("experimental packet controls require research mode")
	}
	if len(s.IPv4Options) > 40 || len(s.IPv4Options)%4 != 0 || (len(s.IPv4Options) != 0 && !s.SourceIP.Is4()) {
		return nil, errors.New("IPv4 options must be at most 40 bytes and four-byte aligned")
	}
	if !s.Malformed && (!validIPOptions(s.IPv4Options) || !validIPOptions(s.TCPOptions)) {
		return nil, errors.New("malformed IP/TCP options require explicit malformed mode")
	}
	if len(s.IPv4Options) != 0 && s.FragmentSize != 0 && !s.Malformed {
		return nil, errors.New("IPv4 options with fragmentation require explicit malformed mode")
	}
	if len(s.IPv6Extensions) != 0 && s.SourceIP.Is4() {
		return nil, errors.New("IPv6 extensions require IPv6 addresses")
	}
	if len(s.VLANTags) > 2 {
		return nil, errors.New("forge supports at most two VLAN tags")
	}
	for _, tag := range s.VLANTags {
		if tag.ID > 4094 || tag.Priority > 7 {
			return nil, errors.New("invalid VLAN tag")
		}
	}
	if len(s.TCPOptions) > 40 || len(s.TCPOptions)%4 != 0 {
		return nil, errors.New("TCP options must be at most 40 bytes and four-byte aligned")
	}
	if len(s.TCPOptions) != 0 && (s.Protocol != 6 || s.RawProtocol) {
		return nil, errors.New("TCP options require a structured TCP packet")
	}
	if (s.IPChecksum != nil && !s.SourceIP.Is4()) || ((s.TransportChecksum != nil || s.CorruptChecksum || s.IPChecksum != nil || s.IPLengthOverride != nil || s.UDPLengthOverride != nil) && !s.Malformed) {
		return nil, errors.New("checksum and length overrides require malformed mode")
	}
	if s.TransportChecksum != nil && s.CorruptChecksum {
		return nil, errors.New("choose one transport checksum override")
	}
	if s.UDPLengthOverride != nil && s.Protocol != 17 {
		return nil, errors.New("UDP length override requires UDP")
	}
	transport, err := forgeTransport(s)
	if err != nil {
		return nil, err
	}
	if s.SourceIP.Is4() {
		return forgeIPv4(s, transport)
	}
	return forgeIPv6(s, transport)
}

func forgeTransport(s ForgeSpec) ([]byte, error) {
	if s.RawProtocol {
		if s.TransportChecksum != nil || s.CorruptChecksum || s.UDPLengthOverride != nil || s.SourcePort != 0 || s.DestPort != 0 {
			return nil, errors.New("raw IP protocol payload has no transport fields")
		}
		return append([]byte(nil), s.Payload...), nil
	}
	var b []byte
	switch s.Protocol {
	case 6: // TCP
		if s.SourcePort == 0 || s.DestPort == 0 || s.TCPFlags&0xc0 != 0 {
			return nil, errors.New("TCP forge requires ports and valid eight-bit flags")
		}
		b = make([]byte, 20+len(s.TCPOptions)+len(s.Payload))
		binary.BigEndian.PutUint16(b[0:2], s.SourcePort)
		binary.BigEndian.PutUint16(b[2:4], s.DestPort)
		binary.BigEndian.PutUint32(b[4:8], s.Sequence)
		b[12], b[13] = byte((20+len(s.TCPOptions))/4)<<4, s.TCPFlags
		binary.BigEndian.PutUint16(b[14:16], s.Window)
		copy(b[20:], s.TCPOptions)
		copy(b[20+len(s.TCPOptions):], s.Payload)
	case 17: // UDP
		if s.SourcePort == 0 || s.DestPort == 0 || len(s.Payload) > 65507 {
			return nil, errors.New("UDP forge requires ports and a bounded payload")
		}
		b = make([]byte, 8+len(s.Payload))
		binary.BigEndian.PutUint16(b[0:2], s.SourcePort)
		binary.BigEndian.PutUint16(b[2:4], s.DestPort)
		binary.BigEndian.PutUint16(b[4:6], uint16(len(b)))
		if s.UDPLengthOverride != nil {
			binary.BigEndian.PutUint16(b[4:6], *s.UDPLengthOverride)
		}
		copy(b[8:], s.Payload)
	case 1, 58: // ICMPv4/v6: caller supplies type, code, rest of header and body.
		if len(s.Payload) < 8 || (s.Protocol == 1) != s.SourceIP.Is4() {
			return nil, errors.New("ICMP forge requires a matching IP family and at least eight header bytes")
		}
		b = append([]byte(nil), s.Payload...)
		b[2], b[3] = 0, 0
	case 132: // SCTP INIT; the initiation tag is the per-probe token.
		if s.SourcePort == 0 || s.DestPort == 0 || len(s.Payload) != 0 {
			return nil, errors.New("SCTP INIT requires ports and no custom payload")
		}
		b = make([]byte, 32)
		binary.BigEndian.PutUint16(b[0:2], s.SourcePort)
		binary.BigEndian.PutUint16(b[2:4], s.DestPort)
		b[12] = 1 // INIT
		binary.BigEndian.PutUint16(b[14:16], 20)
		binary.BigEndian.PutUint32(b[16:20], s.Sequence)
		binary.BigEndian.PutUint32(b[20:24], 65535)
		binary.BigEndian.PutUint16(b[24:26], 1)
		binary.BigEndian.PutUint16(b[26:28], 1)
		binary.BigEndian.PutUint32(b[28:32], s.Sequence^0xa5a5a5a5)
		binary.LittleEndian.PutUint32(b[8:12], sctpCRC(b))
	default:
		if s.Protocol == 0 || s.Protocol == 44 || s.Protocol == 50 || s.Protocol == 51 {
			return nil, fmt.Errorf("IP protocol %d needs a structured header and is not forgeable as raw payload", s.Protocol)
		}
		b = append([]byte(nil), s.Payload...)
	}
	if s.Protocol == 6 || s.Protocol == 17 || s.Protocol == 1 || s.Protocol == 58 {
		var at int
		switch s.Protocol {
		case 6:
			at = 16
		case 17:
			at = 6
		default:
			at = 2
		}
		checksum := transportChecksum(s, b)
		if s.TransportChecksum != nil {
			checksum = *s.TransportChecksum
		}
		if s.CorruptChecksum {
			checksum ^= 1
			if s.Protocol == 17 && checksum == 0 {
				checksum = 2
			}
		}
		binary.BigEndian.PutUint16(b[at:at+2], checksum)
	}
	return b, nil
}

func transportChecksum(s ForgeSpec, b []byte) uint16 {
	var sum uint32
	if s.Protocol != 1 {
		if s.SourceIP.Is4() {
			var pseudo [12]byte
			a, z := s.SourceIP.As4(), s.DestinationIP.As4()
			copy(pseudo[:4], a[:])
			copy(pseudo[4:8], z[:])
			pseudo[9] = s.Protocol
			binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(b)))
			sum = checksumWords(pseudo[:], 0)
		} else {
			var pseudo [40]byte
			a, z := s.SourceIP.As16(), s.DestinationIP.As16()
			copy(pseudo[:16], a[:])
			copy(pseudo[16:32], z[:])
			binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(b)))
			pseudo[39] = s.Protocol
			sum = checksumWords(pseudo[:], 0)
		}
	}
	c := foldChecksum(checksumWords(b, sum))
	if s.Protocol == 17 && c == 0 {
		return 0xffff
	}
	return c
}

func forgeIPv4(s ForgeSpec, transport []byte) ([][]byte, error) {
	hlen := 20 + len(s.IPv4Options)
	if hlen+len(transport) > 65535 {
		return nil, errors.New("IPv4 datagram exceeds 65535 bytes")
	}
	chunk := len(transport)
	if s.FragmentSize > 0 && s.FragmentSize < chunk {
		chunk = s.FragmentSize
	}
	frames := make([][]byte, 0, (len(transport)+max(1, chunk)-1)/max(1, chunk))
	for offset := 0; offset < len(transport) || (len(transport) == 0 && offset == 0); offset += max(1, chunk) {
		end := min(offset+chunk, len(transport))
		ethernetLen := 14 + 4*len(s.VLANTags)
		frame := make([]byte, ethernetLen+hlen+end-offset)
		writeEthernet(frame, s, 0x0800)
		ip := frame[ethernetLen:]
		ip[0], ip[1] = 0x40|byte(hlen/4), s.DSCP<<2
		length := uint16(hlen + end - offset)
		if s.IPLengthOverride != nil {
			length = *s.IPLengthOverride
		}
		binary.BigEndian.PutUint16(ip[2:4], length)
		binary.BigEndian.PutUint16(ip[4:6], uint16(s.ID))
		flags := uint16(offset / 8)
		if end < len(transport) {
			flags |= 0x2000
		}
		if s.DontFragment {
			flags |= 0x4000
		}
		binary.BigEndian.PutUint16(ip[6:8], flags)
		ip[8], ip[9] = s.HopLimit, s.Protocol
		a, z := s.SourceIP.As4(), s.DestinationIP.As4()
		copy(ip[12:16], a[:])
		copy(ip[16:20], z[:])
		copy(ip[20:hlen], s.IPv4Options)
		copy(ip[hlen:], transport[offset:end])
		c := internetChecksum(ip[:hlen])
		if s.IPChecksum != nil {
			c = *s.IPChecksum
		}
		binary.BigEndian.PutUint16(ip[10:12], c)
		frames = append(frames, frame)
		if end == len(transport) {
			break
		}
	}
	return frames, nil
}

func forgeIPv6(s ForgeSpec, transport []byte) ([][]byte, error) {
	ext := make([]byte, 0, 64)
	for _, h := range s.IPv6Extensions {
		if h.Type != 0 && h.Type != 43 && h.Type != 60 || len(h.Data) > 2046 || (len(h.Data)+2)%8 != 0 || len(ext)+len(h.Data)+2 > 256 {
			return nil, errors.New("IPv6 extensions must be bounded, supported and eight-byte aligned")
		}
		ext = append(ext, 0, byte((len(h.Data)+2)/8-1))
		ext = append(ext, h.Data...)
	}
	if len(ext)+len(transport) > 65535 {
		return nil, errors.New("IPv6 payload exceeds 65535 bytes")
	}
	fragment := s.FragmentSize > 0 && s.FragmentSize < len(transport)
	if fragment && s.ID == 0 {
		return nil, errors.New("IPv6 fragmentation requires a nonzero identification")
	}
	chunk := len(transport)
	if fragment {
		chunk = s.FragmentSize
	}
	frames := make([][]byte, 0, (len(transport)+max(1, chunk)-1)/max(1, chunk))
	for offset := 0; offset < len(transport) || (len(transport) == 0 && offset == 0); offset += max(1, chunk) {
		end := min(offset+chunk, len(transport))
		fragLen := 0
		if fragment {
			fragLen = 8
		}
		ethernetLen := 14 + 4*len(s.VLANTags)
		frame := make([]byte, ethernetLen+40+len(ext)+fragLen+end-offset)
		writeEthernet(frame, s, 0x86dd)
		ip := frame[ethernetLen:]
		trafficClass := s.DSCP << 2
		ip[0] = 0x60 | trafficClass>>4
		flowLabel := s.ID & 0xfffff
		ip[1] = trafficClass<<4 | byte(flowLabel>>16)
		ip[2], ip[3] = byte(flowLabel>>8), byte(flowLabel)
		length := uint16(len(ext) + fragLen + end - offset)
		if s.IPLengthOverride != nil {
			length = *s.IPLengthOverride
		}
		binary.BigEndian.PutUint16(ip[4:6], length)
		ip[6], ip[7] = s.Protocol, s.HopLimit
		if len(s.IPv6Extensions) != 0 {
			ip[6] = s.IPv6Extensions[0].Type
		}
		if fragment && len(s.IPv6Extensions) == 0 {
			ip[6] = 44
		}
		a, z := s.SourceIP.As16(), s.DestinationIP.As16()
		copy(ip[8:24], a[:])
		copy(ip[24:40], z[:])
		copy(ip[40:], ext)
		for i := range s.IPv6Extensions {
			at := 40
			for j := 0; j < i; j++ {
				at += len(s.IPv6Extensions[j].Data) + 2
			}
			next := s.Protocol
			if i+1 < len(s.IPv6Extensions) {
				next = s.IPv6Extensions[i+1].Type
			} else if fragment {
				next = 44
			}
			ip[at] = next
		}
		at := 40 + len(ext)
		if fragment {
			ip[at] = s.Protocol
			bits := uint16(offset/8) << 3
			if end < len(transport) {
				bits |= 1
			}
			binary.BigEndian.PutUint16(ip[at+2:at+4], bits)
			binary.BigEndian.PutUint32(ip[at+4:at+8], s.ID)
			at += 8
		}
		copy(ip[at:], transport[offset:end])
		frames = append(frames, frame)
		if end == len(transport) {
			break
		}
	}
	return frames, nil
}

func sctpCRC(b []byte) uint32 {
	return crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))
}

func validSCTPCRC(b []byte) bool {
	if len(b) < 12 {
		return false
	}
	table := crc32.MakeTable(crc32.Castagnoli)
	c := crc32.Update(0, table, b[:8])
	c = crc32.Update(c, table, []byte{0, 0, 0, 0})
	c = crc32.Update(c, table, b[12:])
	return binary.LittleEndian.Uint32(b[8:12]) == c
}

func writeEthernet(frame []byte, s ForgeSpec, innerType uint16) {
	copy(frame[:6], s.DestinationMAC)
	copy(frame[6:12], s.SourceMAC)
	if len(s.VLANTags) == 0 {
		binary.BigEndian.PutUint16(frame[12:14], innerType)
		return
	}
	for i, tag := range s.VLANTags {
		at := 12 + 4*i
		outer := uint16(0x8100)
		if i == 0 && len(s.VLANTags) == 2 {
			outer = 0x88a8
		}
		binary.BigEndian.PutUint16(frame[at:at+2], outer)
		control := tag.ID | uint16(tag.Priority)<<13
		if tag.DropEligible {
			control |= 0x1000
		}
		binary.BigEndian.PutUint16(frame[at+2:at+4], control)
	}
	binary.BigEndian.PutUint16(frame[12+4*len(s.VLANTags):14+4*len(s.VLANTags)], innerType)
}

func isZeroHardware(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func validIPOptions(b []byte) bool {
	for at := 0; at < len(b); {
		switch b[at] {
		case 0:
			for _, pad := range b[at:] {
				if pad != 0 {
					return false
				}
			}
			return true
		case 1:
			at++
		default:
			if at+2 > len(b) {
				return false
			}
			length := int(b[at+1])
			if length < 2 || at+length > len(b) {
				return false
			}
			at += length
		}
	}
	return true
}
