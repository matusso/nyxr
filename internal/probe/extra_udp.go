package probe

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"errors"
)

func skipDNSName(packet []byte, start int) (int, bool) {
	for n := 0; n < 128 && start < len(packet); n++ {
		length := int(packet[start])
		start++
		if length == 0 {
			return start, true
		}
		if length&0xc0 == 0xc0 {
			return start + 1, start < len(packet)
		}
		if length > 63 || start+length > len(packet) {
			return 0, false
		}
		start += length
	}
	return 0, false
}

func dnsTXT(packet []byte) (string, bool) {
	if len(packet) < 12 || packet[2]&0x80 == 0 {
		return "", false
	}
	pos := 12
	for i := 0; i < int(binary.BigEndian.Uint16(packet[4:6])); i++ {
		var ok bool
		pos, ok = skipDNSName(packet, pos)
		if !ok || len(packet)-pos < 4 {
			return "", false
		}
		pos += 4
	}
	for i := 0; i < int(binary.BigEndian.Uint16(packet[6:8])); i++ {
		var ok bool
		pos, ok = skipDNSName(packet, pos)
		if !ok || len(packet)-pos < 10 {
			return "", false
		}
		typeCode := binary.BigEndian.Uint16(packet[pos : pos+2])
		length := int(binary.BigEndian.Uint16(packet[pos+8 : pos+10]))
		pos += 10
		if length > len(packet)-pos {
			return "", false
		}
		if typeCode == 16 && length > 1 && int(packet[pos]) <= length-1 && packet[pos] > 0 {
			return string(packet[pos+1 : pos+1+int(packet[pos])]), true
		}
		pos += length
	}
	return "", false
}

// These matchers keep a protocol-shaped reply separate from a socket-scoped
// reply. Some older UDP protocols have no echoed transaction ID; the scanner
// assigns those responses lower confidence.
func extraMatcher(name string) bool {
	switch name {
	case "dns-status", "dhcp", "nbns", "kerberos", "cldap", "radius", "ike", "l2tp",
		"snmpv1", "slp", "ipmi", "citrix", "db2", "source", "quake", "gamespy", "teamspeak":
		return true
	}
	return false
}

func validateExtra(name string, payload []byte) error {
	valid := true
	switch name {
	case "dns-status":
		valid = len(payload) == 12 && payload[2] == 0x10
	case "dhcp":
		valid = len(payload) >= 244 && payload[0] == 1 && bytes.Equal(payload[236:240], []byte{99, 130, 83, 99})
	case "nbns":
		valid = len(payload) >= 50 && binary.BigEndian.Uint16(payload[4:6]) == 1
	case "kerberos":
		valid = len(payload) >= 4 && payload[0] == 0x6a
	case "cldap":
		_, valid = cldapIDOffset(payload)
	case "radius":
		valid = len(payload) == 20 && (payload[0] == 1 || payload[0] == 4) && binary.BigEndian.Uint16(payload[2:4]) == 20
	case "ike":
		valid = len(payload) >= 28 && payload[17] == 0x10 && int(binary.BigEndian.Uint32(payload[24:28])) == len(payload)
	case "l2tp":
		valid = len(payload) >= 12 && payload[0] == 0xc8 && payload[1] == 2 && int(binary.BigEndian.Uint16(payload[2:4])) == len(payload)
	case "snmpv1":
		_, _, valid = snmpRequestIDOffset(payload, 0)
	case "slp":
		valid = len(payload) >= 16 && payload[0] == 2 && payload[1] == 1
	case "ipmi":
		valid = len(payload) == 12 && bytes.Equal(payload[:4], []byte{6, 0, 255, 6}) && payload[8] == 0x80
	case "citrix":
		valid = len(payload) >= 8 && payload[0] == 0x1e
	case "db2":
		valid = bytes.HasPrefix(payload, []byte("DB2GETADDR\x00"))
	case "source":
		valid = bytes.Equal(payload, []byte("\xff\xff\xff\xffTSourceEngineQuery\x00"))
	case "quake":
		valid = bytes.HasPrefix(payload, []byte("\xff\xff\xff\xffgetstatus"))
	case "gamespy":
		valid = bytes.Equal(payload, []byte("\\status\\"))
	case "teamspeak":
		valid = bytes.HasPrefix(payload, []byte("TS3INIT1\x00"))
	}
	if !valid {
		return errors.New("invalid payload for UDP matcher " + name)
	}
	return nil
}

func prepareExtra(name string, payload []byte, token uint64) {
	switch name {
	case "dns-status", "nbns", "slp":
		if name == "slp" {
			binary.BigEndian.PutUint16(payload[10:12], uint16(token))
		} else {
			binary.BigEndian.PutUint16(payload[:2], uint16(token))
		}
	case "dhcp":
		binary.BigEndian.PutUint32(payload[4:8], uint32(token))
	case "cldap":
		if pos, ok := cldapIDOffset(payload); ok {
			payload[pos] = byte(token%127 + 1)
		}
	case "radius":
		payload[1] = byte(token)
		binary.BigEndian.PutUint64(payload[4:12], token)
		binary.BigEndian.PutUint64(payload[12:20], token^0xa5a5a5a5a5a5a5a5)
	case "ike":
		binary.BigEndian.PutUint64(payload[:8], token)
	case "snmpv1":
		if offset, _, ok := snmpRequestIDOffset(payload, 0); ok {
			binary.BigEndian.PutUint32(payload[offset:offset+4], uint32(token)&0x7fffffff)
		}
	case "ipmi":
		payload[9] = byte(token)
	}
}

func matchExtra(name string, request, response []byte) bool {
	switch name {
	case "dns-status", "nbns":
		return len(response) >= 12 && response[2]&0x80 != 0 && bytes.Equal(request[:2], response[:2]) &&
			((name == "dns-status" && response[2]&0x78 == 0x10) ||
				(name == "nbns" && len(response) >= len(request) && bytes.Equal(request[12:], response[12:len(request)])))
	case "dhcp":
		return len(response) >= 240 && response[0] == 2 && bytes.Equal(request[4:8], response[4:8]) &&
			bytes.Equal(request[28:44], response[28:44]) &&
			bytes.Equal(response[236:240], []byte{99, 130, 83, 99})
	case "kerberos":
		var reply asn1.RawValue
		rest, err := asn1.Unmarshal(response, &reply)
		return err == nil && len(rest) == 0 && reply.Class == 1 && (reply.Tag == 11 || reply.Tag == 30)
	case "cldap":
		pos, ok := cldapIDOffset(request)
		if !ok {
			return false
		}
		_, matched := cldapReply(response, int(request[pos]))
		return matched
	case "radius":
		validCode := (request[0] == 1 && (response[0] == 2 || response[0] == 3 || response[0] == 11)) ||
			(request[0] == 4 && response[0] == 5)
		return len(response) >= 20 && validCode &&
			response[1] == request[1] && int(binary.BigEndian.Uint16(response[2:4])) == len(response)
	case "ike":
		return len(response) >= 28 && bytes.Equal(response[:8], request[:8]) &&
			response[17]>>4 == 1 && int(binary.BigEndian.Uint32(response[24:28])) == len(response)
	case "l2tp":
		return len(response) >= 20 && response[0]&0x80 != 0 && response[1]&15 == 2 &&
			int(binary.BigEndian.Uint16(response[2:4])) == len(response) &&
			bytes.Equal(response[12:18], []byte{0x80, 8, 0, 0, 0, 0}) &&
			binary.BigEndian.Uint16(response[18:20]) == 2
	case "snmpv1":
		return matchSNMPVersion(request, response, 0)
	case "slp":
		return len(response) >= 16 && response[0] == 2 && (response[1] == 2 || response[1] == 11) &&
			bytes.Equal(request[10:12], response[10:12])
	case "ipmi":
		return len(response) >= 12 && bytes.Equal(response[:4], request[:4]) && response[8] == 0x40 && response[9] == request[9]
	case "citrix":
		return len(response) >= 12 && bytes.Equal(response[:8], []byte{0x30, 0, 2, 0x31, 2, 0xfd, 0xa8, 0xe3})
	case "db2":
		return bytes.HasPrefix(response, []byte("DB2RETADDR\x00"))
	case "source":
		return len(response) >= 6 && bytes.Equal(response[:4], []byte{255, 255, 255, 255}) &&
			(response[4] == 'I' || response[4] == 'm' || response[4] == 'A')
	case "quake":
		return bytes.HasPrefix(response, []byte("\xff\xff\xff\xffstatusResponse"))
	case "gamespy":
		return bytes.Contains(response, []byte("\\hostname\\")) || bytes.HasPrefix(response, []byte("\\final\\"))
	case "teamspeak":
		return len(response) >= 16 && (bytes.HasPrefix(response, []byte("TS3INIT1")) ||
			(bytes.Equal(response[8:11], []byte{0, 0, 2}) && (response[11] == 0x97 || response[11] == 0x9b)))
	}
	return false
}
