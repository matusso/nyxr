package probe

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// BACnetProperty is a read-only Device property used after BACnet discovery.
type BACnetProperty struct {
	ID    byte
	Field string
}

var BACnetDeviceProperties = []BACnetProperty{
	{77, "bacnet.object_name"},
	{121, "bacnet.vendor_name"},
	{120, "bacnet.vendor_id"},
	{12, "bacnet.application_software"},
	{44, "bacnet.firmware"},
	{70, "bacnet.model_name"},
	{28, "bacnet.description"},
	{58, "bacnet.location"},
}

// BACnetReadPropertyRequest reads a scalar property of the Device object.
// The wildcard Device instance is accepted by devices that answer before
// their instance number is known, including the controller in the report.
func BACnetReadPropertyRequest(property, invoke byte) []byte {
	return []byte{0x81, 0x0a, 0, 17, 1, 4, 0, 5, invoke, 12,
		12, 2, 0x3f, 0xff, 0xff, 0x19, property}
}

func BACnetFDTRequest() []byte { return []byte{0x81, 0x06, 0, 4} }

// BACnetPropertyValue accepts only an unsegmented ReadProperty Complex-ACK
// matching this request's invoke ID and property ID. Error replies yield no
// value; they still proved the endpoint open during discovery.
func BACnetPropertyValue(request, response []byte) (string, bool) {
	if len(request) != 17 || len(response) < 20 || response[0] != 0x81 || response[1] != 0x0a ||
		int(binary.BigEndian.Uint16(response[2:4])) != len(response) ||
		response[4] != 1 || response[5] != 0 || response[6] != 0x30 ||
		response[7] != request[8] || response[8] != 12 || response[9] != 12 ||
		binary.BigEndian.Uint32(response[10:14])>>22 != 8 ||
		response[14] != 0x19 || response[15] != request[16] || response[16] != 0x3e ||
		response[len(response)-1] != 0x3f {
		return "", false
	}
	value := response[17 : len(response)-1]
	if request[16] == 120 { // Vendor_Identifier is an Unsigned.
		if len(value) < 2 || value[0]>>4 != 2 || value[0]&8 != 0 ||
			int(value[0]&7) != len(value)-1 || len(value) > 5 {
			return "", false
		}
		var id uint32
		for _, octet := range value[1:] {
			id = id<<8 | uint32(octet)
		}
		return strconv.FormatUint(uint64(id), 10), true
	}
	return bacnetCharacterString(value)
}

func bacnetCharacterString(value []byte) (string, bool) {
	if len(value) < 2 || value[0]>>4 != 7 || value[0]&8 != 0 {
		return "", false
	}
	length := int(value[0] & 7)
	pos := 1
	if length == 5 {
		if pos >= len(value) {
			return "", false
		}
		length = int(value[pos])
		pos++
		switch length {
		case 254:
			if len(value)-pos < 2 {
				return "", false
			}
			length = int(binary.BigEndian.Uint16(value[pos : pos+2]))
			pos += 2
		case 255:
			if len(value)-pos < 4 {
				return "", false
			}
			length32 := binary.BigEndian.Uint32(value[pos : pos+4])
			if length32 > 4096 {
				return "", false
			}
			length = int(length32)
			pos += 4
		}
	}
	if length < 1 || length != len(value)-pos {
		return "", false
	}
	charset, raw := value[pos], value[pos+1:]
	var result string
	switch charset {
	case 0: // ISO 10646 UTF-8 (historically ANSI X3.4).
		if !utf8.Valid(raw) {
			return "", false
		}
		result = string(raw)
	case 4: // UCS-2, network byte order.
		if len(raw)%2 != 0 {
			return "", false
		}
		units := make([]uint16, len(raw)/2)
		for i := range units {
			units[i] = binary.BigEndian.Uint16(raw[i*2 : i*2+2])
		}
		result = string(utf16.Decode(units))
	case 5: // ISO 8859-1.
		runes := make([]rune, len(raw))
		for i, octet := range raw {
			runes[i] = rune(octet)
		}
		result = string(runes)
	default:
		return "", false
	}
	result = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, result)
	result = strings.TrimSpace(result)
	return result, result != ""
}

// BACnetFDTFields formats a valid BBMD table into bounded observation fields.
func BACnetFDTFields(response []byte) map[string]string {
	if !validBACnetFDT(response) {
		return nil
	}
	count := (len(response) - 4) / 10
	fields := map[string]string{"bacnet.fdt_entries": strconv.Itoa(count)}
	for i := 0; i < count && i < 32; i++ {
		entry := response[4+i*10 : 14+i*10]
		fields[fmt.Sprintf("bacnet.fdt.%d", i)] = fmt.Sprintf("%d.%d.%d.%d:%d:ttl=%d:timeout=%d",
			entry[0], entry[1], entry[2], entry[3], binary.BigEndian.Uint16(entry[4:6]),
			binary.BigEndian.Uint16(entry[6:8]), binary.BigEndian.Uint16(entry[8:10]))
	}
	return fields
}
