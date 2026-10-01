package probe

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func bacnetPropertyACK(request, value []byte) []byte {
	response := []byte{0x81, 0x0a, 0, 0, 1, 0, 0x30, request[8], 12,
		12, 2, 0x20, 8, 1, 0x19, request[16], 0x3e}
	response = append(response, value...)
	response = append(response, 0x3f)
	binary.BigEndian.PutUint16(response[2:4], uint16(len(response)))
	return response
}

func bacnetStringValue(charset byte, value string) []byte {
	length := len(value) + 1
	result := []byte{0x75, byte(length), charset}
	return append(result, value...)
}

func TestBACnetPropertyValue(t *testing.T) {
	request := BACnetReadPropertyRequest(77, 0x80)
	response := bacnetPropertyACK(request, bacnetStringValue(0, "Site01'PkMajer"))
	if got, ok := BACnetPropertyValue(request, response); !ok || got != "Site01'PkMajer" {
		t.Fatalf("object name = %q, %v", got, ok)
	}
	response[7] ^= 1
	if _, ok := BACnetPropertyValue(request, response); ok {
		t.Fatal("accepted another invoke ID")
	}
	response[7] ^= 1
	response[15] = 0x79
	if _, ok := BACnetPropertyValue(request, response); ok {
		t.Fatal("accepted another property")
	}
	response[15] = 77
	response[18]++
	if _, ok := BACnetPropertyValue(request, response); ok {
		t.Fatal("accepted malformed string length")
	}

	vendor := BACnetReadPropertyRequest(120, 0x91)
	response = bacnetPropertyACK(vendor, []byte{0x22, 0, 7})
	if got, ok := BACnetPropertyValue(vendor, response); !ok || got != "7" {
		t.Fatalf("vendor ID = %q, %v", got, ok)
	}
	request = BACnetReadPropertyRequest(121, 0x92)
	response = bacnetPropertyACK(request, []byte{0x75, 5, 4, 0, 'A', 0, 'B'})
	if got, ok := BACnetPropertyValue(request, response); !ok || got != "AB" {
		t.Fatalf("UCS-2 vendor = %q, %v", got, ok)
	}
}

func TestBACnetFDTFieldsAndReportedDeviceResponse(t *testing.T) {
	response, err := hex.DecodeString("810a0017010030800c0c02200801194b3ec4022008013f")
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := parseBACnetReadDeviceID(response); !ok || id != 2099201 {
		t.Fatalf("reported device response = %d, %v", id, ok)
	}
	fdt := []byte{0x81, 7, 0, 14, 217, 75, 94, 18, 0x62, 0x2d, 0, 30, 0, 34}
	fields := BACnetFDTFields(fdt)
	if fields["bacnet.fdt_entries"] != "1" || fields["bacnet.fdt.0"] != "217.75.94.18:25133:ttl=30:timeout=34" {
		t.Fatalf("FDT fields: %+v", fields)
	}
	fdt[3] = 13
	if BACnetFDTFields(fdt) != nil {
		t.Fatal("accepted a truncated FDT")
	}
}
