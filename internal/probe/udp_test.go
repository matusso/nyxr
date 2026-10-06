package probe

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"strings"
	"testing"
)

func TestBuiltinsAndTokens(t *testing.T) {
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	if len(ForPort(all, 53)) != 4 || len(ForPort(all, 123)) != 3 ||
		len(ForPort(all, 161)) != 5 || len(ForEveryPort(all, 40000)) != len(all) {
		t.Fatalf("unexpected common/deep UDP catalog selection")
	}
	dns := ForPort(all, 53)[0]
	request := Prepare(dns, Token([]byte("secret"), "192.0.2.1", 53, dns.Name, 1))
	response := bytes.Clone(request)
	response[2] |= 0x80
	if !Match(dns, request, response) {
		t.Fatal("matching DNS response rejected")
	}
	response[0] ^= 1
	if Match(dns, request, response) {
		t.Fatal("wrong DNS transaction accepted")
	}
	ntp := ForPort(all, 123)[0]
	nRequest := Prepare(ntp, 0x1234567890abcdef)
	if len(nRequest) != 48 {
		t.Fatalf("NTP payload has %d bytes", len(nRequest))
	}
	nResponse := make([]byte, 48)
	nResponse[0] = (nRequest[0] & 0x38) | 4 // same version, server mode
	copy(nResponse[24:32], nRequest[40:48])
	if !Match(ntp, nRequest, nResponse) {
		t.Fatal("matching NTP response rejected")
	}
	nResponse[24] ^= 1
	if Match(ntp, nRequest, nResponse) {
		t.Fatal("wrong NTP token accepted")
	}
	var snmp Probe
	for _, p := range ForPort(all, 161) {
		if p.Matcher == "snmp" {
			snmp = p
		}
	}
	sRequest := Prepare(snmp, 0x12345678)
	sResponse := bytes.Clone(sRequest)
	offset, _, ok := snmpRequestIDOffset(sRequest, 1)
	if !ok {
		t.Fatal("invalid SNMP request")
	}
	sResponse[offset-4] = 0xa2 // GetResponse-PDU
	if !Match(snmp, sRequest, sResponse) {
		t.Fatal("matching SNMP response rejected")
	}
	sResponse[offset] ^= 1
	if Match(snmp, sRequest, sResponse) {
		t.Fatal("wrong SNMP request ID accepted")
	}
}

func TestSSDPExtractsValidatedDeviceUUID(t *testing.T) {
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	var ssdp Probe
	for _, p := range ForPort(all, 1900) {
		if p.Matcher == "ssdp" {
			ssdp = p
			break
		}
	}
	if ssdp.Name == "" {
		t.Fatal("SSDP probe missing")
	}
	response := []byte("HTTP/1.1 200 OK\r\nUSN: uuid:00112233-4455-6677-8899-aabbccddeeff::upnp:rootdevice\r\nSERVER: test\r\n\r\n")
	if !Match(ssdp, ssdp.Payload, response) {
		t.Fatal("SSDP response rejected")
	}
	fields := Extract(ssdp, response)
	if fields["ssdp.uuid"] != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatalf("UUID: %+v", fields)
	}
	bad := []byte("HTTP/1.1 200 OK\r\nUSN: uuid:not-a-uuid\r\n\r\n")
	if got := Extract(ssdp, bad)["ssdp.uuid"]; got != "" {
		t.Fatalf("accepted invalid UUID %q", got)
	}
}

func TestSNMPv3DiscoveryAndEngineIdentity(t *testing.T) {
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	var discovery Probe
	for _, p := range ForPort(all, 161) {
		if p.Matcher == "snmpv3" {
			discovery = p
		}
	}
	if discovery.Name == "" {
		t.Fatal("SNMPv3 discovery probe missing")
	}
	request := Prepare(discovery, 0x12345678)
	if len(request) != 60 || binary.BigEndian.Uint16(request[9:11]) != 0x5678 {
		t.Fatalf("unexpected discovery request %x", request)
	}
	response := snmpV3ReportFixture(t, 0x5678)
	if !Match(discovery, request, response) {
		t.Fatalf("SNMPv3 Report rejected: %x", response)
	}
	fields := Extract(discovery, response)
	if fields["snmp.version"] != "3" || fields["snmp.enterprise"] != "9" ||
		fields["snmp.engine_id_format"] != "mac" || fields["snmp.engine_id_data"] != "54:a2:74:df:db:42" ||
		fields["snmp.engine_boots"] != "2" || fields["snmp.engine_time"] != "685 days, 8:16:30" ||
		fields["snmp.engine_id"] != "80:00:00:09:03:54:a2:74:df:db:42" {
		t.Fatalf("unexpected SNMPv3 fields: %+v", fields)
	}
	request[9] ^= 1
	if Match(discovery, request, response) {
		t.Fatal("Report with wrong message ID accepted")
	}
	request[9] ^= 1
	if Match(discovery, request, response[:len(response)-1]) {
		t.Fatal("truncated Report accepted")
	}
	// Tokens whose low bits are below 0x80 must still produce minimally
	// encoded two-byte INTEGERs that round-trip through a strict decoder.
	request = Prepare(discovery, 0x000b000b)
	if request[9] == 0 && request[10] < 0x80 || request[50] == 0 && request[51] < 0x80 {
		t.Fatalf("non-minimal SNMPv3 IDs in request %x", request)
	}
	msgID := int(binary.BigEndian.Uint16(request[9:11]))
	if !Match(discovery, request, snmpV3ReportFixture(t, msgID)) {
		t.Fatalf("SNMPv3 Report rejected for low token, msgID %#x", msgID)
	}
}

func snmpV3ReportFixture(t *testing.T, msgID int) []byte {
	t.Helper()
	mustMarshal := func(value any) []byte {
		encoded, err := asn1.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	engine := []byte{0x80, 0, 0, 9, 3, 0x54, 0xa2, 0x74, 0xdf, 0xdb, 0x42}
	usm := mustMarshal(struct {
		Engine []byte
		Boots  int
		Time   int
		User   []byte
		Auth   []byte
		Priv   []byte
	}{engine, 2, 685*86400 + 8*3600 + 16*60 + 30, nil, nil, nil})
	header := mustMarshal(struct {
		ID    int
		Size  int
		Flags []byte
		Model int
	}{msgID, 65507, []byte{0}, 3})
	unknownEngineIDs := mustMarshal(asn1.ObjectIdentifier{1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0})
	unknownEngineIDs = append(unknownEngineIDs, mustMarshal(asn1.RawValue{Class: 1, Tag: 1, Bytes: []byte{1}})...)
	varBind := mustMarshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: unknownEngineIDs})
	varBinds := mustMarshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: varBind})
	pduBody := append([]byte{2, 1, 1, 2, 1, 0, 2, 1, 0}, varBinds...)
	pdu := mustMarshal(asn1.RawValue{Class: 2, Tag: 8, IsCompound: true, Bytes: pduBody})
	scoped := mustMarshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: append([]byte{4, 0, 4, 0}, pdu...)})
	content := append(mustMarshal(3), header...)
	content = append(content, mustMarshal(usm)...)
	content = append(content, scoped...)
	return mustMarshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: content})
}

func TestBACnetWhoIsIdentity(t *testing.T) {
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	var p Probe
	for _, candidate := range ForPort(all, 47808) {
		if candidate.Matcher == "bacnet" {
			p = candidate
		}
	}
	if p.Matcher != "bacnet" {
		t.Fatalf("missing BACnet probe: %+v", p)
	}
	response := []byte{0x81, 0x0a, 0, 0, 1, 0, 0x10, 0, 0xc4, 0x02, 0, 0, 42,
		0x22, 0x04, 0, 0x91, 3, 0x22, 1, 0x23}
	response[3] = byte(len(response))
	if !Match(p, p.Payload, response) {
		t.Fatal("valid I-Am rejected")
	}
	response[1] = 0x0b // broadcast I-Am to the BACnet well-known port
	if !Match(p, p.Payload, response) {
		t.Fatal("valid broadcast I-Am rejected")
	}
	fields := Extract(p, response)
	if fields["bacnet.device_id"] != "42" || fields["bacnet.vendor_id"] != "291" {
		t.Fatalf("fields: %+v", fields)
	}
	response[9] = 0 // not a Device object
	if Match(p, p.Payload, response) {
		t.Fatal("accepted non-device response")
	}
}

func TestBACnetReadOnlyFallbackProbes(t *testing.T) {
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	selected := ForPort(all, 47808)
	if len(selected) != 3 || selected[0].Matcher != "bacnet" ||
		selected[1].Matcher != "bacnet-read" || selected[2].Matcher != "bacnet-fdt" {
		t.Fatalf("expected BACnet probes first on the usual port, got %+v", selected)
	}
	var read, fdt Probe
	for _, p := range selected {
		switch p.Matcher {
		case "bacnet-read":
			read = p
		case "bacnet-fdt":
			fdt = p
		}
	}
	if read.Name == "" || fdt.Name == "" {
		t.Fatalf("missing BACnet fallback probes: %+v", selected)
	}
	request := Prepare(read, 0x1234)
	for _, apdu := range []byte{0x30, 0x50} {
		response := []byte{0x81, 0x0a, 0, 9, 1, 0, apdu, 0x34, 0x0c}
		if !Match(read, request, response) {
			t.Fatalf("read reply %02x rejected", apdu)
		}
		response[7] ^= 1
		if Match(read, request, response) {
			t.Fatal("read reply with wrong invoke ID accepted")
		}
	}
	readResponse := []byte{0x81, 0x0a, 0, 23, 1, 0, 0x30, 0x34, 0x0c, 0x0c,
		0x02, 0x3f, 0xff, 0xff, 0x19, 0x4b, 0x3e, 0xc4, 0, 0, 0, 0, 0x3f}
	binary.BigEndian.PutUint32(readResponse[18:22], 8<<22|2099201)
	if !Match(read, request, readResponse) || Extract(read, readResponse)["bacnet.device_id"] != "2099201" {
		t.Fatalf("Device ID response rejected: %x", readResponse)
	}
	if !bytes.Equal(fdt.Payload, []byte{0x81, 0x06, 0, 4}) {
		t.Fatalf("unexpected FDT request %x", fdt.Payload)
	}
	response := []byte{0x81, 0x07, 0, 14, 192, 0, 2, 1, 0xba, 0xc0, 0, 30, 0, 34}
	if !Match(fdt, fdt.Payload, response) || Extract(fdt, response)["bacnet.fdt_entries"] != "1" {
		t.Fatalf("valid FDT response rejected: %x", response)
	}
	if Match(fdt, fdt.Payload, response[:13]) || Match(fdt, fdt.Payload, []byte{0x81, 0x07, 0, 5, 0}) {
		t.Fatal("malformed FDT response accepted")
	}
	if !Match(fdt, fdt.Payload, []byte{0x81, 0, 0, 6, 0, 0x40}) {
		t.Fatal("FDT read failure still identifies a BACnet endpoint")
	}
}

func TestRPCAndMemcachedUDPProbes(t *testing.T) {
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []uint16{111, 2049} {
		p := ForPort(all, port)[0]
		if p.Matcher != "rpc" {
			t.Fatalf("port %d lacks an RPC NULL probe", port)
		}
		request := Prepare(p, 0x12345678)
		reply := []byte{0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		if !Match(p, request, reply) {
			t.Fatalf("port %d rejected matching RPC reply", port)
		}
		reply[3] ^= 1
		if Match(p, request, reply) {
			t.Fatal("RPC reply with wrong XID accepted")
		}
		reply[3] ^= 1
		reply[23] = 1 // Program unavailable is not a match for the named service.
		if Match(p, request, reply) {
			t.Fatal("RPC error identified as the requested service")
		}
	}
	memcached := ForPort(all, 11211)[0]
	if memcached.Matcher != "memcached" {
		t.Fatalf("missing memcached UDP probe: %+v", memcached)
	}
	request := Prepare(memcached, 0x1234)
	reply := append([]byte{0x12, 0x34, 0, 0, 0, 1, 0, 0}, []byte("VERSION 1.6.0\r\n")...)
	if !Match(memcached, request, reply) {
		t.Fatal("memcached version reply rejected")
	}
	reply[0] ^= 1
	if Match(memcached, request, reply) {
		t.Fatal("memcached reply with wrong request ID accepted")
	}
}

func TestNativeProbeValidation(t *testing.T) {
	const valid = "name: custom\ntransport: udp\nports: [9999]\nsafety: safe\npayload:\n  encoding: base64\n  data: AQID\nmatch:\n  - type: any\n"
	p, err := Parse(strings.NewReader(valid), "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "custom" || !bytes.Equal(p.Payload, []byte{1, 2, 3}) {
		t.Fatalf("got %+v", p)
	}
	if _, err := Parse(strings.NewReader(valid+"unknown: value\n"), ""); err == nil {
		t.Fatal("accepted unknown YAML field")
	}
	if _, err := Parse(strings.NewReader(strings.Replace(valid, "safety: safe", "safety: intrusive", 1)), ""); err == nil {
		t.Fatal("accepted unsafe probe")
	}
}

func TestPhase2BuiltinsAndMatchers(t *testing.T) {
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []uint16{69, 1900, 3478, 5060, 5353, 5355, 5683} {
		selected := ForPort(all, port)
		if len(selected) != 1 || selected[0].Name == "udp-empty" {
			t.Fatalf("port %d: %+v", port, selected)
		}
	}
	for _, tc := range []struct {
		port         uint16
		makeResponse func([]byte) []byte
		field, want  string
	}{
		{3478, func(req []byte) []byte { r := bytes.Clone(req); r[0], r[1] = 1, 1; return r }, "stun.message_type", "0x0101"},
		{5060, func(req []byte) []byte { return []byte("SIP/2.0 200 OK\r\nCall-ID: " + sipCallID(req) + "\r\n\r\n") }, "sip.status", "200"},
		{5683, func(req []byte) []byte { r := bytes.Clone(req); r[1] = 0x45; return r }, "coap.code", "2.05"},
		{69, func([]byte) []byte { return []byte{0, 5, 0, 1, 'x', 0} }, "tftp.error_code", "1"},
		{1900, func([]byte) []byte { return []byte("HTTP/1.1 200 OK\r\nSERVER: fixture\r\n\r\n") }, "ssdp.server", "fixture"},
	} {
		p := ForPort(all, tc.port)[0]
		request := Prepare(p, 0x1234567890abcdef)
		response := tc.makeResponse(request)
		if !Match(p, request, response) {
			t.Fatalf("%s rejected matching response", p.Name)
		}
		if got := Extract(p, response)[tc.field]; got != tc.want {
			t.Fatalf("%s extraction: %q", p.Name, got)
		}
		if p.Matcher == "stun" || p.Matcher == "sip" || p.Matcher == "coap" {
			wrong := tc.makeResponse(Prepare(p, 0x9999999999999999))
			if Match(p, request, wrong) {
				t.Fatalf("%s accepted wrong transaction", p.Name)
			}
		}
	}
}

func TestNativeProbeSchemaAndExtractionValidation(t *testing.T) {
	const base = "schema: nyxr/udp/v1\nname: x\ntransport: udp\nports: [53]\nsafety: safe\npayload:\n  encoding: hex\n  data: 000001000001000000000000\nmatch:\n  - type: dns\nextract: [dns.rcode]\n"
	if _, err := Parse(strings.NewReader(base), ""); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		strings.Replace(base, "nyxr/udp/v1", "nyxr/udp/v2", 1),
		strings.Replace(base, "dns.rcode", "sip.status", 1),
		strings.Replace(base, "[dns.rcode]", "[dns.rcode, dns.rcode]", 1),
		strings.Replace(base, "000001000001000000000000", "000028000001000000000000", 1), // DNS UPDATE is not read-only.
	} {
		if _, err := Parse(strings.NewReader(invalid), ""); err == nil {
			t.Fatalf("accepted invalid probe: %s", invalid)
		}
	}
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	sip := ForPort(all, 5060)[0]
	var d Definition
	d.Name, d.Transport, d.Safety = "unsafe-sip", "udp", "safe"
	d.Payload.Encoding = "ascii"
	d.Payload.Data = string(bytes.Replace(sip.Payload, []byte("OPTIONS "), []byte("INVITE "), 1))
	d.Match = make([]struct {
		Type string `yaml:"type"`
	}, 1)
	d.Match[0].Type = "sip"
	if _, err := d.Compile(""); err == nil {
		t.Fatal("accepted INVITE as a safe SIP probe")
	}
}
