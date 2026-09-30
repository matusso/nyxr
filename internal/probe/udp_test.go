package probe

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuiltinsAndTokens(t *testing.T) {
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	if len(ForPort(all, 53)) != 2 || len(ForPort(all, 123)) != 1 || len(ForPort(all, 161)) != 1 {
		t.Fatalf("unexpected builtins: %+v", all)
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
	nResponse[0] = 0x24 // version 4, server mode
	copy(nResponse[24:32], nRequest[40:48])
	if !Match(ntp, nRequest, nResponse) {
		t.Fatal("matching NTP response rejected")
	}
	nResponse[24] ^= 1
	if Match(ntp, nRequest, nResponse) {
		t.Fatal("wrong NTP token accepted")
	}
	snmp := ForPort(all, 161)[0]
	sRequest := Prepare(snmp, 0x12345678)
	sResponse := bytes.Clone(sRequest)
	sResponse[13] = 0xa2 // GetResponse-PDU
	if !Match(snmp, sRequest, sResponse) {
		t.Fatal("matching SNMP response rejected")
	}
	sResponse[17] ^= 1
	if Match(snmp, sRequest, sResponse) {
		t.Fatal("wrong SNMP request ID accepted")
	}
}

func TestBACnetWhoIsIdentity(t *testing.T) {
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p := ForPort(all, 47808)[0]
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
		if len(selected) != 1 || selected[0].Name == "generic-byte" {
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
