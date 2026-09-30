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
