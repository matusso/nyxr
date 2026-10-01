package probe

import (
	"bytes"
	"testing"
)

func der(tag byte, body ...byte) []byte {
	if len(body) < 128 {
		return append([]byte{tag, byte(len(body))}, body...)
	}
	return append([]byte{tag, 0x81, byte(len(body))}, body...)
}

func cldapAttribute(name string, values ...string) []byte {
	var encoded []byte
	for _, value := range values {
		encoded = append(encoded, der(4, []byte(value)...)...)
	}
	return der(0x30, append(der(4, []byte(name)...), der(0x31, encoded...)...)...)
}

func TestCLDAPRootDSEExtractsReturnedAttributes(t *testing.T) {
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ForPort(all, 389) {
		query := Prepare(p, 0x1234)
		idPos, ok := cldapIDOffset(query)
		if !ok || bytes.Equal(query, p.Payload) {
			t.Fatalf("%s has no prepared message ID", p.Name)
		}
		attrs := append(cldapAttribute("namingContexts", "dc=example,dc=org", "dc=test,dc=org"),
			cldapAttribute("vendorName", "Example Directory")...)
		attrs = append(attrs, cldapAttribute("supportedControl", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10")...)
		entry := der(0x64, append(der(4), der(0x30, attrs...)...)...)
		done := der(0x65, append(der(0x0a, 0), append(der(4), der(4)...)...)...)
		message := der(0x30, append(der(2, query[idPos]), der(0x30, append(entry, done...)...)...)...)
		if !Match(p, query, message) {
			t.Fatalf("%s rejected connectionless search result", p.Name)
		}
		fields := Extract(p, message)
		if fields["cldap.namingcontexts"] != "dc=example,dc=org, dc=test,dc=org" ||
			fields["cldap.vendorname"] != "Example Directory" ||
			fields["cldap.supportedcontrol"] != "1, 2, 3, 4, 5, 6, 7, 8, 9, 10" ||
			fields["cldap.result_code"] != "0" {
			t.Fatalf("%s lost returned attributes: %+v", p.Name, fields)
		}
		wrong := bytes.Clone(message)
		wrong[4] ^= 1
		if Match(p, query, wrong) || Match(p, query, message[:len(message)-1]) {
			t.Fatalf("%s accepted mismatched or truncated reply", p.Name)
		}
	}
}
