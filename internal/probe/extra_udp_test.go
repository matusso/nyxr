package probe

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"testing"
)

func TestExpandedUDPCatalogAndReplies(t *testing.T) {
	all, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]Probe, len(all))
	for _, p := range all {
		byName[p.Name] = p
	}
	for _, name := range []string{
		"dns-status", "dns-version-bind", "dhcp-discover", "ntp-v2", "ntp-v3",
		"ntp-client", "nbns-node-status", "kerberos-as-req", "cldap-rootdse", "cldap-rfc-rootdse",
		"radius-access", "radius-accounting", "ike-main-mode", "l2tp-sccrq",
		"snmp-v1-public", "snmp-v1-private", "snmp-v2c-private", "slp-service-agent", "ipmi-asf-ping", "citrix-discovery",
		"db2-discovery", "source-info", "quake3-status", "gamespy-status",
		"teamspeak3-init", "udp-null",
	} {
		if _, ok := byName[name]; !ok {
			t.Fatalf("missing native UDP probe %s", name)
		}
	}
	if got := ForPort(all, 65000); len(got) != 1 || got[0].Name != "udp-null" {
		t.Fatalf("missing NULL fallback: %+v", got)
	}
	deep := ForEveryPort(all, 53)
	if deep[len(deep)-1].Name != "udp-null" {
		t.Fatal("NULL probe must be last in a deep campaign")
	}

	for _, tc := range []struct {
		name  string
		reply func([]byte) []byte
	}{
		{"dns-status", func(q []byte) []byte { r := bytes.Clone(q); r[2] |= 0x80; return r }},
		{"dhcp-discover", func(q []byte) []byte { r := bytes.Clone(q); r[0] = 2; return r }},
		{"nbns-node-status", func(q []byte) []byte { r := bytes.Clone(q); r[2] |= 0x80; return r }},
		{"kerberos-as-req", func([]byte) []byte {
			r, _ := asn1.Marshal(asn1.RawValue{Class: 1, Tag: 30, IsCompound: true, Bytes: []byte{2, 1, 5}})
			return r
		}},
		{"cldap-rootdse", func(q []byte) []byte {
			pos, _ := cldapIDOffset(q)
			return []byte{0x30, 8, 2, 1, q[pos], 0x65, 3, 0x0a, 1, 0}
		}},
		{"radius-access", func(q []byte) []byte { r := bytes.Clone(q); r[0] = 3; return r }},
		{"radius-accounting", func(q []byte) []byte { r := bytes.Clone(q); r[0] = 5; return r }},
		{"ike-main-mode", func(q []byte) []byte { r := bytes.Clone(q); r[8] = 1; return r }},
		{"l2tp-sccrq", func([]byte) []byte {
			return []byte{0xc8, 2, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 8, 0, 0, 0, 0, 0, 2}
		}},
		{"snmp-v1-public", func(q []byte) []byte {
			r := bytes.Clone(q)
			offset, _, _ := snmpRequestIDOffset(q, 0)
			r[offset-4] = 0xa2
			return r
		}},
		{"snmp-v1-private", func(q []byte) []byte {
			r := bytes.Clone(q)
			offset, _, _ := snmpRequestIDOffset(q, 0)
			r[offset-4] = 0xa2
			return r
		}},
		{"snmp-v2c-private", func(q []byte) []byte {
			r := bytes.Clone(q)
			offset, _, _ := snmpRequestIDOffset(q, 1)
			r[offset-4] = 0xa2
			return r
		}},
		{"slp-service-agent", func(q []byte) []byte { r := bytes.Clone(q); r[1] = 2; return r }},
		{"ipmi-asf-ping", func(q []byte) []byte { r := bytes.Clone(q); r[8] = 0x40; return r }},
		{"citrix-discovery", func([]byte) []byte { return []byte{0x30, 0, 2, 0x31, 2, 0xfd, 0xa8, 0xe3, 2, 0, 6, 0x44} }},
		{"db2-discovery", func([]byte) []byte { return []byte("DB2RETADDR\x00SQL08010\x00host\x00") }},
		{"source-info", func([]byte) []byte { return append(bytes.Repeat([]byte{255}, 4), 'I', 1) }},
		{"quake3-status", func([]byte) []byte { return []byte("\xff\xff\xff\xffstatusResponse\n") }},
		{"gamespy-status", func([]byte) []byte { return []byte("\\hostname\\server\\final\\") }},
		{"teamspeak3-init", func([]byte) []byte { return []byte("TS3INIT1\x00reply payload") }},
	} {
		p := byName[tc.name]
		request := Prepare(p, 0x1234567890abcdef)
		response := tc.reply(request)
		if !Match(p, request, response) {
			t.Errorf("%s rejected a protocol-shaped reply", tc.name)
		}
		if Match(p, request, []byte{1, 2, 3}) {
			t.Errorf("%s accepted a malformed reply", tc.name)
		}
	}
	for _, name := range []string{"dns-status", "dhcp-discover", "nbns-node-status", "radius-access", "ike-main-mode", "slp-service-agent", "ipmi-asf-ping"} {
		p := byName[name]
		q := Prepare(p, 0x1234567890abcdef)
		other := Prepare(p, 0xdeadbeef01020304)
		if bytes.Equal(q, other) {
			t.Errorf("%s lacks a transaction token", name)
		}
	}
	for _, name := range []string{"ntp-v2", "ntp-v3", "ntp-client"} {
		p := byName[name]
		q := Prepare(p, 0x1234567890abcdef)
		r := make([]byte, 48)
		r[0] = q[0]&0x38 | 4
		copy(r[24:32], q[40:48])
		if !Match(p, q, r) {
			t.Errorf("%s rejected matching NTP version", name)
		}
		r[0] += 8
		if Match(p, q, r) {
			t.Errorf("%s accepted wrong NTP version", name)
		}
	}
	if binary.BigEndian.Uint32(byName["ike-main-mode"].Payload[24:28]) != uint32(len(byName["ike-main-mode"].Payload)) {
		t.Fatal("IKE packet length disagrees with payload")
	}
	version := byName["dns-version-bind"]
	query := Prepare(version, 0x1234)
	reply := append(bytes.Clone(query), []byte{0xc0, 0x0c, 0, 16, 0, 3, 0, 0, 0, 60, 0, 10, 9}...)
	reply = append(reply, []byte("BIND 9.18")...)
	reply[2] |= 0x80
	reply[7] = 1
	if !Match(version, query, reply) || Extract(version, reply)["dns.txt"] != "BIND 9.18" {
		t.Fatalf("version.bind TXT reply was not extracted: %x", reply)
	}
	if _, ok := dnsTXT(reply[:len(reply)-1]); ok {
		t.Fatal("truncated DNS TXT answer accepted")
	}
}
