package service

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/matusso/nyxr/internal/observe"
)

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func ldapAttr(name string, vals ...string) []byte {
	var set []byte
	for _, v := range vals {
		set = append(set, derTLV(0x04, []byte(v))...)
	}
	return derTLV(0x30, cat(derTLV(0x04, []byte(name)), derTLV(0x31, set))) // SEQ { type, SET OF val }
}

func ldapResponse(attrs ...[]byte) []byte {
	entry := derTLV(0x64, cat(derTLV(0x04, nil), derTLV(0x30, cat(attrs...)))) // [APP 4]
	msg1 := derTLV(0x30, cat(derTLV(0x02, []byte{0x01}), entry))
	done := derTLV(0x65, cat(derTLV(0x0a, []byte{0x00}), derTLV(0x04, nil), derTLV(0x04, nil))) // [APP 5]
	msg2 := derTLV(0x30, cat(derTLV(0x02, []byte{0x01}), done))
	return cat(msg1, msg2)
}

func TestLDAPIdentifiesActiveDirectory(t *testing.T) {
	resp := ldapResponse(
		ldapAttr("defaultNamingContext", "DC=corp,DC=example"),
		ldapAttr("rootDomainNamingContext", "DC=example"),
		ldapAttr("dnsHostName", "dc01.corp.example"),
		ldapAttr("domainControllerFunctionality", "7"),
		ldapAttr("domainFunctionality", "7"),
		ldapAttr("forestFunctionality", "4"),
		ldapAttr("ldapServiceName", "corp.example:dc01$@CORP.EXAMPLE"),
		ldapAttr("isGlobalCatalogReady", "TRUE"),
		ldapAttr("supportedSASLMechanisms", "GSSAPI", "GSS-SPNEGO"),
	)
	e := identityEngine(t, ProbeLDAP, func(c net.Conn) {
		buf := make([]byte, 4096)
		_, _ = c.Read(buf) // drain the search request, then answer
		_, _ = c.Write(resp)
	})
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 389})
	if o.Service != "ldap" || o.Product != "Active Directory" || o.Fingerprint != observe.FingerprintMatched {
		t.Fatalf("identity: %+v", o)
	}
	want := map[string]string{
		"ad.domain":         "corp.example",
		"ad.forest":         "example",
		"ad.dc_dns":         "dc01.corp.example",
		"ad.domain_level":   "Windows Server 2016 or later",
		"ad.forest_level":   "Windows Server 2008 R2",
		"ad.global_catalog": "true",
	}
	for k, v := range want {
		if o.Attributes[k] != v {
			t.Errorf("attribute %s = %q, want %q", k, o.Attributes[k], v)
		}
	}
	if o.Attributes["ldap.sasl_mechanisms"] != "GSSAPI, GSS-SPNEGO" {
		t.Errorf("sasl = %q", o.Attributes["ldap.sasl_mechanisms"])
	}
}

func TestLDAPPlainServerStillIdentified(t *testing.T) {
	resp := ldapResponse(
		ldapAttr("namingContexts", "dc=example,dc=org"),
		ldapAttr("vendorName", "389 Project"),
		ldapAttr("vendorVersion", "389-Directory/2.4"),
	)
	e := identityEngine(t, ProbeLDAP, func(c net.Conn) {
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		_, _ = c.Write(resp)
	})
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 389})
	if o.Service != "ldap" || o.Product != "389 Project" || o.Version != "389-Directory/2.4" {
		t.Fatalf("plain LDAP: %+v", o)
	}
	if o.Attributes["ldap.naming_contexts"] != "dc=example,dc=org" {
		t.Errorf("naming contexts = %q", o.Attributes["ldap.naming_contexts"])
	}
}

func krbError(code int, realm string) []byte {
	seq := derTLV(0x30, cat(
		derTLV(0xa0, derTLV(0x02, []byte{0x05})),       // pvno
		derTLV(0xa1, derTLV(0x02, []byte{30})),         // msg-type
		derTLV(0xa6, derTLV(0x02, []byte{byte(code)})), // [6] error-code
		derTLV(0xa9, derTLV(0x1b, []byte(realm))),      // [9] realm (GeneralString)
	))
	return derTLV(0x7e, seq) // [APPLICATION 30]
}

func TestKerberosIdentifiesKDCAndRealm(t *testing.T) {
	msg := krbError(6, "CORP.EXAMPLE")
	e := identityEngine(t, ProbeKerberos, func(c net.Conn) {
		var h [4]byte
		if _, err := io.ReadFull(c, h[:]); err != nil {
			return
		}
		req := make([]byte, binary.BigEndian.Uint32(h[:]))
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		frame := make([]byte, 4+len(msg))
		binary.BigEndian.PutUint32(frame[:4], uint32(len(msg)))
		copy(frame[4:], msg)
		_, _ = c.Write(frame)
	})
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 88})
	if o.Service != "kerberos" || o.Fingerprint != observe.FingerprintMatched {
		t.Fatalf("identity: %+v", o)
	}
	if o.Attributes["kerberos.error"] != "C_PRINCIPAL_UNKNOWN" || o.Attributes["kerberos.realm"] != "CORP.EXAMPLE" {
		t.Fatalf("attributes: %+v", o.Attributes)
	}
}
