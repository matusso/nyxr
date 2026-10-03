package service

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"unicode/utf16"

	"github.com/matusso/nyxr/internal/observe"
)

func utf16leBytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
}

func smb2NegotiateResponse(dialect, securityMode uint16, guid [16]byte) []byte {
	hdr := smb2Header(0x0000, 0)
	binary.LittleEndian.PutUint32(hdr[16:20], 0x00000001) // SERVER_TO_REDIR
	body := make([]byte, 65)
	binary.LittleEndian.PutUint16(body[0:2], 65)
	binary.LittleEndian.PutUint16(body[2:4], securityMode)
	binary.LittleEndian.PutUint16(body[4:6], dialect)
	copy(body[8:24], guid[:])
	return append(hdr, body...)
}

func avPair(id uint16, val string) []byte {
	v := utf16leBytes(val)
	out := make([]byte, 4)
	binary.LittleEndian.PutUint16(out[0:2], id)
	binary.LittleEndian.PutUint16(out[2:4], uint16(len(v)))
	return append(out, v...)
}

// ntlmChallenge builds a type-2 message carrying target-info names and an OS
// version, exactly as a Windows server returns to an anonymous session setup.
func ntlmChallenge() []byte {
	flags := uint32(0x00000001 | 0x00000004 | 0x00000200 | 0x02000000) // Unicode|RequestTarget|NTLM|Version
	target := utf16leBytes("CORP")
	var ti []byte
	ti = append(ti, avPair(2, "CORP")...)              // NbDomainName
	ti = append(ti, avPair(1, "DC01")...)              // NbComputerName
	ti = append(ti, avPair(4, "corp.example")...)      // DnsDomainName
	ti = append(ti, avPair(3, "dc01.corp.example")...) // DnsComputerName
	ti = append(ti, avPair(5, "corp.example")...)      // DnsTreeName (forest)
	ti = append(ti, 0, 0, 0, 0)                        // MsvAvEOL
	const base = 56
	m := make([]byte, base)
	copy(m[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(m[8:12], 2)
	binary.LittleEndian.PutUint16(m[12:14], uint16(len(target)))
	binary.LittleEndian.PutUint16(m[14:16], uint16(len(target)))
	binary.LittleEndian.PutUint32(m[16:20], base)
	binary.LittleEndian.PutUint32(m[20:24], flags)
	binary.LittleEndian.PutUint16(m[40:42], uint16(len(ti)))
	binary.LittleEndian.PutUint16(m[42:44], uint16(len(ti)))
	binary.LittleEndian.PutUint32(m[44:48], base+uint32(len(target)))
	m[48], m[49] = 10, 0 // ProductMajor.Minor
	binary.LittleEndian.PutUint16(m[50:52], 19041)
	m[55] = 0x0f // NTLM revision
	m = append(m, target...)
	return append(m, ti...)
}

func smb2SessionResponse(challenge []byte) []byte {
	hdr := smb2Header(0x0001, 1)
	binary.LittleEndian.PutUint32(hdr[16:20], 0x00000001)
	binary.LittleEndian.PutUint32(hdr[8:12], 0xC0000016) // MORE_PROCESSING_REQUIRED
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:2], 9)
	binary.LittleEndian.PutUint16(body[4:6], 64+8)
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(challenge)))
	return append(append(hdr, body...), challenge...)
}

func TestSMBIdentityAndHostInfo(t *testing.T) {
	guid := [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}
	e := identityEngine(t, ProbeSMB, func(c net.Conn) {
		if _, err := readSMBMessage(c); err != nil { // negotiate request
			return
		}
		if _, err := c.Write(directTCP(smb2NegotiateResponse(0x0302, 0x0003, guid))); err != nil {
			return
		}
		if _, err := readSMBMessage(c); err != nil { // session setup request
			return
		}
		_, _ = c.Write(directTCP(smb2SessionResponse(ntlmChallenge())))
	})
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 445})
	if o.Service != "smb" || o.Fingerprint != observe.FingerprintMatched || o.Confidence != 100 {
		t.Fatalf("identity: %+v", o)
	}
	want := map[string]string{
		"smb.dialect":       "SMB 3.0.2",
		"smb.signing":       "required",
		"smb.server_guid":   "44332211-6655-8877-99aa-bbccddeeff00",
		"smb.computer_name": "DC01",
		"smb.domain":        "CORP",
		"smb.dns_computer":  "dc01.corp.example",
		"smb.dns_domain":    "corp.example",
		"smb.dns_forest":    "corp.example",
		"smb.os_version":    "10.0.19041",
	}
	for k, v := range want {
		if o.Attributes[k] != v {
			t.Errorf("attribute %s = %q, want %q", k, o.Attributes[k], v)
		}
	}
	if o.Product != "Windows" || o.Version != "10.0.19041" {
		t.Errorf("product/version = %q/%q", o.Product, o.Version)
	}
	if len(o.Evidence) != 1 || o.Evidence[0].Matched != ProbeSMB || len(o.Evidence[0].Request) == 0 {
		t.Fatalf("audit evidence: %+v", o.Evidence)
	}
}

func rdpConnConfirm(negType byte, value uint32) []byte {
	neg := make([]byte, 8)
	neg[0] = negType
	binary.LittleEndian.PutUint16(neg[2:4], 8)
	binary.LittleEndian.PutUint32(neg[4:8], value)
	cotp := append([]byte{0x00, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00}, neg...)
	cotp[0] = byte(len(cotp) - 1)
	return append([]byte{0x03, 0x00, byte((len(cotp) + 4) >> 8), byte(len(cotp) + 4)}, cotp...)
}

func TestRDPNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name            string
		negType         byte
		value           uint32
		wantSecurity    string
		wantNLA         string
		wantFailureText string
	}{
		{"standard", 0x02, 0, "standard RDP security", "disabled", ""},
		{"nla", 0x02, 2, "CredSSP (NLA)", "enabled", ""},
		{"nla-required", 0x03, 5, "", "required", "CredSSP (NLA) required by server"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := identityEngine(t, ProbeRDP, func(c net.Conn) {
				if _, err := readTPKT(c); err != nil {
					return
				}
				_, _ = c.Write(rdpConnConfirm(tc.negType, tc.value))
			})
			o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 3389})
			if o.Service != "rdp" || o.Fingerprint != observe.FingerprintMatched {
				t.Fatalf("identity: %+v", o)
			}
			if tc.wantSecurity != "" && o.Attributes["rdp.security"] != tc.wantSecurity {
				t.Errorf("rdp.security = %q, want %q", o.Attributes["rdp.security"], tc.wantSecurity)
			}
			if o.Attributes["rdp.nla"] != tc.wantNLA {
				t.Errorf("rdp.nla = %q, want %q", o.Attributes["rdp.nla"], tc.wantNLA)
			}
			if tc.wantFailureText != "" && o.Attributes["rdp.negotiation_failure"] != tc.wantFailureText {
				t.Errorf("rdp.negotiation_failure = %q, want %q", o.Attributes["rdp.negotiation_failure"], tc.wantFailureText)
			}
		})
	}
}

func dceBindAck(ptype byte, secAddr string) []byte {
	var body []byte
	add16 := func(v uint16) { body = append(body, byte(v), byte(v>>8)) }
	if ptype == 12 { // bind_ack
		add16(5840)
		add16(5840)
		body = append(body, 0, 0, 0, 0) // assoc_group_id
		sec := append([]byte(secAddr), 0)
		add16(uint16(len(sec)))
		body = append(body, sec...)
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		body = append(body, 1, 0, 0, 0) // n_results=1
		add16(0)                        // acceptance
		add16(0)                        // reason
		body = append(body, make([]byte, 20)...)
	} else { // bind_nak
		add16(2) // provider_reject_reason
	}
	hdr := make([]byte, 16)
	hdr[0], hdr[1], hdr[2], hdr[3] = 5, 0, ptype, 0x03
	hdr[4] = 0x10
	binary.LittleEndian.PutUint16(hdr[8:10], uint16(16+len(body)))
	binary.LittleEndian.PutUint32(hdr[12:16], 1)
	return append(hdr, body...)
}

func TestMSRPCBind(t *testing.T) {
	t.Run("ack", func(t *testing.T) {
		e := identityEngine(t, ProbeMSRPC, func(c net.Conn) {
			if _, err := readDCERPC(c); err != nil {
				return
			}
			_, _ = c.Write(dceBindAck(12, "135"))
		})
		o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 135})
		if o.Service != "msrpc" || o.Attributes["msrpc.bind"] != "ack" || o.Attributes["msrpc.endpoint"] != "135" {
			t.Fatalf("bind ack: %+v", o)
		}
		if o.Fingerprint != observe.FingerprintMatched || o.Evidence[0].Matched != ProbeMSRPC {
			t.Fatalf("evidence: %+v", o)
		}
	})
	t.Run("nak", func(t *testing.T) {
		e := identityEngine(t, ProbeMSRPC, func(c net.Conn) {
			if _, err := readDCERPC(c); err != nil {
				return
			}
			_, _ = c.Write(dceBindAck(13, ""))
		})
		o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 135})
		if o.Service != "msrpc" || o.Attributes["msrpc.bind"] != "nak" {
			t.Fatalf("bind nak: %+v", o)
		}
	})
}

// TestSMBNegotiateOnlyStillIdentifies confirms the probe reports SMB from the
// negotiate alone when the server declines the anonymous session setup.
func TestSMBNegotiateOnlyStillIdentifies(t *testing.T) {
	guid := [16]byte{}
	e := identityEngine(t, ProbeSMB, func(c net.Conn) {
		if _, err := readSMBMessage(c); err != nil {
			return
		}
		_, _ = c.Write(directTCP(smb2NegotiateResponse(0x0311, 0x0001, guid)))
		// Close without answering the session setup.
	})
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 445})
	if o.Service != "smb" || o.Attributes["smb.dialect"] != "SMB 3.1.1" || o.Attributes["smb.signing"] != "enabled" {
		t.Fatalf("negotiate-only: %+v", o)
	}
	if o.Attributes["smb.os_version"] != "" {
		t.Errorf("unexpected os_version without a challenge: %q", o.Attributes["smb.os_version"])
	}
}
