package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/matusso/nyxr/internal/observe"
)

// This file identifies the services Windows hosts propagate on the network:
// SMB file sharing (139/445), the Remote Desktop Protocol (3389) and the
// DCE/RPC endpoint mapper (135). Every probe is an unauthenticated, read-only
// handshake. The SMB probe completes an SMB2 negotiate and reads the NTLM
// challenge the server returns to an anonymous session setup; it sends no
// credentials and never finishes authentication. The RDP probe performs the
// X.224 security negotiation and, when the server offers TLS, records the
// certificate. The MSRPC probe binds to the endpoint mapper interface.

// addAttr sets one observation attribute, creating the map on first use and
// skipping empty values so a partial parse never records blank fields.
func addAttr(o *observe.Observation, key, value string) {
	if value == "" {
		return
	}
	if o.Attributes == nil {
		o.Attributes = map[string]string{}
	}
	o.Attributes[key] = value
}

func putLE16(b *bytes.Buffer, v uint16) { b.WriteByte(byte(v)); b.WriteByte(byte(v >> 8)) }
func putLE32(b *bytes.Buffer, v uint32) {
	b.WriteByte(byte(v))
	b.WriteByte(byte(v >> 8))
	b.WriteByte(byte(v >> 16))
	b.WriteByte(byte(v >> 24))
}

// directTCP frames an SMB message for the Direct TCP transport (445) and the
// NetBIOS session service (139): a type byte (0 for a session message) and a
// 24-bit big-endian length.
func directTCP(payload []byte) []byte {
	n := len(payload)
	return append([]byte{0x00, byte(n >> 16), byte(n >> 8), byte(n)}, payload...)
}

// readSMBMessage reads one Direct TCP / NetBIOS session message.
func readSMBMessage(c net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n < 4 || n > 0x10000 {
		return nil, fmt.Errorf("invalid SMB frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// utf16le decodes the little-endian UTF-16 strings NTLM uses for names.
func utf16le(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00")
}

// filetimeUTC converts a Windows FILETIME (100 ns intervals since 1601) to a
// time. Zero and clearly out-of-range values return the zero time.
func filetimeUTC(ft uint64) time.Time {
	const epochDelta = 116444736000000000 // 1601-01-01 .. 1970-01-01 in 100 ns units
	if ft <= epochDelta {
		return time.Time{}
	}
	return time.Unix(0, int64(ft-epochDelta)*100).UTC()
}

// encodeNetBIOSName applies the level-2 encoding used by the NetBIOS session
// service: a 16-byte name (15 chars space-padded plus a suffix) where each
// nibble becomes a letter.
func encodeNetBIOSName(name string, suffix byte) []byte {
	raw := make([]byte, 16)
	for i := range 15 {
		if i < len(name) {
			raw[i] = name[i]
		} else {
			raw[i] = ' '
		}
	}
	raw[15] = suffix
	out := make([]byte, 0, 34)
	out = append(out, 0x20)
	for _, b := range raw {
		out = append(out, 'A'+(b>>4), 'A'+(b&0x0f))
	}
	return append(out, 0x00)
}

// netbiosSession performs the session request/response that must precede SMB
// on the NetBIOS session port (139). The wildcard called name "*SMBSERVER"
// is accepted by servers that do not know the query's target name.
func netbiosSession(c net.Conn) error {
	body := append(encodeNetBIOSName("*SMBSERVER", 0x20), encodeNetBIOSName("NYXR", 0x00)...)
	req := append([]byte{0x81, 0x00, byte(len(body) >> 8), byte(len(body))}, body...)
	if _, err := c.Write(req); err != nil {
		return err
	}
	var resp [4]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		return err
	}
	if resp[0] != 0x82 { // positive session response
		return fmt.Errorf("netbios session rejected (0x%02x)", resp[0])
	}
	return nil
}

func smb2Header(command uint16, messageID uint64) []byte {
	h := make([]byte, 64)
	copy(h[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(h[4:6], 64) // header StructureSize
	binary.LittleEndian.PutUint16(h[12:14], command)
	binary.LittleEndian.PutUint16(h[14:16], 1) // CreditRequest
	binary.LittleEndian.PutUint64(h[24:32], messageID)
	return h
}

type smb2Negotiated struct {
	dialect      uint16
	securityMode uint16
	capabilities uint32
	serverGUID   [16]byte
	systemTime   time.Time
	startTime    time.Time
}

// smb2Negotiate offers SMB 2.0.2 through 3.0.2 (dialects that need no
// negotiate contexts) and parses the server's chosen dialect and capabilities.
func (e *Engine) smb2Negotiate(c net.Conn) (smb2Negotiated, error) {
	var out smb2Negotiated
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302}
	body := make([]byte, 36)
	binary.LittleEndian.PutUint16(body[0:2], 36) // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(body[4:6], 0x0001) // SigningEnabled
	if _, err := rand.Read(body[12:28]); err != nil {
		return out, err
	}
	for _, d := range dialects {
		body = append(body, byte(d), byte(d>>8))
	}
	if _, err := c.Write(directTCP(append(smb2Header(0x0000, 0), body...))); err != nil {
		return out, err
	}
	resp, err := readSMBMessage(c)
	if err != nil {
		return out, err
	}
	if len(resp) < 64+65 || resp[0] != 0xFE || resp[1] != 'S' ||
		binary.LittleEndian.Uint16(resp[12:14]) != 0x0000 || // NEGOTIATE command echoed
		binary.LittleEndian.Uint32(resp[8:12]) != 0 { // STATUS_SUCCESS
		return out, fmt.Errorf("not an SMB2 negotiate response")
	}
	b := resp[64:]
	if binary.LittleEndian.Uint16(b[0:2]) != 65 {
		return out, fmt.Errorf("unexpected SMB2 negotiate structure size")
	}
	out.securityMode = binary.LittleEndian.Uint16(b[2:4])
	out.dialect = binary.LittleEndian.Uint16(b[4:6])
	copy(out.serverGUID[:], b[8:24])
	out.capabilities = binary.LittleEndian.Uint32(b[24:28])
	out.systemTime = filetimeUTC(binary.LittleEndian.Uint64(b[40:48]))
	out.startTime = filetimeUTC(binary.LittleEndian.Uint64(b[48:56]))
	return out, nil
}

type ntlmInfo struct {
	targetName                                           string
	nbComputer, nbDomain, dnsComputer, dnsDomain, forest string
	osVersion                                            string
}

// derTLV and friends build the minimal SPNEGO wrapper NTLM needs.
func derTLV(tag byte, content []byte) []byte {
	var length []byte
	switch n := len(content); {
	case n < 0x80:
		length = []byte{byte(n)}
	case n < 0x100:
		length = []byte{0x81, byte(n)}
	default:
		length = []byte{0x82, byte(n >> 8), byte(n)}
	}
	out := append([]byte{tag}, length...)
	return append(out, content...)
}

// spnegoNTLM wraps an NTLMSSP NEGOTIATE message in an SPNEGO NegTokenInit so
// an SMB2 session setup elicits the server's NTLM CHALLENGE.
func spnegoNTLM(ntlm []byte) []byte {
	ntlmOID := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	mechTypes := derTLV(0xa0, derTLV(0x30, ntlmOID)) // [0] mechTypes
	mechToken := derTLV(0xa2, derTLV(0x04, ntlm))    // [2] mechToken
	negInit := derTLV(0xa0, derTLV(0x30, append(mechTypes, mechToken...)))
	return derTLV(0x60, append(spnegoOID, negInit...)) // [APPLICATION 0]
}

func ntlmNegotiate() []byte {
	m := make([]byte, 32)
	copy(m[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(m[8:12], 1) // NtLmNegotiate
	// Unicode | OEM | RequestTarget | NTLM | AlwaysSign | ExtendedSessionSecurity.
	binary.LittleEndian.PutUint32(m[12:16], 0x00000001|0x00000002|0x00000004|0x00000200|0x00008000|0x00080000)
	return m
}

// smb2SessionNTLM runs an anonymous SMB2 session setup and parses the NTLM
// CHALLENGE (type 2). The challenge's target-info pairs reveal the computer
// and domain names, and its version field the OS build. No type-3 message is
// sent, so authentication never completes.
func (e *Engine) smb2SessionNTLM(c net.Conn) *ntlmInfo {
	token := spnegoNTLM(ntlmNegotiate())
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 25)                   // StructureSize
	body[3] = 0x01                                                 // SecurityMode: signing enabled
	binary.LittleEndian.PutUint16(body[12:14], 88)                 // SecurityBufferOffset (64 header + 24 body)
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(token))) // SecurityBufferLength
	body = append(body, token...)
	if _, err := c.Write(directTCP(append(smb2Header(0x0001, 1), body...))); err != nil {
		return nil
	}
	resp, err := readSMBMessage(c)
	if err != nil {
		return nil
	}
	idx := bytes.Index(resp, []byte("NTLMSSP\x00"))
	if idx < 0 {
		return nil
	}
	msg := resp[idx:]
	if len(msg) < 48 || binary.LittleEndian.Uint32(msg[8:12]) != 2 { // NtLmChallenge
		return nil
	}
	info := &ntlmInfo{}
	flags := binary.LittleEndian.Uint32(msg[20:24])
	readField := func(off int) []byte {
		fl := int(binary.LittleEndian.Uint16(msg[off : off+2]))
		fo := int(binary.LittleEndian.Uint32(msg[off+4 : off+8]))
		if fl <= 0 || fo < 0 || fo+fl > len(msg) {
			return nil
		}
		return msg[fo : fo+fl]
	}
	info.targetName = utf16le(readField(12))
	if flags&0x02000000 != 0 && len(msg) >= 56 { // NegotiateVersion
		info.osVersion = fmt.Sprintf("%d.%d.%d", msg[48], msg[49], binary.LittleEndian.Uint16(msg[50:52]))
	}
	for av := readField(40); len(av) >= 4; {
		id := binary.LittleEndian.Uint16(av[0:2])
		l := int(binary.LittleEndian.Uint16(av[2:4]))
		av = av[4:]
		if id == 0 || l > len(av) { // MsvAvEOL or truncation
			break
		}
		value := utf16le(av[:l])
		av = av[l:]
		switch id {
		case 1:
			info.nbComputer = value
		case 2:
			info.nbDomain = value
		case 3:
			info.dnsComputer = value
		case 4:
			info.dnsDomain = value
		case 5:
			info.forest = value
		}
	}
	return info
}

func smbSigning(mode uint16) string {
	switch {
	case mode&0x0002 != 0:
		return "required"
	case mode&0x0001 != 0:
		return "enabled"
	default:
		return "disabled"
	}
}

func smbDialectName(d uint16) string {
	switch d {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	}
	return fmt.Sprintf("0x%04x", d)
}

func guidString(b [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]), binary.BigEndian.Uint16(b[8:10]), b[10:16])
}

// probeSMB identifies SMB and, where the server allows an anonymous session
// setup, the host and OS it belongs to. It falls back to an SMBv1 negotiate on
// a fresh connection when SMB2 is disabled.
func (e *Engine) probeSMB(ctx context.Context, t Target, o *observe.Observation) bool {
	ev := observe.Evidence{Probe: ProbeSMB, Layer: "tcp", Started: time.Now().UTC()}
	matched := false
	defer func() {
		if matched {
			ev.Matched = ProbeSMB
		}
		o.Evidence = append(o.Evidence, ev)
	}()
	timeout := e.timeout(ProbeSMB)
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		return false
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()

	if t.Port == 139 {
		if err := netbiosSession(rc); err != nil {
			e.finish(&ev, rc, err)
			return false
		}
	}
	neg, err := e.smb2Negotiate(rc)
	if err != nil {
		e.finish(&ev, rc, err)
		return e.smb1Negotiate(ctx, t, o) // SMB2 disabled: try the legacy dialect
	}
	o.Service, o.Confidence, o.Probe = "smb", 100, ProbeSMB
	o.Reason = "validated SMB2 negotiate response"
	addAttr(o, "smb.dialect", smbDialectName(neg.dialect))
	addAttr(o, "smb.signing", smbSigning(neg.securityMode))
	addAttr(o, "smb.server_guid", guidString(neg.serverGUID))
	if neg.capabilities&0x00000040 != 0 { // SMB2_GLOBAL_CAP_ENCRYPTION
		addAttr(o, "smb.encryption", "supported")
	}
	if !neg.systemTime.IsZero() {
		addAttr(o, "smb.system_time", neg.systemTime.Format(time.RFC3339))
	}
	if !neg.startTime.IsZero() {
		addAttr(o, "smb.server_start", neg.startTime.Format(time.RFC3339))
	}
	if info := e.smb2SessionNTLM(rc); info != nil {
		addAttr(o, "smb.target_name", info.targetName)
		addAttr(o, "smb.computer_name", info.nbComputer)
		addAttr(o, "smb.domain", info.nbDomain)
		addAttr(o, "smb.dns_computer", info.dnsComputer)
		addAttr(o, "smb.dns_domain", info.dnsDomain)
		addAttr(o, "smb.dns_forest", info.forest)
		if info.osVersion != "" {
			addAttr(o, "smb.os_version", info.osVersion)
			o.Product, o.Version = "Windows", info.osVersion
			o.Reason = "validated SMB2 negotiate and NTLM challenge"
		}
	}
	e.finish(&ev, rc, nil)
	matched = true
	return true
}

func smb1Header(command byte) []byte {
	h := make([]byte, 32)
	copy(h[0:4], []byte{0xFF, 'S', 'M', 'B'})
	h[4] = command
	return h
}

// smb1Negotiate confirms a server that only speaks SMBv1, a notable finding in
// its own right, and reports its signing policy. It opens its own connection
// and records its own evidence.
func (e *Engine) smb1Negotiate(ctx context.Context, t Target, o *observe.Observation) bool {
	ev := observe.Evidence{Probe: ProbeSMB, Layer: "tcp", Started: time.Now().UTC()}
	matched := false
	defer func() {
		if matched {
			ev.Matched = ProbeSMB
		}
		o.Evidence = append(o.Evidence, ev)
	}()
	timeout := e.timeout(ProbeSMB)
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		return false
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	if t.Port == 139 {
		if err := netbiosSession(rc); err != nil {
			e.finish(&ev, rc, err)
			return false
		}
	}
	dialects := append([]byte{0x02}, []byte("NT LM 0.12\x00")...)
	body := []byte{0x00, byte(len(dialects)), byte(len(dialects) >> 8)} // WordCount, ByteCount
	body = append(body, dialects...)
	if _, err := rc.Write(directTCP(append(smb1Header(0x72), body...))); err != nil {
		e.finish(&ev, rc, err)
		return false
	}
	resp, err := readSMBMessage(rc)
	e.finish(&ev, rc, err)
	if err != nil || len(resp) < 33 || resp[0] != 0xFF || resp[1] != 'S' || resp[2] != 'M' || resp[3] != 'B' || resp[4] != 0x72 {
		return false
	}
	o.Service, o.Confidence, o.Probe = "smb", 100, ProbeSMB
	o.Reason, o.Version = "validated SMBv1 negotiate response", "1"
	addAttr(o, "smb.version", "1")
	if wc := int(resp[32]); wc >= 2 && len(resp) > 35 {
		mode := resp[35]
		addAttr(o, "smb1.security_mode", fmt.Sprintf("0x%02x", mode))
		switch {
		case mode&0x08 != 0:
			addAttr(o, "smb.signing", "required")
		case mode&0x04 != 0:
			addAttr(o, "smb.signing", "enabled")
		default:
			addAttr(o, "smb.signing", "disabled")
		}
	}
	matched = true
	return true
}

// rdpConnRequest builds an X.224 Connection Request carrying an RDP
// Negotiation Request for the given security protocols.
func rdpConnRequest(protocols uint32) []byte {
	neg := make([]byte, 8)
	neg[0] = 0x01 // TYPE_RDP_NEG_REQ
	binary.LittleEndian.PutUint16(neg[2:4], 0x0008)
	binary.LittleEndian.PutUint32(neg[4:8], protocols)
	cotp := append([]byte{0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00}, neg...)
	cotp[0] = byte(len(cotp) - 1) // LI: octets after the length indicator
	return append([]byte{0x03, 0x00, byte((len(cotp) + 4) >> 8), byte(len(cotp) + 4)}, cotp...)
}

// readTPKT reads one TPKT-framed message and returns the X.224 payload.
func readTPKT(c net.Conn) ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, err
	}
	if h[0] != 0x03 {
		return nil, fmt.Errorf("not a TPKT header (0x%02x)", h[0])
	}
	n := int(h[2])<<8 | int(h[3])
	if n < 5 || n > 0x2000 {
		return nil, fmt.Errorf("invalid TPKT length %d", n)
	}
	buf := make([]byte, n-4)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func rdpProtocolName(p uint32) string {
	switch p {
	case 0:
		return "standard RDP security"
	case 1:
		return "TLS"
	case 2:
		return "CredSSP (NLA)"
	case 8:
		return "CredSSP with Early User Auth"
	}
	return fmt.Sprintf("0x%08x", p)
}

func rdpNLA(selected uint32) string {
	switch selected {
	case 2, 8:
		return "enabled"
	case 1:
		return "optional (TLS without NLA)"
	case 0:
		return "disabled"
	}
	return ""
}

func rdpFailureName(code uint32) string {
	switch code {
	case 1:
		return "SSL required by server"
	case 2:
		return "SSL not allowed by server"
	case 3:
		return "SSL certificate not on server"
	case 4:
		return "inconsistent flags"
	case 5:
		return "CredSSP (NLA) required by server"
	case 6:
		return "SSL with user auth required by server"
	}
	return fmt.Sprintf("0x%08x", code)
}

// probeRDP performs the RDP X.224 security negotiation and, when the server
// selects a TLS-based protocol, records the certificate it presents.
func (e *Engine) probeRDP(ctx context.Context, t Target, o *observe.Observation) bool {
	ev := observe.Evidence{Probe: ProbeRDP, Layer: "tcp", Started: time.Now().UTC()}
	matched := false
	defer func() {
		if matched {
			ev.Matched = ProbeRDP
		}
		o.Evidence = append(o.Evidence, ev)
	}()
	timeout := e.timeout(ProbeRDP)
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		return false
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	const requested = 0x0B // PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX
	if _, err := rc.Write(rdpConnRequest(requested)); err != nil {
		e.finish(&ev, rc, err)
		return false
	}
	resp, err := readTPKT(rc)
	if err != nil {
		e.finish(&ev, rc, err)
		return false
	}
	// A valid X.224 Connection Confirm (code 0xD0) identifies RDP.
	if len(resp) < 2 || resp[1]&0xF0 != 0xD0 {
		e.finish(&ev, rc, fmt.Errorf("not an X.224 connection confirm"))
		return false
	}
	o.Service, o.Confidence, o.Probe = "rdp", 100, ProbeRDP
	o.Reason = "validated RDP X.224 connection confirm"
	var selected uint32 = 0xffffffff
	if neg := resp[7:]; len(neg) >= 8 { // RDP negotiation field follows the fixed CC header
		switch neg[0] {
		case 0x02: // TYPE_RDP_NEG_RSP
			selected = binary.LittleEndian.Uint32(neg[4:8])
			addAttr(o, "rdp.security", rdpProtocolName(selected))
			addAttr(o, "rdp.nla", rdpNLA(selected))
		case 0x03: // TYPE_RDP_NEG_FAILURE
			addAttr(o, "rdp.negotiation_failure", rdpFailureName(binary.LittleEndian.Uint32(neg[4:8])))
			if binary.LittleEndian.Uint32(neg[4:8]) == 5 {
				addAttr(o, "rdp.nla", "required")
			}
		}
	} else {
		addAttr(o, "rdp.security", "standard RDP security")
		addAttr(o, "rdp.nla", "disabled")
	}
	// TLS and CredSSP both run a TLS handshake next; complete it to read the
	// certificate, which usually carries the host's own name.
	if selected == 1 || selected == 2 || selected == 8 {
		tc := tls.Client(rc, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, CipherSuites: clientCipherSuites})
		if tc.HandshakeContext(ctx) == nil {
			state := tc.ConnectionState()
			o.TLS = summarizeTLS(state)
			if len(state.PeerCertificates) > 0 {
				addAttr(o, "rdp.hostname", state.PeerCertificates[0].Subject.CommonName)
			}
		}
	}
	e.finish(&ev, rc, nil)
	matched = true
	return true
}

// dceRPCBind builds a connection-oriented DCE/RPC bind to the endpoint-mapper
// interface with the NDR transfer syntax.
func dceRPCBind() []byte {
	epmUUID := []byte{0x08, 0x83, 0xAF, 0xE1, 0x1F, 0x5D, 0xC9, 0x11, 0x91, 0xA4, 0x08, 0x00, 0x2B, 0x14, 0xA0, 0xFA}
	ndrUUID := []byte{0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60}
	var body bytes.Buffer
	putLE16(&body, 5840) // max_xmit_frag
	putLE16(&body, 5840) // max_recv_frag
	putLE32(&body, 0)    // assoc_group_id
	body.WriteByte(1)    // num context elements
	body.WriteByte(0)    // reserved
	putLE16(&body, 0)    // reserved2
	putLE16(&body, 0)    // p_cont_id
	body.WriteByte(1)    // n_transfer_syntaxes
	body.WriteByte(0)    // reserved
	body.Write(epmUUID)  // abstract syntax: EPM
	putLE16(&body, 3)    // interface version major
	putLE16(&body, 0)    // interface version minor
	body.Write(ndrUUID)  // transfer syntax: NDR
	putLE16(&body, 2)    // NDR version major
	putLE16(&body, 0)    // NDR version minor
	b := body.Bytes()
	hdr := make([]byte, 16)
	hdr[0], hdr[1], hdr[2], hdr[3] = 5, 0, 11, 0x03 // v5.0, bind, first+last frag
	hdr[4] = 0x10                                   // data representation: little-endian ASCII
	binary.LittleEndian.PutUint16(hdr[8:10], uint16(16+len(b)))
	binary.LittleEndian.PutUint32(hdr[12:16], 1) // call_id
	return append(hdr, b...)
}

// readDCERPC reads one connection-oriented DCE/RPC PDU.
func readDCERPC(c net.Conn) ([]byte, error) {
	var h [16]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, err
	}
	if h[0] != 5 {
		return nil, fmt.Errorf("not DCE/RPC (version %d)", h[0])
	}
	n := int(binary.LittleEndian.Uint16(h[8:10]))
	if n < 16 || n > 0x4000 {
		return nil, fmt.Errorf("invalid DCE/RPC fragment length %d", n)
	}
	buf := make([]byte, n)
	copy(buf, h[:])
	if _, err := io.ReadFull(c, buf[16:]); err != nil {
		return nil, err
	}
	return buf, nil
}

// probeMSRPC binds to the DCE/RPC endpoint mapper. A bind acknowledgement or a
// bind rejection both prove MSRPC; the acknowledgement also reports the
// server's secondary address.
func (e *Engine) probeMSRPC(ctx context.Context, t Target, o *observe.Observation) bool {
	ev := observe.Evidence{Probe: ProbeMSRPC, Layer: "tcp", Started: time.Now().UTC()}
	matched := false
	defer func() {
		if matched {
			ev.Matched = ProbeMSRPC
		}
		o.Evidence = append(o.Evidence, ev)
	}()
	timeout := e.timeout(ProbeMSRPC)
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		return false
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	if _, err := rc.Write(dceRPCBind()); err != nil {
		e.finish(&ev, rc, err)
		return false
	}
	resp, err := readDCERPC(rc)
	e.finish(&ev, rc, err)
	if err != nil || len(resp) < 16 || resp[0] != 5 {
		return false
	}
	switch resp[2] { // PTYPE
	case 12: // bind_ack
		o.Service, o.Confidence, o.Probe = "msrpc", 100, ProbeMSRPC
		o.Reason = "validated DCE/RPC bind acknowledgement"
		addAttr(o, "msrpc.bind", "ack")
		if len(resp) >= 26 {
			if secLen := int(binary.LittleEndian.Uint16(resp[24:26])); secLen > 0 && 26+secLen <= len(resp) {
				addAttr(o, "msrpc.endpoint", strings.TrimRight(string(resp[26:26+secLen]), "\x00"))
			}
		}
		matched = true
		return true
	case 13: // bind_nak
		o.Service, o.Confidence, o.Probe = "msrpc", 100, ProbeMSRPC
		o.Reason = "DCE/RPC bind rejected (endpoint mapper present)"
		addAttr(o, "msrpc.bind", "nak")
		if len(resp) >= 18 {
			addAttr(o, "msrpc.reject_reason", fmt.Sprintf("0x%04x", binary.LittleEndian.Uint16(resp[16:18])))
		}
		matched = true
		return true
	}
	return false
}
