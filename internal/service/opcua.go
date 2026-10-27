package service

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// OPC UA binary discovery (OPC 10000-6 §7, OPC 10000-4 §5.4.4). The probe
// sends Hello, opens a secure channel with SecurityPolicy None, calls
// GetEndpoints and closes the channel. GetEndpoints is a discovery service
// that every server must answer without a session. The probe never creates
// or activates a session, never presents credentials and never reads or
// writes the address space, so every attribute is discovery-level.

const (
	opcuaMaxMessage   = 1 << 17 // reassembled response bound
	opcuaMaxChunks    = 8
	opcuaMaxString    = 4096
	opcuaMaxArray     = 64
	opcuaMaxEndpoints = 32
	opcuaPolicyNone   = "http://opcfoundation.org/UA/SecurityPolicy#None"
)

// Binary encoding IDs (four-byte NodeIds in namespace 0).
const (
	opcuaOpenRequest       = 446
	opcuaOpenResponse      = 449
	opcuaCloseRequest      = 452
	opcuaGetEndpointsReq   = 428
	opcuaGetEndpointsResp  = 431
	opcuaServiceFault      = 397
	opcuaSecurityModeNone  = 1
	opcuaRequestTimeoutMs  = 3000
	opcuaRequestedLifetime = 60000
)

type uaWriter struct{ b []byte }

func (w *uaWriter) u8(v byte)    { w.b = append(w.b, v) }
func (w *uaWriter) u32(v uint32) { w.b = binary.LittleEndian.AppendUint32(w.b, v) }
func (w *uaWriter) i32(v int32)  { w.u32(uint32(v)) }
func (w *uaWriter) u64(v uint64) { w.b = binary.LittleEndian.AppendUint64(w.b, v) }
func (w *uaWriter) str(s string) {
	w.i32(int32(len(s)))
	w.b = append(w.b, s...)
}
func (w *uaWriter) null()            { w.i32(-1) } // null String, ByteString or array
func (w *uaWriter) nodeID(id uint16) { w.b = append(w.b, 1, 0, byte(id), byte(id>>8)) }

// requestHeader writes a header without an authentication token: every
// request here is sessionless.
func (w *uaWriter) requestHeader(handle uint32) {
	w.b = append(w.b, 0, 0) // null NodeId authentication token
	w.u64(0)                // timestamp: not needed by the server
	w.u32(handle)
	w.u32(0) // return no diagnostics
	w.null() // audit entry ID
	w.u32(opcuaRequestTimeoutMs)
	w.b = append(w.b, 0, 0, 0) // null additional header
}

func opcuaFrame(kind string, body []byte) []byte {
	out := append([]byte(kind+"F"), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(out[4:], uint32(8+len(body)))
	return append(out, body...)
}

func opcuaHello(endpoint string) []byte {
	var w uaWriter
	w.u32(0)               // protocol version
	w.u32(65536)           // receive buffer
	w.u32(65536)           // send buffer
	w.u32(opcuaMaxMessage) // max message size
	w.u32(opcuaMaxChunks)
	w.str(endpoint)
	return opcuaFrame("HEL", w.b)
}

func opcuaOpen() []byte {
	var w uaWriter
	w.u32(0) // secure channel ID: assigned by the server
	w.str(opcuaPolicyNone)
	w.null() // sender certificate
	w.null() // receiver thumbprint
	w.u32(1) // sequence number
	w.u32(1) // request ID
	w.nodeID(opcuaOpenRequest)
	w.requestHeader(1)
	w.u32(0) // client protocol version
	w.u32(0) // issue
	w.u32(opcuaSecurityModeNone)
	w.null() // client nonce
	w.u32(opcuaRequestedLifetime)
	return opcuaFrame("OPN", w.b)
}

func opcuaMessage(kind string, channel, token, seq uint32, typ uint16, body func(*uaWriter)) []byte {
	var w uaWriter
	w.u32(channel)
	w.u32(token)
	w.u32(seq)
	w.u32(seq) // request ID follows the sequence number
	w.nodeID(typ)
	w.requestHeader(seq)
	body(&w)
	return opcuaFrame(kind, w.b)
}

type uaReader struct {
	b   []byte
	err error
}

func (r *uaReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *uaReader) u8() byte {
	if v := r.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (r *uaReader) u32() uint32 {
	if v := r.take(4); v != nil {
		return binary.LittleEndian.Uint32(v)
	}
	return 0
}

// bytes reads a String or ByteString; null and empty both return nil.
func (r *uaReader) bytes(limit int) []byte {
	n := int32(r.u32())
	if r.err != nil || n <= 0 {
		return nil
	}
	if int(n) > limit {
		r.err = fmt.Errorf("OPC UA string of %d bytes exceeds %d", n, limit)
		return nil
	}
	return r.take(int(n))
}

func (r *uaReader) str() string { return printable(r.bytes(opcuaMaxString), 256) }

func (r *uaReader) arrayLen() int {
	n := int32(r.u32())
	if n > opcuaMaxArray && r.err == nil {
		r.err = fmt.Errorf("OPC UA array of %d elements exceeds %d", n, opcuaMaxArray)
	}
	return max(int(n), 0)
}

// nodeID reads any NodeId encoding and returns the numeric ID, or 0.
func (r *uaReader) nodeID() uint32 {
	switch enc := r.u8(); enc & 0x3f {
	case 0:
		return uint32(r.u8())
	case 1:
		r.take(1)
		return uint32(r.u8()) | uint32(r.u8())<<8
	case 2:
		r.take(2)
		return r.u32()
	case 3:
		r.take(2)
		r.bytes(opcuaMaxString)
	case 4:
		r.take(2 + 16)
	case 5:
		r.take(2)
		r.bytes(opcuaMaxString)
	default:
		r.err = fmt.Errorf("unsupported NodeId encoding %#x", enc)
	}
	return 0
}

func (r *uaReader) localizedText() string {
	mask := r.u8()
	if mask&1 != 0 {
		r.str() // locale
	}
	if mask&2 != 0 {
		return r.str()
	}
	return ""
}

// diagnosticInfo skips a DiagnosticInfo, which may nest once per level.
func (r *uaReader) diagnosticInfo(depth int) {
	mask := r.u8()
	for _, bit := range []byte{1, 2, 4, 8} { // symbolic ID, namespace, localized text, locale
		if mask&bit != 0 {
			r.take(4)
		}
	}
	if mask&0x10 != 0 {
		r.bytes(opcuaMaxString)
	}
	if mask&0x20 != 0 {
		r.take(4)
	}
	if mask&0x40 != 0 {
		if depth > 4 {
			r.err = errors.New("OPC UA diagnostics nested too deeply")
			return
		}
		r.diagnosticInfo(depth + 1)
	}
}

// responseHeader skips to the service body and returns the status code.
func (r *uaReader) responseHeader() uint32 {
	r.take(8 + 4) // timestamp, request handle
	status := r.u32()
	r.diagnosticInfo(0)
	for i, n := 0, r.arrayLen(); i < n && r.err == nil; i++ {
		r.bytes(opcuaMaxString)
	}
	r.nodeID() // additional header type
	if r.u8()&1 != 0 {
		r.bytes(opcuaMaxString)
	}
	return status
}

// readOPCUA reads one message, reassembling intermediate chunks. It returns
// the message type and the body after the 8-byte header of the final chunk.
func readOPCUA(c net.Conn) (string, []byte, error) {
	var body []byte
	for chunk := 0; chunk < opcuaMaxChunks; chunk++ {
		var h [8]byte
		if _, err := io.ReadFull(c, h[:]); err != nil {
			return "", nil, err
		}
		kind, size := string(h[:3]), int(binary.LittleEndian.Uint32(h[4:]))
		if !slices.Contains([]string{"ACK", "ERR", "OPN", "MSG", "CLO"}, kind) || size < 8 || len(body)+size > opcuaMaxMessage {
			return "", nil, fmt.Errorf("invalid OPC UA message header %x", h)
		}
		part := make([]byte, size-8)
		if _, err := io.ReadFull(c, part); err != nil {
			return "", nil, err
		}
		if h[3] != 'F' && h[3] != 'C' {
			return "", nil, fmt.Errorf("OPC UA chunk aborted (%q)", h[3])
		}
		if chunk > 0 {
			// Later chunks repeat the channel, token, sequence number and
			// request ID; keep the first copy only.
			if kind != "MSG" || len(part) < 16 {
				return "", nil, errors.New("invalid OPC UA continuation chunk")
			}
			part = part[16:]
		}
		body = append(body, part...)
		if h[3] == 'F' {
			return kind, body, nil
		}
		if kind != "MSG" {
			return "", nil, errors.New("only MSG may be chunked")
		}
	}
	return "", nil, errors.New("too many OPC UA chunks")
}

// opcuaEndpoint is one EndpointDescription returned by GetEndpoints.
type opcuaEndpoint struct {
	url, applicationURI, productURI, applicationName, policy string
	applicationType, mode                                    uint32
	certificate                                              []byte
	tokens                                                   []uint32
	level                                                    byte
}

func parseEndpoints(r *uaReader) []opcuaEndpoint {
	var out []opcuaEndpoint
	n := r.arrayLen()
	for i := 0; i < n && r.err == nil; i++ {
		var ep opcuaEndpoint
		ep.url = r.str()
		ep.applicationURI, ep.productURI, ep.applicationName = r.str(), r.str(), r.localizedText()
		ep.applicationType = r.u32()
		r.str() // gateway server URI
		r.str() // discovery profile URI
		for j, m := 0, r.arrayLen(); j < m && r.err == nil; j++ {
			r.str() // discovery URLs
		}
		ep.certificate = r.bytes(opcuaMaxMessage)
		ep.mode = r.u32()
		ep.policy = r.str()
		for j, m := 0, r.arrayLen(); j < m && r.err == nil; j++ {
			r.str() // policy ID
			ep.tokens = append(ep.tokens, r.u32())
			r.str() // issued token type
			r.str() // issuer endpoint URL
			r.str() // security policy URI
		}
		r.str() // transport profile URI
		ep.level = r.u8()
		if r.err == nil && len(out) < opcuaMaxEndpoints {
			out = append(out, ep)
		}
	}
	return out
}

var opcuaModes = map[uint32]string{1: "None", 2: "Sign", 3: "SignAndEncrypt"}
var opcuaTokens = map[uint32]string{0: "anonymous", 1: "username", 2: "certificate", 3: "issued-token"}
var opcuaAppTypes = map[uint32]string{0: "server", 1: "client", 2: "client-and-server", 3: "discovery-server"}

// probeOPCUA identifies an OPC UA server from its discovery endpoints.
func (e *Engine) probeOPCUA(ctx context.Context, t Target, o *observe.Observation) bool {
	ev := observe.Evidence{Probe: ProbeOPCUA, Layer: "tcp", Started: time.Now().UTC()}
	defer func() { o.Evidence = append(o.Evidence, ev) }()
	timeout := e.timeout(ProbeOPCUA)
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		return false
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	host := t.serverName()
	if host == "" {
		host = t.Addr.String()
	}
	endpoint := "opc.tcp://" + net.JoinHostPort(host, strconv.Itoa(int(t.Port)))
	endpoints, err := e.opcuaDiscover(rc, endpoint)
	e.finish(&ev, rc, err)
	if err != nil || len(endpoints) == 0 {
		if err == nil {
			ev.Error = "OPC UA server returned no endpoints"
		}
		return false
	}
	attrs := map[string]string{"opcua.access": "discovery", "opcua.endpoint_count": strconv.Itoa(len(endpoints))}
	var modes, policies, tokens []string
	addUnique := func(list *[]string, v string) {
		if v != "" && !slices.Contains(*list, v) {
			*list = append(*list, v)
		}
	}
	for _, ep := range endpoints {
		addUnique(&modes, opcuaModes[ep.mode])
		addUnique(&policies, strings.TrimPrefix(ep.policy, "http://opcfoundation.org/UA/SecurityPolicy#"))
		for _, tok := range ep.tokens {
			addUnique(&tokens, opcuaTokens[tok])
		}
	}
	server := endpoints[0]
	for key, value := range map[string]string{
		"opcua.application_uri": server.applicationURI, "opcua.product_uri": server.productURI,
		"opcua.application_name": server.applicationName, "opcua.application_type": opcuaAppTypes[server.applicationType],
		"opcua.endpoint_url": server.url, "opcua.security_modes": strings.Join(modes, ","),
		"opcua.security_policies": strings.Join(policies, ","), "opcua.user_token_types": strings.Join(tokens, ","),
	} {
		if value != "" {
			attrs[key] = value
		}
	}
	// Offered token types are advertised policy, not a login attempt.
	attrs["opcua.anonymous_offered"] = strconv.FormatBool(slices.Contains(tokens, "anonymous"))
	for _, ep := range endpoints {
		if len(ep.certificate) == 0 {
			continue
		}
		sum := sha256.Sum256(ep.certificate)
		attrs["opcua.certificate_sha256"] = hex.EncodeToString(sum[:])
		if certs, err := x509.ParseCertificates(ep.certificate); err == nil && len(certs) > 0 {
			leaf := sha256.Sum256(certs[0].Raw)
			attrs["opcua.certificate_sha256"] = hex.EncodeToString(leaf[:])
			attrs["opcua.certificate_subject"] = certs[0].Subject.String()
			attrs["opcua.certificate_not_after"] = certs[0].NotAfter.UTC().Format(time.RFC3339)
		}
		break
	}
	o.Service, o.Attributes = ProbeOPCUA, attrs
	o.Product = server.applicationName
	o.Confidence, o.Probe = 100, ProbeOPCUA
	o.Reason = "validated OPC UA GetEndpoints discovery response"
	ev.Matched = ProbeOPCUA
	return true
}

// opcuaDiscover runs Hello, OpenSecureChannel(None), GetEndpoints and
// CloseSecureChannel on one connection.
func (e *Engine) opcuaDiscover(c net.Conn, endpoint string) ([]opcuaEndpoint, error) {
	if _, err := c.Write(opcuaHello(endpoint)); err != nil {
		return nil, err
	}
	kind, body, err := readOPCUA(c)
	if err != nil {
		return nil, err
	}
	if kind == "ERR" {
		r := uaReader{b: body}
		code := r.u32()
		return nil, fmt.Errorf("OPC UA error %#08x: %s", code, r.str())
	}
	if kind != "ACK" || len(body) < 20 {
		return nil, errors.New("OPC UA Hello not acknowledged")
	}
	if _, err := c.Write(opcuaOpen()); err != nil {
		return nil, err
	}
	kind, body, err = readOPCUA(c)
	if err != nil {
		return nil, err
	}
	r := uaReader{b: body}
	channel := r.u32()
	if kind != "OPN" || r.str() != opcuaPolicyNone {
		return nil, errors.New("OPC UA secure channel refused")
	}
	r.bytes(opcuaMaxMessage) // sender certificate
	r.bytes(opcuaMaxString)  // receiver thumbprint
	r.take(8)                // sequence number, request ID
	if id := r.nodeID(); id != opcuaOpenResponse || r.err != nil {
		return nil, fmt.Errorf("unexpected OPC UA open response %d", id)
	}
	if status := r.responseHeader(); status != 0 {
		return nil, fmt.Errorf("OPC UA open status %#08x", status)
	}
	r.u32() // server protocol version
	r.u32() // channel ID again
	token := r.u32()
	if r.err != nil {
		return nil, r.err
	}
	request := opcuaMessage("MSG", channel, token, 2, opcuaGetEndpointsReq, func(w *uaWriter) {
		w.str(endpoint)
		w.null() // locale IDs
		w.null() // profile URIs
	})
	if _, err := c.Write(request); err != nil {
		return nil, err
	}
	kind, body, err = readOPCUA(c)
	if err != nil {
		return nil, err
	}
	// Best effort: the channel is closed on our side either way.
	_, _ = c.Write(opcuaMessage("CLO", channel, token, 3, opcuaCloseRequest, func(*uaWriter) {}))
	if kind != "MSG" {
		return nil, errors.New("unexpected OPC UA response type " + kind)
	}
	r = uaReader{b: body}
	r.take(16) // channel, token, sequence number, request ID
	switch id := r.nodeID(); {
	case r.err != nil:
		return nil, r.err
	case id == opcuaServiceFault:
		return nil, fmt.Errorf("OPC UA service fault %#08x", r.responseHeader())
	case id != opcuaGetEndpointsResp:
		return nil, fmt.Errorf("unexpected OPC UA response %d", id)
	}
	if status := r.responseHeader(); status != 0 {
		return nil, fmt.Errorf("OPC UA GetEndpoints status %#08x", status)
	}
	endpoints := parseEndpoints(&r)
	return endpoints, r.err
}
