package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/matusso/nyxr/internal/observe"
)

// opcuaSim answers Hello, OpenSecureChannel(None), GetEndpoints and
// CloseSecureChannel like a discovery-capable server. Any other service,
// such as CreateSession, is recorded as a violation.
type opcuaSim struct {
	helloError bool
	fault      bool
	chunked    bool
	hugeString bool
	cert       []byte
	mu         sync.Mutex
	received   [][]byte
	services   []uint32
	violation  string
}

func uaFrame(kind string, final byte, body []byte) []byte {
	out := append([]byte(kind), final, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(out[4:], uint32(8+len(body)))
	return append(out, body...)
}

func uaResponseHeader(w *uaWriter, status uint32) {
	w.u64(0)
	w.u32(1)
	w.u32(status)
	w.u8(0)  // diagnostics
	w.null() // string table
	w.b = append(w.b, 0, 0, 0)
}

func (s *opcuaSim) endpoints(w *uaWriter) {
	type ep struct {
		mode   uint32
		policy string
		tokens []uint32
	}
	list := []ep{{1, opcuaPolicyNone, []uint32{0}}, {3, "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256", []uint32{1, 2}}}
	w.i32(int32(len(list)))
	for _, e := range list {
		w.str("opc.tcp://plc.example.test:4840")
		w.str("urn:example:plc:server")
		w.str("urn:example:product")
		w.u8(2)
		if s.hugeString {
			w.i32(opcuaMaxString + 1)
		} else {
			w.str("Example OPC UA Server")
		}
		w.u32(0) // server
		w.null()
		w.null()
		w.i32(1)
		w.str("opc.tcp://plc.example.test:4840")
		if e.mode == 1 {
			w.null()
		} else {
			w.i32(int32(len(s.cert)))
			w.b = append(w.b, s.cert...)
		}
		w.u32(e.mode)
		w.str(e.policy)
		w.i32(int32(len(e.tokens)))
		for _, tok := range e.tokens {
			w.str("policy")
			w.u32(tok)
			w.null()
			w.null()
			w.null()
		}
		w.str("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary")
		w.u8(byte(e.mode))
	}
}

func (s *opcuaSim) fail(reason string) {
	s.mu.Lock()
	s.violation = reason
	s.mu.Unlock()
}

func (s *opcuaSim) serve(c net.Conn) {
	var got bytes.Buffer
	defer func() {
		s.mu.Lock()
		s.received = append(s.received, got.Bytes())
		s.mu.Unlock()
	}()
	in := io.TeeReader(c, &got)
	read := func() (string, []byte) {
		var h [8]byte
		if _, err := io.ReadFull(in, h[:]); err != nil {
			return "", nil
		}
		body := make([]byte, binary.LittleEndian.Uint32(h[4:])-8)
		if _, err := io.ReadFull(in, body); err != nil {
			return "", nil
		}
		return string(h[:3]), body
	}
	if kind, _ := read(); kind != "HEL" {
		s.fail("expected Hello")
		return
	}
	if s.helloError {
		var w uaWriter
		w.u32(0x807f0000)
		w.str("endpoint URL rejected")
		_, _ = c.Write(uaFrame("ERR", 'F', w.b))
		return
	}
	var ack uaWriter
	for _, v := range []uint32{0, 65536, 65536, 1 << 17, 8} {
		ack.u32(v)
	}
	_, _ = c.Write(uaFrame("ACK", 'F', ack.b))
	kind, body := read()
	r := uaReader{b: body}
	r.u32()
	if kind != "OPN" || r.str() != opcuaPolicyNone {
		s.fail("expected OpenSecureChannel with SecurityPolicy None")
		return
	}
	var opn uaWriter
	opn.u32(7)
	opn.str(opcuaPolicyNone)
	opn.null()
	opn.null()
	opn.u32(1)
	opn.u32(1)
	opn.nodeID(opcuaOpenResponse)
	uaResponseHeader(&opn, 0)
	opn.u32(0)
	opn.u32(7)  // channel
	opn.u32(11) // token
	opn.u64(0)
	opn.u32(60000)
	opn.null()
	_, _ = c.Write(uaFrame("OPN", 'F', opn.b))
	for {
		kind, body := read()
		if kind == "" {
			return
		}
		r := uaReader{b: body}
		channel, token := r.u32(), r.u32()
		r.take(8)
		service := r.nodeID()
		s.mu.Lock()
		s.services = append(s.services, service)
		s.mu.Unlock()
		if channel != 7 || token != 11 {
			s.fail("wrong secure channel or token")
			return
		}
		switch {
		case kind == "CLO" && service == opcuaCloseRequest:
			return
		case kind != "MSG" || service != opcuaGetEndpointsReq:
			s.fail("unexpected service")
			return
		}
		var resp uaWriter
		resp.u32(7)
		resp.u32(11)
		resp.u32(2)
		resp.u32(2)
		if s.fault {
			resp.nodeID(opcuaServiceFault)
			uaResponseHeader(&resp, 0x80010000)
			_, _ = c.Write(uaFrame("MSG", 'F', resp.b))
			continue
		}
		resp.nodeID(opcuaGetEndpointsResp)
		uaResponseHeader(&resp, 0)
		s.endpoints(&resp)
		if s.chunked {
			split := 16 + 40
			first := resp.b[:split]
			second := append(append([]byte(nil), resp.b[:16]...), resp.b[split:]...)
			_, _ = c.Write(append(uaFrame("MSG", 'C', first), uaFrame("MSG", 'F', second)...))
			continue
		}
		_, _ = c.Write(uaFrame("MSG", 'F', resp.b))
	}
}

var opcuaTarget = Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 4840}

func TestOPCUADiscovery(t *testing.T) {
	cert := testCertificate(t, "plc.example.test").Certificate[0]
	for _, chunked := range []bool{false, true} {
		sim := &opcuaSim{cert: cert, chunked: chunked}
		o := identityEngine(t, ProbeOPCUA, sim.serve).Interrogate(context.Background(), opcuaTarget)
		if sim.violation != "" {
			t.Fatal(sim.violation)
		}
		if o.Service != ProbeOPCUA || o.Product != "Example OPC UA Server" || o.Version != "" || o.Confidence != 100 || o.Fingerprint != observe.FingerprintMatched {
			t.Fatalf("chunked=%v identity: %+v", chunked, o)
		}
		sum := sha256.Sum256(cert)
		want := map[string]string{"opcua.access": "discovery", "opcua.application_uri": "urn:example:plc:server",
			"opcua.product_uri": "urn:example:product", "opcua.application_type": "server", "opcua.endpoint_count": "2",
			"opcua.security_modes": "None,SignAndEncrypt", "opcua.security_policies": "None,Basic256Sha256",
			"opcua.user_token_types": "anonymous,username,certificate", "opcua.anonymous_offered": "true",
			"opcua.certificate_sha256": hex.EncodeToString(sum[:]), "opcua.certificate_subject": "CN=plc.example.test"}
		for k, v := range want {
			if o.Attributes[k] != v {
				t.Errorf("chunked=%v %s = %q, want %q", chunked, k, o.Attributes[k], v)
			}
		}
		checkAudit(t, o, &sim.mu, &sim.received)
		sim.mu.Lock()
		services := sim.services
		sim.mu.Unlock()
		if len(services) != 2 || services[0] != opcuaGetEndpointsReq || services[1] != opcuaCloseRequest {
			t.Fatalf("only GetEndpoints and CloseSecureChannel may be called: %v", services)
		}
	}
}

func TestOPCUANegativeCases(t *testing.T) {
	for name, sim := range map[string]*opcuaSim{
		"hello error":   {helloError: true},
		"service fault": {fault: true},
		"huge string":   {hugeString: true},
	} {
		o := identityEngine(t, ProbeOPCUA, sim.serve).Interrogate(context.Background(), opcuaTarget)
		if o.Service != "" || len(o.Evidence) != 1 || o.Evidence[0].Error == "" {
			t.Fatalf("%s must not identify and must explain why: %+v", name, o.Evidence)
		}
		if name == "hello error" && !strings.Contains(o.Evidence[0].Error, "endpoint URL rejected") {
			t.Fatalf("ERR reason lost: %s", o.Evidence[0].Error)
		}
		checkAudit(t, o, &sim.mu, &sim.received)
	}
	// Truncated: the server closes after half of the acknowledgement.
	e := identityEngine(t, ProbeOPCUA, func(c net.Conn) {
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		_, _ = c.Write(uaFrame("ACK", 'F', make([]byte, 20))[:12])
	})
	if o := e.Interrogate(context.Background(), opcuaTarget); o.Service != "" || o.Evidence[0].Error == "" {
		t.Fatalf("truncated acknowledgement: %+v", o)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sim := &opcuaSim{}
	var obs observe.Observation
	if identityEngine(t, ProbeOPCUA, sim.serve).probeOPCUA(ctx, opcuaTarget, &obs) || len(sim.received) != 0 {
		t.Fatalf("canceled probe transmitted: %+v", obs)
	}
}

func TestOPCUAHostnameEndpointURL(t *testing.T) {
	var hello []byte
	var mu sync.Mutex
	e := identityEngine(t, ProbeOPCUA, func(c net.Conn) {
		buf := make([]byte, 256)
		n, _ := c.Read(buf)
		mu.Lock()
		hello = buf[:n]
		mu.Unlock()
	})
	target := opcuaTarget
	target.Hostnames = []string{"plc.example.test"}
	e.Interrogate(context.Background(), target)
	mu.Lock()
	defer mu.Unlock()
	if !bytes.Contains(hello, []byte("opc.tcp://plc.example.test:4840")) {
		t.Fatalf("Hello must name the operator's hostname: %q", hello)
	}
}

func FuzzOPCUAEndpoints(f *testing.F) {
	var w uaWriter
	uaResponseHeader(&w, 0)
	(&opcuaSim{cert: []byte{1, 2, 3}}).endpoints(&w)
	f.Add(w.b)
	f.Fuzz(func(t *testing.T, data []byte) {
		r := uaReader{b: data}
		r.responseHeader()
		if eps := parseEndpoints(&r); len(eps) > opcuaMaxEndpoints {
			t.Fatalf("unbounded endpoints: %d", len(eps))
		}
	})
}
