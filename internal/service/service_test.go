package service

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

func testEngine(t *testing.T, fallback ...string) *Engine {
	t.Helper()
	e, err := Start(context.Background(), Config{Probes: Names(), Fallback: fallback, Timeout: 600 * time.Millisecond, Workers: 1}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

func targetOf(t *testing.T, addr string) Target {
	t.Helper()
	ap := netip.MustParseAddrPort(addr)
	return Target{Addr: ap.Addr(), Port: ap.Port()}
}

// serve accepts connections and runs handle on each until the test ends.
func serve(t *testing.T, handle func(net.Conn)) Target {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	return targetOf(t, ln.Addr().String())
}

func TestSSHBannerIdentified(t *testing.T) {
	target := serve(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")
		time.Sleep(500 * time.Millisecond)
	})
	o := testEngine(t).Interrogate(context.Background(), target)
	if o.Service != "ssh" || o.Product != "OpenSSH" || o.Version != "9.6p1" || o.Confidence != 100 || o.Fingerprint != observe.FingerprintMatched {
		t.Fatalf("unexpected SSH identity: %+v", o)
	}
	if o.Attributes["ssh.comment"] != "Ubuntu-3ubuntu13.5" || len(o.Evidence) != 1 || o.Evidence[0].Matched != "ssh" {
		t.Fatalf("SSH evidence missing: %+v", o)
	}
	if !strings.HasPrefix(string(o.Evidence[0].Response), "SSH-2.0-") || len(o.Evidence[0].Request) != 0 {
		t.Fatal("banner probe must be passive and retain the banner")
	}
}

func TestUnknownBannerRetained(t *testing.T) {
	target := serve(t, func(c net.Conn) { _, _ = c.Write([]byte("\x00\x01WEIRD-PROTO ready\r\n")) })
	o := testEngine(t).Interrogate(context.Background(), target)
	if o.Service != "" || o.Fingerprint != observe.FingerprintUnknown || o.Attributes["banner"] != "..WEIRD-PROTO ready" {
		t.Fatalf("unknown banner must be retained, not guessed: %+v", o)
	}
	if string(o.Evidence[0].Response) != "\x00\x01WEIRD-PROTO ready\r\n" {
		t.Fatalf("raw bytes lost: %q", o.Evidence[0].Response)
	}
}

func TestHTTPIdentifiedByFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		w.Header().Set("Server", "nginx/1.25.3 (Ubuntu)")
		_, _ = io.WriteString(w, "<html><head><title> Welcome\n to nginx </title></head></html>")
	}))
	defer srv.Close()
	target := targetOf(t, srv.Listener.Addr().String())
	if o := testEngine(t).Interrogate(context.Background(), target); o.Service != "" {
		t.Fatalf("an unhinted port without fallback must stay unidentified: %+v", o)
	}
	o := testEngine(t, ProbeHTTP).Interrogate(context.Background(), target)
	if o.Service != "http" || o.Product != "nginx" || o.Version != "1.25.3" || o.Attributes["http.title"] != "Welcome  to nginx" || o.Attributes["http.status"] != "200" {
		t.Fatalf("unexpected HTTP identity: %+v", o)
	}
	last := o.Evidence[len(o.Evidence)-1]
	if last.Matched != "http" || !strings.HasPrefix(string(last.Request), "GET / HTTP/1.1\r\n") || !strings.HasPrefix(string(last.Response), "HTTP/1.1 200") {
		t.Fatalf("HTTP evidence incomplete: %+v", last)
	}
}

func TestHTTPSWithCertificateAndALPN(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Caddy")
		}))
		srv.EnableHTTP2 = h2
		srv.StartTLS()
		target := targetOf(t, srv.Listener.Addr().String())
		o := testEngine(t, ProbeTLS, ProbeHTTP).Interrogate(context.Background(), target)
		srv.Close()
		if o.Service != "https" || o.Product != "Caddy" || o.TLS == nil || o.Fingerprint != observe.FingerprintMatched {
			t.Fatalf("h2=%v: unexpected HTTPS identity: %+v", h2, o)
		}
		// The TLS record describes the first handshake, even when a second
		// HTTP/1.1-only connection read the response head.
		if want := map[bool]string{false: "http/1.1", true: "h2"}[h2]; o.TLS.ALPN != want {
			t.Fatalf("h2=%v: ALPN %q, want %q", h2, o.TLS.ALPN, want)
		}
		if len(o.TLS.Certificates) == 0 || o.TLS.Certificates[0].SHA256 == "" || o.TLS.Certificates[0].KeyBits == 0 {
			t.Fatalf("certificate chain not recorded: %+v", o.TLS)
		}
		var handshake bool
		for _, ev := range o.Evidence {
			if ev.Probe == "tls" && ev.Matched == "tls" && len(ev.Request) > 0 && ev.Request[0] == 0x16 && len(ev.Response) > 0 && ev.Response[0] == 0x16 {
				handshake = true
			}
		}
		if !handshake {
			t.Fatalf("raw handshake records not retained: %+v", o.Evidence)
		}
	}
}

func TestPlainHTTPOnTLSPortFallsBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	real := targetOf(t, srv.Listener.Addr().String())
	e, err := Start(context.Background(), Config{Probes: Names(), Timeout: 600 * time.Millisecond, Workers: 1,
		// Pretend the server listens on 443 so the TLS-first hint applies.
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(real.Addr.String(), strconv.Itoa(int(real.Port))))
		}}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	o := e.Interrogate(context.Background(), Target{Addr: real.Addr, Port: 443})
	if o.Service != "http" || o.TLS != nil {
		t.Fatalf("plain HTTP on 443 must be identified as http: %+v", o)
	}
	if got := strings.Join(o.ProbesAttempted, ","); got != "banner,tls,http" {
		t.Fatalf("probe order %s", got)
	}
}

func TestDNSVersionBind(t *testing.T) {
	target := serve(t, func(c net.Conn) {
		var length [2]byte
		if _, err := io.ReadFull(c, length[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		resp := append([]byte(nil), q...)
		resp[2], resp[3] = 0x84, 0x00 // QR, AA, NOERROR
		resp[7] = 1                   // ANCOUNT
		txt := "9.18.24-1-Debian"
		resp = append(resp, 0xc0, 12, 0, 16, 0, 3, 0, 0, 0, 0, 0, byte(len(txt)+1), byte(len(txt)))
		resp = append(resp, txt...)
		binary.BigEndian.PutUint16(length[:], uint16(len(resp)))
		_, _ = c.Write(append(length[:], resp...))
	})
	e := testEngine(t)
	// Exercise the DNS probe directly: the loopback port is not 53.
	var o observe.Observation
	if !e.probeDNS(context.Background(), target, &o) {
		t.Fatalf("DNS not identified: %+v", o)
	}
	if o.Service != "dns" || o.Attributes["dns.version_bind"] != "9.18.24-1-Debian" || o.Attributes["dns.rcode"] != "0" {
		t.Fatalf("unexpected DNS identity: %+v", o)
	}
}

func TestDNSRejectsMismatchedID(t *testing.T) {
	msg := []byte{0x12, 0x34, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, _, err := parseDNSResponse(msg, 0x1235); err == nil {
		t.Fatal("mismatched transaction ID accepted")
	}
	if _, _, err := parseDNSResponse(msg[:11], 0x1234); err == nil {
		t.Fatal("short message accepted")
	}
}

func TestSilentPortReportsUnknownWithEvidence(t *testing.T) {
	target := serve(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	e, err := Start(context.Background(), Config{Probes: Names(), Fallback: []string{ProbeHTTP}, Timeout: 300 * time.Millisecond, Workers: 1}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	o := e.Interrogate(context.Background(), target)
	if o.Service != "" || o.Fingerprint != observe.FingerprintUnknown || len(o.Evidence) != 2 || o.Reason != "no probe matched" {
		t.Fatalf("silent service: %+v", o)
	}
	if o.Evidence[1].Error != "timeout" || len(o.Evidence[1].Request) == 0 {
		t.Fatalf("the unanswered request must be kept: %+v", o.Evidence[1])
	}
}

func TestClosedPortReportsError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := targetOf(t, ln.Addr().String())
	_ = ln.Close()
	o := testEngine(t).Interrogate(context.Background(), target)
	if o.State != "error" || !strings.Contains(o.Reason, "banner connection failed") {
		t.Fatalf("closed port: %+v", o)
	}
}

func TestEngineQueueEmitsEverySubmission(t *testing.T) {
	target := serve(t, func(c net.Conn) { _, _ = io.WriteString(c, "SSH-2.0-dropbear_2022.83\r\n") })
	var mu sync.Mutex
	var got []observe.Observation
	e, err := Start(context.Background(), Config{Probes: []string{ProbeBanner, ProbeSSH}, Timeout: time.Second, Workers: 2, QueueSize: 1, Rate: 200},
		func(o observe.Observation) { mu.Lock(); got = append(got, o); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := e.Submit(context.Background(), target); err != nil {
			t.Fatal(err)
		}
	}
	e.Close()
	if len(got) != 5 {
		t.Fatalf("want 5 observations, got %d", len(got))
	}
	for _, o := range got {
		if o.Product != "dropbear" || o.Version != "2022.83" {
			t.Fatalf("unexpected: %+v", o)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	for _, c := range []Config{
		{Probes: Names(), Timeout: time.Second},
		{Probes: Names(), Workers: 1},
		{Workers: 1, Timeout: time.Second},
		{Probes: []string{"telnet"}, Workers: 1, Timeout: time.Second},
		{Probes: Names(), Fallback: []string{"ftp"}, Workers: 1, Timeout: time.Second},
	} {
		if c.Validate() == nil {
			t.Fatalf("accepted invalid config %+v", c)
		}
	}
}
