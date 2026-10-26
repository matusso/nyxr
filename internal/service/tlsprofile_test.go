package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

func testCertificate(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serveTLS runs a TLS 1.2+ listener whose certificate depends on the SNI it
// receives, and records every SNI.
func serveTLS(t *testing.T, cert func(sni string) (*tls.Certificate, error)) (Target, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12,
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			seen = append(seen, h.ServerName)
			mu.Unlock()
			return cert(h.ServerName)
		}})
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
			go func() { defer c.Close(); _ = c.(*tls.Conn).Handshake(); time.Sleep(50 * time.Millisecond) }()
		}
	}()
	return targetOf(t, ln.Addr().String()), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func tlsProfileEngine(t *testing.T, profiles ...string) *Engine {
	t.Helper()
	e, err := Start(context.Background(), Config{Probes: []string{ProbeTLS}, Fallback: []string{ProbeTLS}, TLSProfiles: profiles,
		Timeout: 800 * time.Millisecond, Workers: 1}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

func profileResult(o observe.Observation, profile, serverName string) (observe.TLSProfileResult, bool) {
	for _, r := range o.TLS.Profiles {
		if r.Profile == profile && r.ServerName == serverName {
			return r, true
		}
	}
	return observe.TLSProfileResult{}, false
}

func TestTLSSendsOperatorHostnameAsSNIAndProbesVirtualHosts(t *testing.T) {
	app, other := testCertificate(t, "app.example.test"), testCertificate(t, "other.example.test")
	target, seen := serveTLS(t, func(sni string) (*tls.Certificate, error) {
		switch sni {
		case "app.example.test":
			return &app, nil
		case "other.example.test":
			return &other, nil
		}
		return nil, errors.New("no certificate for this name")
	})
	target.Hostnames = []string{"app.example.test", "other.example.test"}
	o := tlsProfileEngine(t, TLSProfileNames()...).Interrogate(context.Background(), target)
	if o.Service != "tls" || o.TLS == nil || o.TLS.ServerName != "app.example.test" || o.TLS.Profile != "default" ||
		o.TLS.Certificates[0].DNSNames[0] != "app.example.test" {
		t.Fatalf("default handshake must send the operator's hostname: %+v", o.TLS)
	}
	if got := seen(); got[0] != "app.example.test" {
		t.Fatalf("first ClientHello SNI = %q", got[0])
	}
	if r, ok := profileResult(o, TLSProfileNoSNI, ""); !ok || r.Outcome != "alert" || r.Alert == "" {
		t.Fatalf("a name-based server must refuse the no-SNI profile with an alert: %+v", o.TLS.Profiles)
	}
	if r, ok := profileResult(o, TLSProfileVHosts, "other.example.test"); !ok || r.Outcome != "negotiated" || r.LeafSHA256 == o.TLS.Certificates[0].SHA256 {
		t.Fatalf("virtual host must negotiate with its own certificate: %+v", o.TLS.Profiles)
	}
	if r, ok := profileResult(o, TLSProfileLegacy, "app.example.test"); !ok || r.Outcome != "alert" || r.Alert != "protocol_version" {
		t.Fatalf("a TLS 1.2+ server must refuse the legacy profile: %+v", o.TLS.Profiles)
	}
	if r, ok := profileResult(o, TLSProfile13, "app.example.test"); !ok || r.Outcome != "negotiated" || r.Version != "TLS 1.3" {
		t.Fatalf("tls13 profile: %+v", o.TLS.Profiles)
	}
	if r, ok := profileResult(o, TLSProfile12, "app.example.test"); !ok || r.Outcome != "negotiated" || r.Version != "TLS 1.2" || !strings.HasPrefix(r.CipherSuite, "TLS_ECDHE_ECDSA") {
		t.Fatalf("tls12 profile: %+v", o.TLS.Profiles)
	}
	if len(o.FingerprintConflicts) != 0 {
		t.Fatalf("different names may present different certificates without a conflict: %+v", o.FingerprintConflicts)
	}
	byProfile := map[string]observe.AppFingerprint{}
	for _, f := range o.AppFingerprints {
		if f.Method != observe.FingerprintTLSServer || f.Status != "observed" || len(f.Value) != 64 || o.Evidence[f.Evidence].Matched == "" {
			t.Fatalf("fingerprint without versioned method or matched source evidence: %+v", f)
		}
		byProfile[f.Profile+"|"+f.ServerName] = f
	}
	def, ok := byProfile["default|app.example.test"]
	if !ok || !strings.HasPrefix(def.Normalized, "0304;1301;") {
		t.Fatalf("default fingerprint: %+v", o.AppFingerprints)
	}
	if tls12 := byProfile["tls12|app.example.test"]; !strings.HasPrefix(tls12.Normalized, "0303;") || tls12.Value == def.Value {
		t.Fatalf("tls12 fingerprint must differ from TLS 1.3: %+v", tls12)
	}
	for _, r := range o.TLS.Profiles {
		if o.Evidence[r.Evidence].Probe != probeTLSProfile+r.Profile {
			t.Fatalf("profile %s points at evidence %+v", r.Profile, o.Evidence[r.Evidence])
		}
	}
}

func TestTLSRecordsConflictingCertificatesForOneName(t *testing.T) {
	a, b := testCertificate(t, "lb.example.test"), testCertificate(t, "lb.example.test")
	var n atomic.Int32
	target, _ := serveTLS(t, func(string) (*tls.Certificate, error) {
		if n.Add(1)%2 == 1 {
			return &a, nil
		}
		return &b, nil
	})
	target.Hostnames = []string{"lb.example.test"}
	o := tlsProfileEngine(t, TLSProfile13).Interrogate(context.Background(), target)
	if len(o.FingerprintConflicts) != 1 {
		t.Fatalf("expected one certificate conflict: %+v", o.FingerprintConflicts)
	}
	c := o.FingerprintConflicts[0]
	if c.Field != "tls.leaf_sha256" || len(c.Values) != 2 || c.Values[0] == c.Values[1] || len(c.Evidence) != 2 {
		t.Fatalf("conflict must keep both values and their evidence: %+v", c)
	}
}

func TestTLSProfilesAreOptInAndBounded(t *testing.T) {
	cert := testCertificate(t, "a.example.test")
	target, seen := serveTLS(t, func(string) (*tls.Certificate, error) { return &cert, nil })
	o := tlsProfileEngine(t).Interrogate(context.Background(), target)
	if o.TLS == nil || len(o.TLS.Profiles) != 0 || len(seen()) != 1 || seen()[0] != "" || o.TLS.ServerName != "" {
		t.Fatalf("without profiles or a hostname only one SNI-less handshake is sent: %+v %q", o.TLS, seen())
	}
	target.Hostnames = []string{"a.example.test", "b.example.test", "c.example.test", "d.example.test", "e.example.test"}
	before := len(seen())
	o = tlsProfileEngine(t, TLSProfileVHosts, TLSProfileNoSNI).Interrogate(context.Background(), target)
	// default + three extra names + no-sni; the fifth name exceeds the bound.
	if got := len(seen()) - before; got != 5 || len(o.TLS.Profiles) != 4 {
		t.Fatalf("vhost handshakes must stay within MaxTargetHostnames: %d handshakes, %+v", got, o.TLS.Profiles)
	}
	if _, err := Start(context.Background(), Config{Probes: []string{ProbeTLS}, TLSProfiles: []string{"sslv2"}, Timeout: time.Second, Workers: 1}, func(observe.Observation) {}); err == nil {
		t.Fatal("unknown TLS profile accepted")
	}
}

func TestTLSProfileCanceledStopsBeforeSending(t *testing.T) {
	cert := testCertificate(t, "a.example.test")
	target, seen := serveTLS(t, func(string) (*tls.Certificate, error) { return &cert, nil })
	ctx, cancel := context.WithCancel(context.Background())
	e := tlsProfileEngine(t, TLSProfileNames()...)
	o := observe.Observation{TLS: &observe.TLS{}}
	cancel()
	e.collectTLSProfiles(ctx, target, nil, &o)
	if len(o.TLS.Profiles) != 0 || len(o.Evidence) != 0 || len(seen()) != 0 {
		t.Fatalf("canceled scan sent profile handshakes: %+v", o)
	}
}

func TestClassifyTLSFailure(t *testing.T) {
	for _, c := range []struct {
		ev      observe.Evidence
		outcome string
		alert   string
	}{
		{observe.Evidence{Response: []byte{21, 3, 3, 0, 2, 2, 112}, Error: "remote error"}, "alert", "unrecognized_name"},
		{observe.Evidence{Response: []byte("HTTP/1.1 400 Bad Request\r\n\r\n"), Error: "tls: first record does not look like a TLS handshake"}, "plaintext", ""},
		{observe.Evidence{Error: "timeout"}, "no-response", ""},
		{observe.Evidence{Error: "dial tcp: connection refused"}, "error", ""},
	} {
		var r observe.TLSProfileResult
		classifyTLSFailure(&r, c.ev)
		if r.Outcome != c.outcome || r.Alert != c.alert || r.Error != c.ev.Error {
			t.Errorf("%q: got %+v, want %s %s", c.ev.Response, r, c.outcome, c.alert)
		}
	}
}

func TestTLSPlaintextListenerIsNotFingerprinted(t *testing.T) {
	target := serve(t, func(c net.Conn) {
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n"))
	})
	target.Hostnames = []string{"plain.example.test"}
	e, err := Start(context.Background(), Config{Probes: []string{ProbeTLS, ProbeHTTP}, Fallback: []string{ProbeTLS}, TLSProfiles: TLSProfileNames(),
		Timeout: 500 * time.Millisecond, Workers: 1}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	o := e.Interrogate(context.Background(), target)
	if o.Service != "http" || o.TLS != nil || len(o.AppFingerprints) != 0 {
		t.Fatalf("a plaintext answer to a ClientHello must not produce TLS fingerprints: %+v", o)
	}
}
