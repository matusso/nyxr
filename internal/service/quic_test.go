package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/quic-go/quic-go/http3"
)

func TestQUICHTTP3Probe(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local HTTP/3"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local HTTP/3"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "nyxr-test")
			w.Header().Set("Alt-Svc", `h3=":443"`)
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	defer listener.Close()
	port := uint16(listener.LocalAddr().(*net.UDPAddr).Port)
	e := &Engine{cfg: Config{Timeout: 3 * time.Second, Fallback: []string{ProbeQUIC}}, enabled: map[string]bool{ProbeQUIC: true}}
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: port, Transport: "udp", State: "open|filtered"})
	if o.State != "open" || o.Service != "http3" || o.Fingerprint != observe.FingerprintMatched {
		t.Fatalf("HTTP/3 identity: %+v", o)
	}
	if o.TLS == nil || o.TLS.ALPN != "h3" || len(o.TLS.Certificates) != 1 {
		t.Fatalf("QUIC TLS identity: %+v", o.TLS)
	}
	if o.Attributes["http.status"] != "204" || o.Attributes["http.server"] != "nyxr-test" || o.Attributes["quic.version"] == "" ||
		o.Attributes["quic.transport.active_connection_id_limit"] == "" || o.Attributes["quic.connection_id.server_initial"] == "" ||
		o.Attributes["quic.connection_id.client_initial"] == "" || o.Attributes["quic.version_negotiation"] != "false" {
		t.Fatalf("QUIC/HTTP metadata: %+v", o.Attributes)
	}
	if len(o.Evidence) < 2 {
		t.Fatalf("missing QUIC and HTTP/3 evidence: %+v", o.Evidence)
	}
}
