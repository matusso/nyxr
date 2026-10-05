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
	"net/netip"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/pion/dtls/v3"
)

func TestDTLSProbe(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "local DTLS"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := dtls.ListenWithOptions("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		dtls.WithCertificates(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.(*dtls.Conn).HandshakeContext(context.Background())
			_ = conn.Close()
		}
	}()
	port := uint16(listener.Addr().(*net.UDPAddr).Port)
	e := &Engine{cfg: Config{Timeout: 3 * time.Second, Fallback: []string{ProbeDTLS}}, enabled: map[string]bool{ProbeDTLS: true}}
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: port, Transport: "udp", State: "open|filtered"})
	if o.State != "open" || o.Service != ProbeDTLS || o.Fingerprint != observe.FingerprintMatched {
		t.Fatalf("DTLS identity: %+v", o)
	}
	if o.TLS == nil || len(o.TLS.Certificates) != 1 || o.TLS.Certificates[0].Subject == "" {
		t.Fatalf("DTLS certificate: %+v", o.TLS)
	}
}
