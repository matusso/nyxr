package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/tlsrecord"
)

// TLS-wrapped protocols where the server speaks first after the handshake.
var serverFirstTLS = portSet(465, 563, 585, 614, 989, 990, 992, 993, 994, 995, 6697)

// clientCipherSuites offers every suite Go implements, including legacy ones,
// so the handshake reaches old servers. Nothing is sent after the handshake
// that depends on the negotiated suite being strong: this only observes.
var clientCipherSuites = func() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}()

// probeTLS is the shared TLS subsystem: it completes a handshake without
// verification, records the negotiated parameters and certificate chain, and
// then identifies the service carried inside TLS.
func (e *Engine) probeTLS(ctx context.Context, t Target, o *observe.Observation) bool {
	var alpn []string
	if e.enabled[ProbeHTTP] {
		alpn = []string{"h2", "http/1.1"}
	}
	tc, ev, ok := e.handshake(ctx, t, alpn)
	o.Evidence = append(o.Evidence, ev)
	if !ok {
		if desc, alert := tlsrecord.Alert(ev.Response); alert && desc == tlsrecord.NoApplicationProtocol {
			return e.directPostgres(ctx, t, o)
		}
		return false
	}
	defer tc.Close()
	state := tc.ConnectionState()
	o.TLS = summarizeTLS(state)
	o.Service, o.Confidence, o.Probe = "tls", 100, ProbeTLS
	o.Reason = "TLS handshake completed"

	switch {
	case state.NegotiatedProtocol == "h2":
		o.Service = "https"
		o.Reason = "TLS handshake negotiated ALPN h2"
		// HTTP/2 framing is out of scope here; ask again for HTTP/1.1 to
		// read the response head.
		inner, innerEv, ok := e.handshake(ctx, t, []string{"http/1.1"})
		if !ok {
			o.Evidence = append(o.Evidence, innerEv)
			return true
		}
		defer inner.Close()
		e.httpInsideTLS(ctx, t, inner, o)
	case e.enabled[ProbeHTTP] && !serverFirstTLS[t.Port]:
		e.httpInsideTLS(ctx, t, tc, o)
	default:
		rc := e.record(tc)
		inEv := observe.Evidence{Probe: ProbeBanner, Layer: "tls", Started: time.Now().UTC()}
		stop := deadline(ctx, rc, e.timeout(ProbeBanner))
		data, err := readSome(rc, e.cfg.MaxEvidence, 200*time.Millisecond)
		stop()
		e.finish(&inEv, rc, err)
		o.Evidence = append(o.Evidence, inEv)
		if len(data) > 0 {
			o.Attributes = map[string]string{"tls.inner_banner": printable(data, 256)}
			o.Reason += "; service inside TLS unrecognized, banner retained"
		}
	}
	return true
}

// directPostgres retries a handshake refused for its ALPN offer as a
// PostgreSQL 17+ client using direct SSL (sslnegotiation=direct), which must
// offer ALPN "postgresql". The server agreeing to it identifies the service.
func (e *Engine) directPostgres(ctx context.Context, t Target, o *observe.Observation) bool {
	tc, ev, ok := e.handshake(ctx, t, []string{"postgresql"})
	if ok {
		defer tc.Close()
		ok = tc.ConnectionState().NegotiatedProtocol == "postgresql"
	}
	if !ok {
		ev.Matched = ""
		o.Evidence = append(o.Evidence, ev)
		return false
	}
	ev.Matched = ProbeDatabase
	o.Evidence = append(o.Evidence, ev)
	identifyDatabase(o, "postgresql", "PostgreSQL-compatible", "", "TLS handshake negotiated ALPN postgresql (direct SSL)", 100)
	o.Probe, o.TLS = ProbeTLS+"+"+ProbeDatabase, summarizeTLS(tc.ConnectionState())
	o.Attributes = map[string]string{"postgresql.ssl_supported": "true", "postgresql.direct_ssl": "true"}
	return true
}

func (e *Engine) httpInsideTLS(ctx context.Context, t Target, tc *tls.Conn, o *observe.Observation) {
	service, reason, tlsInfo := o.Service, o.Reason, o.TLS
	ev, matched := e.probeHTTP(ctx, t, tc, "tls", o)
	o.Evidence = append(o.Evidence, ev)
	if matched {
		if ev.Matched == ProbeDatabase {
			o.Probe = ProbeTLS + "+" + ProbeDatabase
		} else {
			o.Service, o.Probe = "https", ProbeTLS+"+"+ProbeHTTP
		}
		o.Reason = "TLS handshake completed; " + o.Reason
	} else {
		o.Service, o.Reason = service, reason+"; no HTTP response inside TLS"
	}
	o.TLS = tlsInfo
}

func (e *Engine) handshake(ctx context.Context, t Target, alpn []string) (*tls.Conn, observe.Evidence, bool) {
	timeout := e.timeout(ProbeTLS)
	ev := observe.Evidence{Probe: ProbeTLS, Layer: "tcp", Started: time.Now().UTC()}
	raw, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		return nil, ev, false
	}
	rc := e.record(raw)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	tc := tls.Client(rc, &tls.Config{
		InsecureSkipVerify: true, // identification, not trust: the chain is recorded instead
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       clientCipherSuites,
		NextProtos:         alpn,
	})
	err = tc.HandshakeContext(ctx)
	e.finish(&ev, rc, err)
	if err != nil {
		_ = raw.Close()
		return nil, ev, false
	}
	ev.Matched = ProbeTLS
	return tc, ev, true
}

func summarizeTLS(s tls.ConnectionState) *observe.TLS {
	info := &observe.TLS{
		Version: tls.VersionName(s.Version), CipherSuite: tls.CipherSuiteName(s.CipherSuite),
		ALPN: s.NegotiatedProtocol, ServerName: s.ServerName,
		OCSPStapled: len(s.OCSPResponse) > 0, SCTs: len(s.SignedCertificateTimestamps),
	}
	for _, c := range s.PeerCertificates {
		info.Certificates = append(info.Certificates, summarizeCertificate(c))
	}
	return info
}

func summarizeCertificate(c *x509.Certificate) observe.Certificate {
	sum := sha256.Sum256(c.Raw)
	out := observe.Certificate{
		Subject: c.Subject.String(), Issuer: c.Issuer.String(), Serial: c.SerialNumber.Text(16),
		DNSNames: c.DNSNames, NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(),
		PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(), SignatureAlgorithm: c.SignatureAlgorithm.String(),
		SHA256: hex.EncodeToString(sum[:]),
	}
	for _, ip := range c.IPAddresses {
		out.IPAddresses = append(out.IPAddresses, ip.String())
	}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		out.KeyBits = k.N.BitLen()
	case *ecdsa.PublicKey:
		out.KeyBits = k.Curve.Params().BitSize
	case ed25519.PublicKey:
		out.KeyBits = 256
	}
	out.SelfSigned = bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
	return out
}
