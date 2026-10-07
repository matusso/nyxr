package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/pion/dtls/v3"
)

// probeDTLS completes an unauthenticated DTLS handshake without application
// data. Like the QUIC probe, it records certificates even when they are
// self-signed or do not name the scanned IP address.
func (e *Engine) probeDTLS(ctx context.Context, t Target, o *observe.Observation) bool {
	started := time.Now()
	ev := observe.Evidence{Probe: ProbeDTLS, Layer: "dtls", Started: started.UTC()}
	index := len(o.Evidence)
	o.Evidence = append(o.Evidence, ev)
	defer func() {
		ev.Duration = time.Since(started)
		o.Evidence[index] = ev
	}()
	if err := e.pacer.wait(ctx); err != nil {
		ev.Error = err.Error()
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, e.timeout(ProbeDTLS))
	defer cancel()
	addr := &net.UDPAddr{IP: net.IP(t.Addr.AsSlice()), Port: int(t.Port), Zone: t.Addr.Zone()}
	network := "udp4"
	if t.Addr.Is6() {
		network = "udp6"
	}
	conn, err := dtls.DialWithOptions(network, addr, dtls.WithInsecureSkipVerify(true)) //nolint:gosec
	if err != nil {
		ev.Error = err.Error()
		return false
	}
	defer conn.Close()
	if err := conn.HandshakeContext(probeCtx); err != nil {
		ev.Error = err.Error()
		return false
	}
	state, ok := conn.ConnectionState()
	if !ok {
		ev.Error = "DTLS handshake completed without connection state"
		return false
	}
	o.Probe, o.Service = ProbeDTLS, ProbeDTLS
	o.Reason = "DTLS handshake completed"
	o.RTT = time.Since(started)
	o.Attributes = map[string]string{
		"dtls.cipher_suite_id": fmt.Sprintf("0x%04x", state.CipherSuiteID),
		"dtls.alpn":            state.NegotiatedProtocol,
		"dtls.certificates":    strconv.Itoa(len(state.PeerCertificates)),
	}
	o.TLS = &observe.TLS{Version: "DTLS", CipherSuite: tls.CipherSuiteName(uint16(state.CipherSuiteID)), ALPN: state.NegotiatedProtocol}
	for _, raw := range state.PeerCertificates {
		cert, parseErr := x509.ParseCertificate(raw)
		if parseErr == nil {
			o.TLS.Certificates = append(o.TLS.Certificates, summarizeCertificate(cert))
		}
	}
	ev.Matched = ProbeDTLS
	return true
}
