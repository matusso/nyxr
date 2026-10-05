package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlogwriter"
)

// probeQUIC performs a real QUIC/TLS handshake, then a read-only HTTP/3 HEAD.
// Certificate verification is intentionally deferred: discovery must retain
// identity from self-signed and name-mismatched hosts addressed by IP.
func (e *Engine) probeQUIC(ctx context.Context, t Target, o *observe.Observation) bool {
	started := time.Now()
	ev := observe.Evidence{Probe: ProbeQUIC, Layer: "quic", Started: started.UTC()}
	defer func() {
		ev.Duration = time.Since(started)
		o.Evidence = append([]observe.Evidence{ev}, o.Evidence...)
	}()
	if err := e.pacer.wait(ctx); err != nil {
		ev.Error = err.Error()
		return false
	}
	probeCtx, cancel := context.WithTimeout(ctx, e.timeout(ProbeQUIC))
	defer cancel()
	address := net.JoinHostPort(t.Addr.String(), strconv.Itoa(int(t.Port)))
	tlsConfig := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}} //nolint:gosec
	trace := newQUICTrace()
	conn, err := quic.DialAddr(probeCtx, address, tlsConfig, &quic.Config{
		EnableDatagrams: true,
		Tracer: func(_ context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
			if isClient {
				trace.mu.Lock()
				trace.fields["quic.connection_id.client_initial"] = connID.String()
				trace.mu.Unlock()
			}
			return trace
		},
	})
	if err != nil {
		ev.Error = err.Error()
		return false
	}
	defer conn.CloseWithError(0, "scan complete")
	state := conn.ConnectionState()
	o.Probe, o.Service = ProbeQUIC, "quic"
	o.Reason = "QUIC/TLS handshake completed"
	o.RTT = time.Since(started)
	o.TLS = summarizeTLS(state.TLS)
	o.Attributes = map[string]string{
		"quic.version":         state.Version.String(),
		"quic.datagram.remote": strconv.FormatBool(state.SupportsDatagrams.Remote),
		"quic.alpn":            state.TLS.NegotiatedProtocol,
	}
	for key, value := range trace.snapshot() {
		o.Attributes[key] = value
	}
	if o.Attributes["quic.version_negotiation"] == "" {
		o.Attributes["quic.version_negotiation"] = "false"
	}
	if state.TLS.NegotiatedProtocol == http3.NextProtoH3 {
		o.Service = "http3"
		o.Reason = "QUIC/TLS handshake negotiated HTTP/3"
	}
	ev.Matched = "quic"
	// The handshake bytes are encrypted and owned by quic-go. The negotiated
	// values above are structured evidence; do not invent raw packet bytes.
	transport := &http3.Transport{EnableDatagrams: true, QUICConfig: &quic.Config{EnableDatagrams: true}}
	defer transport.Close()
	h3 := transport.NewClientConn(conn)
	select {
	case <-h3.ReceivedSettings():
		if settings := h3.Settings(); settings != nil {
			o.Attributes["http3.settings.datagram"] = strconv.FormatBool(settings.EnableDatagrams)
			o.Attributes["http3.settings.extended_connect"] = strconv.FormatBool(settings.EnableExtendedConnect)
			o.Attributes["http3.webtransport_prerequisites"] = strconv.FormatBool(settings.EnableExtendedConnect && settings.EnableDatagrams)
			keys := make([]uint64, 0, len(settings.Other))
			for id := range settings.Other {
				keys = append(keys, id)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for _, id := range keys {
				o.Attributes[fmt.Sprintf("http3.settings.0x%x", id)] = strconv.FormatUint(settings.Other[id], 10)
			}
		}
	case <-probeCtx.Done():
		return true // a completed QUIC handshake already proves the port open
	}
	request, err := http.NewRequestWithContext(probeCtx, http.MethodHead, "https://"+address+"/", nil)
	if err != nil {
		return true
	}
	httpStarted := time.Now()
	httpEv := observe.Evidence{Probe: "http3-head", Layer: "http3", Started: httpStarted.UTC(), Request: []byte("HEAD / HTTP/3")}
	response, err := h3.RoundTrip(request)
	httpEv.Duration = time.Since(httpStarted)
	if err != nil {
		httpEv.Error = err.Error()
		o.Evidence = append(o.Evidence, httpEv)
		return true
	}
	defer response.Body.Close()
	httpEv.Matched = "http3"
	httpEv.Response = []byte(response.Status)
	o.Evidence = append(o.Evidence, httpEv)
	o.Attributes["http.status"] = strconv.Itoa(response.StatusCode)
	for _, header := range []struct{ name, key string }{{"Server", "http.server"}, {"Alt-Svc", "http.alt_svc"}} {
		if value := strings.TrimSpace(response.Header.Get(header.name)); value != "" {
			o.Attributes[header.key] = printable([]byte(value), 256)
		}
	}
	return true
}
