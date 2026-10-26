package pipeline

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/scan"
)

// A hostname target keeps its name as the TLS SNI while discovery and
// authorization use only the resolved address.
func TestHostnameTargetReachesTLSAsSNI(t *testing.T) {
	cert := httptest.NewTLSServer(http.NotFoundHandler())
	certs := cert.TLS.Certificates
	cert.Close()
	on := true
	resolved, err := (config.Request{Targets: []string{"localhost"}, AllowTargets: []string{"127.0.0.1", "::1"}, Profile: "tcp-basic", Ports: "443",
		Service: &on, ServiceProbes: "tls"}).Resolve(config.ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	loopback := netip.MustParseAddr("127.0.0.1")
	if names := resolved.Config.TargetNames[loopback]; len(names) != 1 || names[0] != "localhost" {
		t.Skipf("localhost does not resolve to 127.0.0.1 here: %v", resolved.Config.TargetNames)
	}
	var mu sync.Mutex
	var sni []string
	var output bytes.Buffer
	opts := FromResolved(resolved)
	opts.Sinks = []Sink{NewJSONSink(&output)}
	opts.Discover = func(_ context.Context, _ config.Config, emit func(scan.Observation) error) error {
		return emit(scan.Observation{Target: loopback, Transport: "tcp", Port: 443, State: "open"})
	}
	opts.ServiceDial = func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			tc := tls.Server(server, &tls.Config{Certificates: certs, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
				mu.Lock()
				sni = append(sni, h.ServerName)
				mu.Unlock()
				return nil, nil
			}})
			_ = tc.Handshake()
		}()
		return client, nil
	}
	if _, err := Run(context.Background(), resolved.Config, opts); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sni) == 0 || sni[0] != "localhost" {
		t.Fatalf("SNI = %q, want the operator's hostname", sni)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"server_name":"localhost"`)) || !bytes.Contains(output.Bytes(), []byte(`"profile":"default"`)) {
		t.Fatalf("service record must report the SNI sent and the profile: %s", output.String())
	}
}
