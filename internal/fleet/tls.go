package fleet

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
)

// ServerTLS loads the controller certificate. A non-empty clientCA requires
// every agent to present a certificate it signed (mutual TLS) in addition to
// its enrolled credential.
func ServerTLS(certFile, keyFile, clientCA string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("fleet TLS needs a certificate and a key")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("fleet TLS: %w", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if clientCA != "" {
		pool, err := loadPool(clientCA)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs, cfg.ClientAuth = pool, tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// ClientTLS builds the agent's TLS configuration. An empty caFile uses the
// system roots; certFile/keyFile add a client certificate for mutual TLS.
func ClientTLS(caFile, certFile, keyFile, serverName string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName}
	if caFile != "" {
		pool, err := loadPool(caFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("an agent client certificate needs both --tls-cert and --tls-key")
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("agent TLS: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func loadPool(file string) (*x509.CertPool, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s holds no PEM certificates", file)
	}
	return pool, nil
}

// IsLoopback reports whether a host:port names a loopback address. Plaintext
// fleet transport is only allowed there.
func IsLoopback(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
