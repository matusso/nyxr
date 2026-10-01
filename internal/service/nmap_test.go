package service

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/nmapdb"
	"github.com/matusso/nyxr/internal/observe"
)

// nmapProbes is a synthetic nmap-service-probes database for the engine tests.
const nmapProbes = `Probe TCP NULL q||
match ftp m|^220[- ].*ProFTPD ([\w.]+)| p/ProFTPD/ v/$1/
softmatch smtp m|^220 |
match ssh m|^SSH-| p/decoy/
`

func nmapEngine(t *testing.T, probes []string) *Engine {
	t.Helper()
	db, err := nmapdb.Parse(strings.NewReader(nmapProbes), "test")
	if err != nil {
		t.Fatal(err)
	}
	e, err := Start(context.Background(), Config{Probes: probes, Timeout: 600 * time.Millisecond, Workers: 1, Nmap: db},
		func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

func TestNmapBannerMatch(t *testing.T) {
	target := serve(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "220 ProFTPD 1.3.5 Server ready.\r\n")
		time.Sleep(400 * time.Millisecond)
	})
	o := nmapEngine(t, []string{ProbeBanner, ProbeNmap}).Interrogate(context.Background(), target)
	if o.Service != "ftp" || o.Product != "ProFTPD" || o.Version != "1.3.5" {
		t.Fatalf("unexpected nmap identity: %+v", o)
	}
	if o.Confidence != 90 || o.Fingerprint != observe.FingerprintMatched || o.Probe != ProbeNmap {
		t.Fatalf("expected a hard match at 90%%: %+v", o)
	}
	if len(o.Evidence) != 1 || o.Evidence[0].Matched != ProbeNmap {
		t.Fatalf("evidence should record the nmap match: %+v", o.Evidence)
	}
	if o.Attributes["nmap.probe"] != "NULL" {
		t.Fatalf("attributes missing provenance: %+v", o.Attributes)
	}
}

func TestNmapSoftmatchConfidence(t *testing.T) {
	target := serve(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "220 mail.example.org ESMTP ready\r\n")
		time.Sleep(400 * time.Millisecond)
	})
	o := nmapEngine(t, []string{ProbeBanner, ProbeNmap}).Interrogate(context.Background(), target)
	if o.Service != "smtp" || o.Confidence != 75 {
		t.Fatalf("expected an smtp softmatch at 75%%: %+v", o)
	}
}

// TestNmapDoesNotOverrideSSH verifies the built-in SSH matcher still wins: the
// nmap fallback only runs when the built-in matchers do not recognize a banner.
func TestNmapDoesNotOverrideSSH(t *testing.T) {
	target := serve(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "SSH-2.0-OpenSSH_9.6p1\r\n")
		time.Sleep(400 * time.Millisecond)
	})
	o := nmapEngine(t, []string{ProbeBanner, ProbeSSH, ProbeNmap}).Interrogate(context.Background(), target)
	if o.Service != "ssh" || o.Product != "OpenSSH" || o.Probe != ProbeSSH {
		t.Fatalf("SSH matcher must take precedence over nmap: %+v", o)
	}
}

// TestNmapEnabledWithoutDatabase confirms the probe is a safe no-op when no
// database is attached: the banner is retained as unknown rather than crashing.
func TestNmapEnabledWithoutDatabase(t *testing.T) {
	target := serve(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "220 ProFTPD 1.3.5 Server ready.\r\n")
		time.Sleep(400 * time.Millisecond)
	})
	e, err := Start(context.Background(), Config{Probes: []string{ProbeBanner, ProbeNmap}, Timeout: 600 * time.Millisecond, Workers: 1},
		func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	o := e.Interrogate(context.Background(), target)
	if o.Fingerprint != observe.FingerprintUnknown || o.Service != "" {
		t.Fatalf("nmap probe without a database must not identify a service: %+v", o)
	}
}
