package service

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// panicConn panics on the first read, standing in for any parser bug a
// hostile reply could trigger.
type panicConn struct{ net.Conn }

func (panicConn) Read([]byte) (int, error) { panic("injected parser fault") }

func TestProbePanicIsContained(t *testing.T) {
	e, err := Start(context.Background(), Config{Probes: []string{ProbeRDP}, Timeout: time.Second, Workers: 1,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go func() { defer server.Close(); _, _ = server.Read(make([]byte, 64)) }()
			return panicConn{client}, nil
		}}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 3389})
	if o.Service == "rdp" {
		t.Fatalf("panicking probe left a claim: %+v", o)
	}
	found := false
	for _, ev := range o.Evidence {
		if ev.Probe == ProbeRDP && strings.Contains(ev.Error, "probe panic: injected parser fault") {
			found = true
		}
	}
	if !found {
		t.Fatalf("panic not recorded in evidence: %+v", o.Evidence)
	}
}
