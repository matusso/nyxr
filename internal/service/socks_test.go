package service

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

func socksEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := Start(context.Background(), Config{
		Probes: []string{ProbeSOCKS}, Fallback: []string{ProbeSOCKS},
		Timeout: time.Second, Workers: 1,
	}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

func TestSOCKS5ReportsAllocatedUDPRelay(t *testing.T) {
	target := serve(t, func(c net.Conn) {
		var greeting [3]byte
		if _, err := io.ReadFull(c, greeting[:]); err != nil || greeting != [3]byte{5, 1, 0} {
			return
		}
		_, _ = c.Write([]byte{5, 0})
		var associate [10]byte
		if _, err := io.ReadFull(c, associate[:]); err != nil || associate != [10]byte{5, 3, 0, 1} {
			return
		}
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0x12, 0x34})
	})
	o := socksEngine(t).Interrogate(context.Background(), target)
	if o.Service != "socks5" || o.Fingerprint != observe.FingerprintMatched ||
		o.Attributes["socks.udp_associate"] != "accepted" ||
		o.Attributes["socks.udp_relay_address"] != target.Addr.String() ||
		o.Attributes["socks.udp_relay_port"] != "4660" || len(o.Evidence) != 1 ||
		o.Evidence[0].Matched != ProbeSOCKS {
		t.Fatalf("SOCKS5 UDP relay was not reported: %+v", o)
	}
}

func TestSOCKS4IdentifiesTCPWithoutClaimingUDP(t *testing.T) {
	var connections atomic.Int32
	target := serve(t, func(c net.Conn) {
		connections.Add(1)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		var first [1]byte
		if _, err := io.ReadFull(c, first[:]); err != nil {
			return
		}
		if first[0] == 5 {
			return
		}
		var rest [8]byte
		if _, err := io.ReadFull(c, rest[:]); err != nil {
			return
		}
		_, _ = c.Write([]byte{0, 0x5b, 0, 0, 0, 0, 0, 0})
	})
	o := socksEngine(t).Interrogate(context.Background(), target)
	if o.Service != "socks4" || o.Attributes["socks.udp_associate"] != "unsupported" ||
		len(o.Evidence) != 2 || connections.Load() != 2 {
		t.Fatalf("SOCKS4 detection failed: %+v (%d connections)", o, connections.Load())
	}
}
