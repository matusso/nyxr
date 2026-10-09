package scan

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/probe"
)

func TestUnknownUDPResponseRetainedWithBounds(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	response := bytes.Repeat([]byte{0xff}, 5000)
	go func() {
		var b [64]byte
		_, peer, err := server.ReadFromUDP(b[:])
		if err == nil {
			_, _ = server.WriteToUDP(response, peer)
		}
	}()
	target := task{target: netip.MustParseAddr("127.0.0.1"), port: uint16(server.LocalAddr().(*net.UDPAddr).Port), transport: "udp"}
	// The DNS matcher deliberately cannot recognize this response. Discovery
	// still sees an open socket, without claiming a protocol match.
	limiter := newScopedProbeLimiter(config.Config{})
	defer limiter.Close()
	o := probeUDPCampaign(context.Background(), target, 100*time.Millisecond, []probe.Probe{{Name: "dns", Matcher: "dns", Ports: []uint16{target.port}, Payload: []byte{0, 1}}}, 0, []byte("secret"), limiter)
	if o.State != "open" || o.Service != "" || len(o.Evidence) != 1 {
		t.Fatalf("unknown response lost: %+v", o)
	}
	ev := o.Evidence[0]
	if len(ev.Response) != 4096 || !ev.Truncated || ev.Matched != "" || !bytes.Equal(ev.Response, response[:4096]) {
		t.Fatalf("response retention: %+v", ev)
	}
	// Buffer reuse must not mutate retained response bytes; overflow retains
	// the newest exchange while marking omitted middle responses.
	input := []byte{1, 2, 3}
	for i := 0; i < 40; i++ {
		retainUDPExchange(&o, sentProbe{probe: probe.Probe{Name: "fixture"}, request: []byte{byte(i)}, sent: time.Now()}, input, "")
	}
	input[0] = 99
	if len(o.Evidence) != 32 || !o.EvidenceTruncated || o.Evidence[31].Request[0] != 39 || o.Evidence[31].Response[0] != 1 {
		t.Fatalf("unbounded or reused transcript: %+v", o)
	}
}
