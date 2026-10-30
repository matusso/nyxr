package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/observe"
)

func sealedExchange(t *testing.T, port uint16, layer string, request, response []byte) observe.Observation {
	t.Helper()
	o := observe.Observation{ID: "store:test/1", Kind: observe.KindService, Target: netip.MustParseAddr("127.0.0.1"),
		Transport: "tcp", Port: port, State: "open", Service: "redis", Fingerprint: observe.FingerprintMatched,
		Evidence: []observe.Evidence{{Probe: "database/redis", Layer: layer, Request: request, Response: response, Matched: "database"}}}
	o.Stamp("scan-1")
	if _, err := o.Seal(); err != nil {
		t.Fatal(err)
	}
	return o
}

func noDial(t *testing.T) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		t.Error("offline replay dialed the network")
		return nil, errors.New("no network")
	}
}

func TestCloneProtocolDraftsCompilableDefinition(t *testing.T) {
	o := sealedExchange(t, 6379, "tcp", []byte("PING\r\n"), []byte("+PONG\r\n"))
	draft, err := CloneProtocol(o, 0)
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseProtocol(bytes.NewReader(draft))
	if err != nil {
		t.Fatalf("draft does not compile: %v\n%s", err, draft)
	}
	text := string(draft)
	if d.Name != "clone-database-redis" || d.Transport != "tcp" || !reflect.DeepEqual(d.Ports, []uint16{6379}) ||
		!strings.Contains(text, `send: {hex: "50494e470d0a"}`) || !strings.Contains(text, `expect: {hex: "2b504f4e470d0a"}`) ||
		!strings.Contains(text, o.Source.ArtifactID+"#/evidence/0") {
		t.Fatalf("draft:\n%s", text)
	}
	tlsDraft, err := CloneProtocol(sealedExchange(t, 443, "tls", []byte("GET / HTTP/1.0\r\n\r\n"), []byte("HTTP/1.0 200 OK\r\n")), 0)
	if err != nil || !strings.Contains(string(tlsDraft), "- tls: true") {
		t.Fatalf("TLS draft: %v\n%s", err, tlsDraft)
	}
	if _, err := CloneProtocol(sealedExchange(t, 443, "quic", []byte{1}, []byte{2}), 0); err == nil {
		t.Fatal("native QUIC exchange cloned into byte steps")
	}
	if _, err := CloneProtocol(o, 1); err == nil {
		t.Fatal("missing exchange cloned")
	}
	unsealed := o
	unsealed.Source = nil
	if _, err := CloneProtocol(unsealed, 0); err == nil {
		t.Fatal("unsealed observation cloned")
	}
}

const pingDefinition = `schema: nyxr/protocol/v2
protocol: ping
transport: tcp
ports: [6379]
timeout: 2s
steps:
  - label: ask
    send: {text: "PING\r\n"}
  - repeat: {from: ask, count: 2}
  - receive: {max_bytes: 64}
  - expect: {prefix: "+PONG"}
  - extract: {redis.reply: '\+([A-Z]+)'}
`

func TestPlanReplayPinsTargetAndBoundsTraffic(t *testing.T) {
	o := sealedExchange(t, 6379, "tcp", []byte("PING\r\n"), []byte("+PONG\r\n"))
	_, plan, err := PlanReplay(ReplayInput{Observation: o, Definition: []byte(pingDefinition), Mode: observe.ProbeRunLive})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Target != o.Target || plan.Port != 6379 || plan.Transport != "tcp" || plan.Connections != 1 ||
		plan.MaxSendBytes != 12 || plan.MaxReceiveBytes != 128 || plan.Source != *o.Evidence[0].Source {
		t.Fatalf("live plan: %+v", plan)
	}
	_, plan, err = PlanReplay(ReplayInput{Observation: o, Definition: []byte(pingDefinition), Mode: observe.ProbeRunOffline})
	if err != nil || plan.Connections != 0 || plan.Timeout != offlineReplayTimeout {
		t.Fatalf("offline plan: %+v %v", plan, err)
	}
	other := strings.Replace(pingDefinition, "[6379]", "[6380]", 1)
	if _, _, err := PlanReplay(ReplayInput{Observation: o, Definition: []byte(other), Mode: observe.ProbeRunOffline}); err == nil {
		t.Fatal("definition for another port accepted")
	}
	if _, _, err := PlanReplay(ReplayInput{Observation: o, Definition: []byte(pingDefinition), Mode: "resend"}); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

func TestOfflineReplayIsDeterministicAndSendsNothing(t *testing.T) {
	o := sealedExchange(t, 6379, "tcp", []byte("PING\r\nPING\r\n"), []byte("+PONG\r\n"))
	before := o
	in := ReplayInput{Observation: o, Definition: []byte(pingDefinition), Mode: observe.ProbeRunOffline, Dial: noDial(t)}
	first, err := Replay(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Replay(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != observe.ProbeRunMatched || !first.RequestMatchesEvidence || first.Result.State != "offline" ||
		first.Result.Kind != observe.KindProbeReplay || first.Result.Attributes["redis.reply"] != "PONG" || first.ID == second.ID {
		t.Fatalf("offline run: %+v", first)
	}
	a, b := first.Result.Evidence[0], second.Result.Evidence[0]
	if first.Status != second.Status || !reflect.DeepEqual(first.Result.Attributes, second.Result.Attributes) ||
		!bytes.Equal(a.Request, b.Request) || !bytes.Equal(a.Response, b.Response) || a.Error != b.Error {
		t.Fatalf("replay is not deterministic:\n%+v\n%+v", first, second)
	}
	if !reflect.DeepEqual(o, before) {
		t.Fatal("replay modified the source observation")
	}
	edited := strings.Replace(pingDefinition, `"PING\r\n"`, `"INFO\r\n"`, 1)
	run, err := Replay(context.Background(), ReplayInput{Observation: o, Definition: []byte(edited), Mode: observe.ProbeRunOffline})
	if err != nil || run.RequestMatchesEvidence || run.Status != observe.ProbeRunMatched || !strings.Contains(run.Result.Reason, "differs") {
		t.Fatalf("edited request: %+v %v", run, err)
	}
	miss := strings.Replace(pingDefinition, `"+PONG"`, `"-ERR"`, 1)
	if run, err := Replay(context.Background(), ReplayInput{Observation: o, Definition: []byte(miss), Mode: observe.ProbeRunOffline}); err != nil || run.Status != observe.ProbeRunUnmatched {
		t.Fatalf("unmatched replay: %+v %v", run, err)
	}
}

const framedDefinition = `schema: nyxr/protocol/v2
protocol: framed
transport: tcp
ports: [%d]
timeout: 200ms
steps:
  - send: {hex: "01"}
  - receive:
      max_bytes: 64
      length: {offset: 0, bytes: 1, order: big}
  - expect: {hex: "%s"}
`

func TestOfflineReplayReportsTruncatedEvidenceAsPartial(t *testing.T) {
	// The length byte promises 8 more bytes; only 3 were retained.
	o := sealedExchange(t, 6379, "tcp", []byte{1}, []byte{8, 'a', 'b', 'c'})
	definition := fmt.Sprintf(framedDefinition, 6379, "08")
	run, err := Replay(context.Background(), ReplayInput{Observation: o, Definition: []byte(definition), Mode: observe.ProbeRunOffline})
	if err != nil || run.Status != observe.ProbeRunPartial || run.Error == "" {
		t.Fatalf("partial offline replay: %+v %v", run, err)
	}
}

func TestLiveReplayRecordsMatchedFailedAndPartialResends(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	replies := make(chan []byte, 2)
	go func() {
		for reply := range replies {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 64)
			_, _ = c.Read(buf)
			_, _ = c.Write(reply)
			c.Close()
		}
	}()
	o := sealedExchange(t, port, "tcp", []byte{1}, []byte{2, 'o', 'k'})
	in := ReplayInput{Observation: o, Definition: []byte(fmt.Sprintf(framedDefinition, port, "02")), Mode: observe.ProbeRunLive}

	replies <- []byte{2, 'o', 'k'}
	run, err := Replay(context.Background(), in)
	if err != nil || run.Status != observe.ProbeRunMatched || run.Result.State != "open" || run.Mode != observe.ProbeRunLive {
		t.Fatalf("live match: %+v %v", run, err)
	}
	replies <- []byte{2, 'o'} // closes mid-frame
	run, err = Replay(context.Background(), in)
	if err != nil || run.Status != observe.ProbeRunPartial || run.Error == "" {
		t.Fatalf("live partial: %+v %v", run, err)
	}
	close(replies)
	ln.Close()
	run, err = Replay(context.Background(), in)
	if err != nil || run.Status != observe.ProbeRunFailed || run.Result.State != "error" {
		t.Fatalf("live failure: %+v %v", run, err)
	}
}

// FuzzCloneAndOfflineReplay checks that any retained exchange either fails
// to clone or yields a definition that compiles and replays offline.
func FuzzCloneAndOfflineReplay(f *testing.F) {
	f.Add([]byte("PING\r\n"), []byte("+PONG\r\n"), "tcp")
	f.Add([]byte{}, []byte{}, "tls")
	f.Add([]byte{0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f}, []byte("S"), "tcp")
	f.Fuzz(func(t *testing.T, request, response []byte, layer string) {
		if len(request) > 4096 || len(response) > 4096 {
			return
		}
		o := sealedExchange(t, 9000, layer, request, response)
		draft, err := CloneProtocol(o, 0)
		if err != nil {
			return
		}
		run, err := Replay(context.Background(), ReplayInput{Observation: o, Definition: draft, Mode: observe.ProbeRunOffline, Dial: noDial(t)})
		if err != nil {
			t.Fatalf("clone does not replay: %v\n%s", err, draft)
		}
		if len(response) > 0 && (run.Status != observe.ProbeRunMatched || !run.RequestMatchesEvidence) {
			t.Fatalf("clone does not match its own evidence: %+v\n%s", run, draft)
		}
	})
}
