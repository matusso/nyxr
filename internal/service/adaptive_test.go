package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"golang.org/x/net/http2"
)

func checkAdaptiveTrace(t *testing.T, o observe.Observation) {
	t.Helper()
	if o.ProbeStopReason == "" || len(o.ProbeUpdates) == 0 {
		t.Fatalf("missing adaptive termination or updates: %+v", o)
	}
	for _, u := range o.ProbeUpdates {
		if u.EvidenceStart < 0 || u.EvidenceEnd > len(o.Evidence) || u.EvidenceStart >= u.EvidenceEnd {
			t.Fatalf("invalid evidence range: %+v", u)
		}
		if u.Outcome == "inconclusive" && !reflect.DeepEqual(u.Before, u.After) {
			t.Fatalf("inconclusive I/O changed hypotheses: %+v", u)
		}
		for _, distribution := range [][]observe.ServiceHypothesis{u.Before, u.After} {
			sum := 0.0
			for _, h := range distribution {
				if math.IsNaN(h.Probability) || h.Probability < 0 || h.Probability > 1 {
					t.Fatalf("invalid probability: %+v", h)
				}
				sum += h.Probability
			}
			if math.Abs(1-sum) > 1e-9 {
				t.Fatalf("probabilities sum to %g", sum)
			}
		}
	}
}

func TestAdaptiveSilenceDoesNotDisproveProtocols(t *testing.T) {
	target := serve(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	e, err := Start(context.Background(), Config{Probes: []string{ProbeHTTP, ProbeTLS},
		Fallback: []string{ProbeHTTP, ProbeTLS}, Timeout: 50 * time.Millisecond, Workers: 1,
	}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	o := e.Interrogate(context.Background(), target)
	checkAdaptiveTrace(t, o)
	if o.Fingerprint != observe.FingerprintUnknown || o.ProbeStopReason != "candidates exhausted" || len(o.ProbeDecisions) != 2 {
		t.Fatalf("silent target: %+v", o)
	}
	for _, u := range o.ProbeUpdates {
		if u.Outcome != "inconclusive" {
			t.Fatalf("silence became a signature: %+v", u)
		}
	}
}

func TestAdaptiveProbeBudgetBoundsDatabaseRequests(t *testing.T) {
	var connections atomic.Int32
	target := serve(t, func(c net.Conn) {
		connections.Add(1)
		buf := make([]byte, 128)
		if _, err := c.Read(buf); err == nil {
			_, _ = io.WriteString(c, "unrecognized\r\n")
		}
	})
	e, err := Start(context.Background(), Config{Probes: []string{ProbeDatabase}, Fallback: []string{ProbeDatabase},
		Timeout: 50 * time.Millisecond, Workers: 1, MaxProbes: 2,
	}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	o := e.Interrogate(context.Background(), target)
	checkAdaptiveTrace(t, o)
	// One passive read, exactly two planned database wire exchanges.
	if connections.Load() != 3 || o.ProbeStopReason != "probe budget exhausted" || len(o.Evidence) != 3 {
		t.Fatalf("budget did not bound wire traffic: connections=%d result=%+v", connections.Load(), o)
	}
}

func TestAdaptiveDatabaseUsesRejectionToChooseRedis(t *testing.T) {
	e := plannerEngine()
	p := newDatabasePlanner(e, 5432, false)
	first, _, _ := p.next()
	if first != "database/postgresql" {
		t.Fatalf("unexpected hinted request %s", first)
	}
	p.update(first, false, []byte("-ERR unknown command\r\n"), e)
	if next, gain, _ := p.next(); next != "database/redis" || gain <= 0 {
		t.Fatalf("RESP rejection did not select Redis: %s gain=%g", next, gain)
	}
}

func TestAdaptiveEnabledProbesBoundDynamicCandidates(t *testing.T) {
	e := &Engine{cfg: Config{Fallback: []string{ProbeHTTP}}, enabled: map[string]bool{ProbeHTTP: true}}
	p := newProbePlanner(e, 12345)
	p.update(ProbeHTTP, false, []byte("-ERR unknown command\r\n"), e)
	if next, _, _ := p.next(); next != "" {
		t.Fatalf("disabled database probe became eligible: %s", next)
	}
	p = newProbePlanner(e, 12345)
	p.update(ProbeHTTP, false, []byte("HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server."), e)
	if next, _, _ := p.next(); next != "" {
		t.Fatalf("disabled TLS probe became eligible: %s", next)
	}
}

func TestAdaptiveReusesActiveServerFirstGreeting(t *testing.T) {
	var connections atomic.Int32
	target := serve(t, func(c net.Conn) {
		if connections.Add(1) == 1 {
			_, _ = io.Copy(io.Discard, c) // no initial greeting
			return
		}
		_, _ = io.WriteString(c, "SSH-2.0-OpenSSH_9.7\r\n")
	})
	e, err := Start(context.Background(), Config{Probes: []string{ProbeHTTP, ProbeSSH},
		Fallback: []string{ProbeHTTP}, Timeout: 200 * time.Millisecond, Workers: 1,
	}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	o := e.Interrogate(context.Background(), target)
	checkAdaptiveTrace(t, o)
	if o.Service != "ssh" || connections.Load() != 2 || len(o.ProbeDecisions) != 1 || o.Evidence[1].Matched != ProbeSSH {
		t.Fatalf("active greeting was not reused without extra traffic: %+v", o)
	}
}

func TestAdaptiveHTTP2RejectsOversizedFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		defer server.Close()
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(server, preface); err != nil {
			return
		}
		f := http2.NewFramer(server, server)
		for i := 0; i < 2; i++ { // client SETTINGS and HEADERS
			if _, err := f.ReadFrame(); err != nil {
				return
			}
		}
		_, _ = server.Write([]byte{0xff, 0xff, 0xff, 1, 4, 0, 0, 0, 1})
	}()
	e := &Engine{cfg: Config{MaxEvidence: 128, Timeout: time.Second, UserAgent: "nyxr"}}
	var o observe.Observation
	ev, matched := e.probeHTTP2(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 443}, client, &o)
	if matched || ev.Error == "" || len(ev.Response) != 9 || o.Service != "" {
		t.Fatalf("oversized HTTP/2 frame accepted or lost: matched=%v evidence=%+v", matched, ev)
	}
}

func TestAdaptiveCanceledTargetDoesNotDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := &Engine{cfg: Config{Fallback: []string{ProbeHTTP}, Dial: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("canceled target dialed")
		return nil, errors.New("unexpected dial")
	}}, enabled: map[string]bool{ProbeHTTP: true}}
	o := e.Interrogate(ctx, Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 80})
	if o.ProbeStopReason != "canceled" || len(o.ProbeDecisions) != 0 {
		t.Fatalf("canceled result: %+v", o)
	}
}

func TestAdaptiveQuietGapCannotExtendDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	e := &Engine{cfg: Config{MaxEvidence: 64}}
	rc := e.record(client)
	stop := deadline(context.Background(), rc, 60*time.Millisecond)
	defer stop()
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = server.Write([]byte("hello"))
	}()
	start := time.Now()
	data, err := readSome(rc, 64, time.Second)
	if string(data) != "hello" || !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(start) > 300*time.Millisecond {
		t.Fatalf("quiet read escaped its budget: data=%q err=%v elapsed=%s", data, err, time.Since(start))
	}
}

func TestAdaptiveHTTPRequiresGrammar(t *testing.T) {
	for _, data := range []string{"HTTP/1.garbage", "HTTP/1.1 garbage\r\n\r\n", "HTTP/1.1 200 OK\r\nBad header\r\n\r\n"} {
		var o observe.Observation
		if parseHTTP(&o, []byte(data)) || responseHint([]byte(data)) != "" {
			t.Fatalf("malformed HTTP became evidence: %q", data)
		}
	}
}

func TestAdaptiveUDPExchangesPreserveEvidenceIndices(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := plannerEngine(ProbeQUIC, ProbeDTLS)
	p := newProbePlannerFor(e, 443, "udp")
	o := observe.Observation{Evidence: []observe.Evidence{{Probe: "earlier", Response: []byte("preserve")}}}
	target := Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 443, Transport: "udp"}
	for _, name := range []string{ProbeQUIC, ProbeDTLS} {
		before, start := p.probabilities(), len(o.Evidence)
		if name == ProbeQUIC {
			e.probeQUIC(ctx, target, &o)
		} else {
			e.probeDTLS(ctx, target, &o)
		}
		p.observeExchange(&o, name, false, start, before, e)
		if o.Evidence[start].Probe != name || o.Evidence[0].Probe != "earlier" {
			t.Fatalf("UDP exchange moved earlier evidence: %+v", o.Evidence)
		}
		last := o.ProbeUpdates[len(o.ProbeUpdates)-1]
		if last.EvidenceStart != start || last.EvidenceEnd != start+1 || !reflect.DeepEqual(last.Before, last.After) {
			t.Fatalf("UDP error changed confidence or evidence reference: %+v", last)
		}
	}
}

func TestAdaptiveHTTP2OnlyUsesOneHandshake(t *testing.T) {
	var connections, requests atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.ProtoMajor != 2 {
			t.Errorf("HTTP/1 fallback request: %s", r.Proto)
		}
		w.Header().Set("Server", "Caddy/2.9.1")
		_, _ = io.WriteString(w, "<title>h2 only</title>")
	}))
	srv.EnableHTTP2 = true
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	srv.TLS = &tls.Config{NextProtos: []string{"h2"}}
	srv.StartTLS()
	defer srv.Close()
	e, err := Start(context.Background(), Config{Probes: []string{ProbeTLS, ProbeHTTP}, Fallback: []string{ProbeTLS},
		Timeout: time.Second, Workers: 1,
	}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	o := e.Interrogate(context.Background(), targetOf(t, srv.Listener.Addr().String()))
	checkAdaptiveTrace(t, o)
	if o.Service != "https" || o.Product != "Caddy" || o.Version != "2.9.1" || o.TLS.ALPN != "h2" ||
		o.Attributes["http.title"] != "h2 only" || o.Attributes["http.version"] != "HTTP/2" || connections.Load() != 1 || requests.Load() != 1 {
		t.Fatalf("HTTP/2 identity or connection reuse: connections=%d requests=%d result=%+v", connections.Load(), requests.Load(), o)
	}
	if len(o.ProbeDecisions) != 2 || o.ProbeDecisions[1].Probe != "http2" || len(o.Evidence) != 2 ||
		!bytes.HasPrefix(o.Evidence[1].Request, []byte(http2.ClientPreface)) || len(o.Evidence[1].Response) == 0 {
		t.Fatalf("missing HTTP/2 planning or wire evidence: %+v", o)
	}
}

const envoyInfo = `{"version":"b050513e840aa939a01f89b07c162f00ab3150eb/1.31.2/Clean/RELEASE/BoringSSL","state":"LIVE","command_line_options":{"concurrency":8},"uptime_current_epoch":"6s"}`

func TestAdaptiveEnvoyValidationFollowsProductHint(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP1", true: "HTTP2"}[h2], func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Server", "envoy")
				if r.URL.Path == "/server_info" {
					_, _ = io.WriteString(w, envoyInfo)
				}
			}))
			srv.EnableHTTP2 = h2
			srv.StartTLS()
			defer srv.Close()
			o := testEngine(t, ProbeTLS).Interrogate(context.Background(), targetOf(t, srv.Listener.Addr().String()))
			checkAdaptiveTrace(t, o)
			if o.Service != "https" || o.Product != "Envoy Proxy" || o.Version != "1.31.2" || o.Attributes["envoy.confidence"] != "99" || requests.Load() != 2 {
				t.Fatalf("Envoy product path failed: requests=%d result=%+v", requests.Load(), o)
			}
			last := o.ProbeUpdates[len(o.ProbeUpdates)-1]
			if last.Probe != "envoy-validation" || last.Outcome != "matched" {
				t.Fatalf("missing product confidence update: %+v", last)
			}
		})
	}
}

func TestAdaptiveEnvoyValidationDoesNotAcceptHeaderAlone(t *testing.T) {
	for _, body := range []string{`{"version":"1.31.2"}`, strings.Replace(envoyInfo, `"LIVE"`, `"not-a-state"`, 1), strings.Replace(envoyInfo, "/Clean/", "/Forged/", 1)} {
		if version, ok := parseEnvoyInfo([]byte("HTTP/1.1 200 OK\r\n\r\n" + body)); ok {
			t.Fatalf("generic or malformed JSON claimed Envoy %s: %s", version, body)
		}
	}
}
