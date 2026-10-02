package service

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

func plannerEngine(fallback ...string) *Engine {
	enabled := map[string]bool{}
	for _, name := range Names() {
		enabled[name] = true
	}
	return &Engine{cfg: Config{Fallback: fallback}, enabled: enabled}
}

func probability(p *probePlanner, family string) float64 {
	return p.prob[familyIndex(family)]
}

func TestPlannerUpdatesAndReordersAfterEveryResponse(t *testing.T) {
	e := plannerEngine()
	p := newProbePlanner(e, 443)
	if next, _, _ := p.next(); next != ProbeTLS {
		t.Fatalf("443 should initially favor TLS; got %s", next)
	}
	priorTLS := probability(p, ProbeTLS)
	p.update(ProbeTLS, false, nil, e)
	if probability(p, ProbeTLS) >= priorTLS {
		t.Fatal("failed TLS handshake did not reduce TLS probability")
	}
	if next, gain, score := p.next(); next != ProbeHTTP || gain <= 0 || score <= 0 {
		t.Fatalf("expected informative HTTP follow-up, got %q gain=%g score=%g", next, gain, score)
	}
	p.update(ProbeHTTP, true, []byte("HTTP/1.1 200 OK\r\n\r\n"), e)
	if probability(p, ProbeHTTP) < 0.9 {
		t.Fatalf("validated HTTP response has weak posterior: %v", p.probabilities())
	}
	var sum float64
	for _, hypothesis := range p.probabilities() {
		sum += hypothesis.Probability
	}
	if sum < 0.999999 || sum > 1.000001 {
		t.Fatalf("posterior does not normalize: %g", sum)
	}
}

func TestPlannerUsesResponseShapeToUnlockRedisProbe(t *testing.T) {
	e := plannerEngine(ProbeHTTP)
	p := newProbePlanner(e, 12345)
	if next, _, _ := p.next(); next != ProbeHTTP {
		t.Fatalf("unexpected initial probe %s", next)
	}
	if p.candidates[ProbeDatabase] {
		t.Fatal("database probe should need a port hint or response signal")
	}
	p.update(ProbeHTTP, false, []byte("-ERR unknown command 'GET'\r\n"), e)
	if next, _, _ := p.next(); next != ProbeDatabase || !p.redisHint {
		t.Fatalf("RESP-shaped HTTP rejection did not select Redis probe: %s", next)
	}
	if probability(p, ProbeDatabase) < 0.8 {
		t.Fatalf("RESP-shaped response did not raise database odds: %v", p.probabilities())
	}
}

func TestPlannerTreatsPlainHTTPOnTLSAsTLSHint(t *testing.T) {
	e := plannerEngine(ProbeHTTP)
	p := newProbePlanner(e, 12345)
	response := []byte("HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n")
	if !plaintextToTLSError(response) {
		t.Fatal("TLS server's HTTP error was not recognized")
	}
	p.update(ProbeHTTP, false, response, e)
	if next, _, _ := p.next(); next != ProbeTLS {
		t.Fatalf("expected TLS probe after transport error; got %s", next)
	}
	if probability(p, ProbeTLS) < 0.8 {
		t.Fatalf("transport error did not raise TLS odds: %v", p.probabilities())
	}
}

func TestPlannerRedisOnUnusualPort(t *testing.T) {
	target := serve(t, func(c net.Conn) {
		var first [4]byte
		if _, err := io.ReadFull(c, first[:]); err != nil {
			return // passive banner connection
		}
		switch string(first[:]) {
		case "GET ":
			_, _ = io.WriteString(c, "-ERR unknown command 'GET'\r\n")
		case "*1\r\n":
			_, _ = io.WriteString(c, "+PONG\r\n")
		}
	})
	e, err := Start(context.Background(), Config{
		Probes: []string{ProbeBanner, ProbeHTTP, ProbeDatabase}, Fallback: []string{ProbeHTTP},
		Timeout: 250 * time.Millisecond, Workers: 1,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(target.Addr.String(), strconv.Itoa(int(target.Port))))
		},
	}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 12345})
	if o.Service != "redis" || o.Fingerprint != observe.FingerprintMatched {
		t.Fatalf("Redis on unusual port not identified: %+v", o)
	}
	if want := []string{ProbeBanner, ProbeHTTP, ProbeDatabase}; !reflect.DeepEqual(o.ProbesAttempted, want) {
		t.Fatalf("probe path %v, want %v", o.ProbesAttempted, want)
	}
	if len(o.ProbeDecisions) != 2 || o.ServiceHypotheses[0].Family != ProbeDatabase {
		t.Fatalf("planner trace missing: %+v", o)
	}
	if o.ProbeDecisions[1].Hypotheses[0].Family != ProbeDatabase ||
		o.ProbeDecisions[1].Hypotheses[0].Probability < 0.8 {
		t.Fatalf("second decision did not preserve updated odds: %+v", o.ProbeDecisions[1])
	}
}

func TestPlannerReusesHTTPResponseForDatabaseIdentity(t *testing.T) {
	target := serve(t, func(c net.Conn) {
		var first [4]byte
		if _, err := io.ReadFull(c, first[:]); err != nil {
			return // passive banner connection
		}
		if string(first[:]) == "GET " {
			_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nX-Elastic-Product: Elasticsearch\r\nConnection: close\r\n\r\n{\"version\":{\"number\":\"8.12.0\"}}")
		}
	})
	e, err := Start(context.Background(), Config{
		Probes: []string{ProbeBanner, ProbeHTTP, ProbeDatabase}, Fallback: []string{ProbeHTTP},
		Timeout: 250 * time.Millisecond, Workers: 1,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(target.Addr.String(), strconv.Itoa(int(target.Port))))
		},
	}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 12345})
	if o.Service != "elasticsearch" || o.Version != "8.12.0" {
		t.Fatalf("HTTP database identity not extracted: %+v", o)
	}
	if len(o.ProbeDecisions) != 1 || o.Evidence[len(o.Evidence)-1].Matched != ProbeDatabase ||
		o.ServiceHypotheses[0].Family != "elasticsearch" {
		t.Fatalf("database identity should reuse HTTP exchange: %+v", o)
	}
}

func TestPlannerKeepsDatabaseIdentityInsideTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		_, _ = io.WriteString(w, "{\"version\":{\"number\":\"8.12.0\"}}")
	}))
	defer srv.Close()
	target := targetOf(t, srv.Listener.Addr().String())
	e, err := Start(context.Background(), Config{
		Probes:   []string{ProbeBanner, ProbeTLS, ProbeHTTP, ProbeDatabase},
		Fallback: []string{ProbeTLS, ProbeHTTP}, Timeout: 500 * time.Millisecond, Workers: 1,
	}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	o := e.Interrogate(context.Background(), target)
	if o.Service != "elasticsearch" || o.Version != "8.12.0" || o.TLS == nil {
		t.Fatalf("TLS database identity lost: %+v", o)
	}
	if o.ServiceHypotheses[0].Family != "elasticsearch" {
		t.Fatalf("posterior lost database identity: %+v", o.ServiceHypotheses)
	}
}
