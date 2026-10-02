package api

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/packetio"
	"github.com/matusso/nyxr/internal/pipeline"
	"github.com/matusso/nyxr/internal/scan"
	"github.com/matusso/nyxr/internal/storage"
)

const testToken = "0123456789abcdef-token"

type env struct {
	srv     *httptest.Server
	manager *Manager
	store   *storage.Store
}

func newEnv(t *testing.T, mc ManagerConfig, token string) *env {
	t.Helper()
	store, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	mc.Store = store
	m, err := NewManager(mc)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(Handler(ServerConfig{Manager: m, Store: store, Token: token, Version: "test",
		EvidenceDir: mc.EvidenceDir, AllowedHosts: []string{"127.0.0.1"}}))
	t.Cleanup(func() { srv.Close(); m.Close(); store.Close() })
	return &env{srv: srv, manager: m, store: store}
}

func (e *env) do(t *testing.T, method, path, body string, headers ...string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	for i := 0; i+1 < len(headers); i += 2 {
		if headers[i] == "Host" {
			req.Host = headers[i+1]
			continue
		}
		req.Header.Set(headers[i], headers[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, b
}

// fakeDiscover emits one open and one closed port per target, optionally
// waiting on release first.
func fakeDiscover(release <-chan struct{}) func(*pipeline.Options) {
	return func(o *pipeline.Options) {
		o.Discover = func(ctx context.Context, cfg config.Config, emit func(scan.Observation) error) error {
			if release != nil {
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			for _, target := range cfg.Targets {
				for i, state := range []string{"open", "closed"} {
					if err := emit(scan.Observation{Timestamp: time.Now().UTC(), Target: target, Transport: "tcp",
						Port: cfg.Ports[i%len(cfg.Ports)], State: state, Confidence: 100, Reason: "fake", Probe: "tcp-connect"}); err != nil {
						return err
					}
				}
			}
			return nil
		}
	}
}

func TestSecurityGuards(t *testing.T) {
	e := newEnv(t, ManagerConfig{}, testToken)
	req, _ := http.NewRequest("GET", e.srv.URL+"/api/v1/profiles", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %d", res.StatusCode)
	}
	if res, _ := e.do(t, "GET", "/api/v1/profiles", "", "Authorization", "Bearer wrong-token-000000"); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", res.StatusCode)
	}
	// A form post (possible cross-origin without preflight) is refused.
	if res, _ := e.do(t, "POST", "/api/v1/scans", "", "Content-Type", "text/plain"); res.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain POST: %d", res.StatusCode)
	}
	if res, _ := e.do(t, "GET", "/api/v1/profiles", "", "Host", "rebind.example:80"); res.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("foreign Host: %d", res.StatusCode)
	}
	res, body := e.do(t, "GET", "/", "")
	if res.StatusCode != 200 || !strings.Contains(string(body), "app.js") || !strings.Contains(res.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("UI: %d %q", res.StatusCode, res.Header.Get("Content-Security-Policy"))
	}
}

func TestStatsReflectStoredInventory(t *testing.T) {
	e := newEnv(t, ManagerConfig{}, testToken)
	now := time.Now().UTC()
	sc := observe.Scan{ID: "stats-scan", Profile: "tcp", Started: now, Status: "completed", Targets: 1}
	if err := e.store.BeginScan(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("192.0.2.42")
	port := observe.Observation{Timestamp: now, Target: addr, Transport: "tcp", Port: 443, State: "open"}
	service := observe.Observation{Kind: observe.KindService, Timestamp: now.Add(time.Second), Target: addr,
		Transport: "tcp", Port: 443, State: "open", Service: "https", Fingerprint: observe.FingerprintMatched}
	port.Stamp(sc.ID)
	service.Stamp(sc.ID)
	if err := e.store.AddObservations(context.Background(), []observe.Observation{port, service}); err != nil {
		t.Fatal(err)
	}
	res, body := e.do(t, "GET", "/api/v1/stats", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("stats: %d %s", res.StatusCode, body)
	}
	var stats map[string]int
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]int{"scans": 1, "running": 0, "hosts": 1, "open_ports": 1, "services": 1} {
		if stats[key] != want {
			t.Errorf("stats[%s] = %d, want %d", key, stats[key], want)
		}
	}
}

func TestPlanAndRefusals(t *testing.T) {
	e := newEnv(t, ManagerConfig{}, testToken)
	res, body := e.do(t, "POST", "/api/v1/plan", `{"targets":["127.0.0.1"],"ports":"22,80","protocols":"tcp","service":true}`)
	if res.StatusCode != 200 {
		t.Fatalf("plan: %d %s", res.StatusCode, body)
	}
	var plan config.StagePlan
	if err := json.Unmarshal(body, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Tasks != 2 || plan.Service == nil {
		t.Fatalf("plan = %+v", plan)
	}
	for name, doc := range map[string]string{
		"unknown field": `{"targets":["127.0.0.1"],"portz":"80"}`,
		"server file":   `{"targets":["127.0.0.1"],"protocols":"udp","ports":"53","udp_probe_file":"/etc/passwd"}`,
		"raw syn":       `{"targets":["127.0.0.1"],"ports":"80","protocols":"tcp","tcp_mode":"syn","interface":"eth0"}`,
		"icmp":          `{"targets":["127.0.0.1"],"protocols":"icmp"}`,
		"capture":       `{"targets":["127.0.0.1"],"ports":"80","protocols":"tcp","pcapng":"x.pcapng","interface":"eth0"}`,
		"ot-safe scope": `{"targets":["127.0.0.1"],"profile":"ot-safe"}`,
	} {
		for _, path := range []string{"/api/v1/plan", "/api/v1/scans"} {
			if res, body := e.do(t, "POST", path, doc); res.StatusCode < 400 {
				t.Errorf("%s via %s accepted: %s", name, path, body)
			}
		}
	}
}

func TestRawRequestsNeedPacketdAndEvidenceDir(t *testing.T) {
	opener := packetio.Opener(func(string) (packetio.PacketIO, error) { return nil, packetio.ErrUnavailable })
	dir := t.TempDir()
	m, err := NewManager(ManagerConfig{Store: &storage.Store{}, OpenLive: opener, EvidenceDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.Resolve(config.Request{Targets: []string{"127.0.0.1"}, Ports: "80", Protocols: "tcp", PCAPNG: "a.pcapng", Interface: "eth0"})
	if err != nil {
		t.Fatal(err)
	}
	if r.PCAPNG != filepath.Join(dir, "a.pcapng") {
		t.Fatalf("capture placed at %s", r.PCAPNG)
	}
}

func TestScanLifecycleWithLiveEvents(t *testing.T) {
	release := make(chan struct{})
	e := newEnv(t, ManagerConfig{Pipeline: fakeDiscover(release)}, testToken)
	res, body := e.do(t, "POST", "/api/v1/scans", `{"targets":["192.0.2.1","192.0.2.2"],"ports":"22,80","protocols":"tcp"}`)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", res.StatusCode, body)
	}
	var sc observe.Scan
	if err := json.Unmarshal(body, &sc); err != nil {
		t.Fatal(err)
	}
	if sc.ID == "" || sc.Status != "running" {
		t.Fatalf("created = %+v", sc)
	}
	// The running-scan limit (default 1) refuses a second scan.
	if res, _ := e.do(t, "POST", "/api/v1/scans", `{"targets":["192.0.2.3"],"ports":"22","protocols":"tcp"}`); res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second scan: %d", res.StatusCode)
	}

	req, _ := http.NewRequest("GET", e.srv.URL+"/api/v1/scans/"+sc.ID+"/events", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	stream, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	if ct := stream.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	close(release)
	events := readSSE(t, stream.Body)
	var observations int
	var last observe.Scan
	for _, ev := range events {
		switch ev.Type {
		case "observation":
			observations++
		case observe.KindScan:
			if err := json.Unmarshal(ev.Data, &last); err != nil {
				t.Fatal(err)
			}
		}
	}
	if observations != 4 || last.Status != "completed" || last.Observations != 4 {
		t.Fatalf("events: %d observations, final %+v", observations, last)
	}

	_, body = e.do(t, "GET", "/api/v1/scans/"+sc.ID+"/observations", "")
	var stored []observe.Observation
	if err := json.Unmarshal(body, &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 4 || stored[0].ScanID != sc.ID || stored[0].Schema != observe.SchemaVersion {
		t.Fatalf("stored = %s", body)
	}
	_, body = e.do(t, "GET", "/api/v1/scans/"+sc.ID+"/observations?address=192.0.2.2", "")
	if err := json.Unmarshal(body, &stored); err != nil || len(stored) != 2 {
		t.Fatalf("filtered = %s", body)
	}
	_, body = e.do(t, "GET", "/api/v1/scans", "")
	var list []observe.Scan
	if err := json.Unmarshal(body, &list); err != nil || len(list) != 1 || list[0].Status != "completed" {
		t.Fatalf("list = %s", body)
	}
	_, body = e.do(t, "GET", "/api/v1/assets", "")
	var assets []storage.Asset
	if err := json.Unmarshal(body, &assets); err != nil || len(assets) != 2 {
		t.Fatalf("assets = %s", body)
	}
	// A finished scan's event stream yields its stored summary and ends.
	_, body = e.do(t, "GET", "/api/v1/scans/"+sc.ID+"/events", "")
	if !strings.Contains(string(body), `"status":"completed"`) {
		t.Fatalf("finished stream = %s", body)
	}
	if res, _ := e.do(t, "GET", "/api/v1/scans/nope", ""); res.StatusCode != 404 {
		t.Fatalf("unknown scan: %d", res.StatusCode)
	}
}

func TestCancelKeepsPartialResults(t *testing.T) {
	e := newEnv(t, ManagerConfig{Pipeline: fakeDiscover(make(chan struct{}))}, testToken)
	_, body := e.do(t, "POST", "/api/v1/scans", `{"targets":["192.0.2.1"],"ports":"22","protocols":"tcp"}`)
	var sc observe.Scan
	if err := json.Unmarshal(body, &sc); err != nil {
		t.Fatal(err)
	}
	if res, _ := e.do(t, "POST", "/api/v1/scans/"+sc.ID+"/cancel", "{}"); res.StatusCode != http.StatusAccepted {
		t.Fatalf("cancel: %d", res.StatusCode)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		stored, ok, err := e.store.Scan(context.Background(), sc.ID)
		if err != nil {
			t.Fatal(err)
		}
		if ok && stored.Status == "failed" && strings.Contains(stored.Error, "canceled") {
			if res, _ := e.do(t, "POST", "/api/v1/scans/"+sc.ID+"/cancel", "{}"); res.StatusCode != http.StatusConflict {
				t.Fatalf("second cancel: %d", res.StatusCode)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("canceled scan was not recorded")
}

func TestHubDropsSlowSubscriberWithoutBlocking(t *testing.T) {
	h := newHub()
	_, slow, _ := h.subscribe(0)
	for i := 0; i < subscriberBuffer+10; i++ {
		h.publish("observation", i) // must not block
	}
	if !h.isLagged(slow) {
		t.Fatal("slow subscriber not marked lagged")
	}
	n := 0
	for range slow.ch {
		n++
	}
	if n != subscriberBuffer {
		t.Fatalf("slow subscriber got %d events", n)
	}
	// Resuming after the last delivered event replays the rest.
	replay, s, gap := h.subscribe(uint64(subscriberBuffer))
	if gap || len(replay) != 10 || s == nil {
		t.Fatalf("resume: gap=%v replay=%d", gap, len(replay))
	}
	for i := 0; i < historySize+5; i++ {
		h.publish("observation", i)
	}
	h.close()
	replay, s, gap = h.subscribe(0)
	if !gap || len(replay) != historySize || s != nil {
		t.Fatalf("evicted: gap=%v replay=%d sub=%v", gap, len(replay), s != nil)
	}
}

type sseEvent struct {
	Type string
	Data json.RawMessage
}

func readSSE(t *testing.T, r io.Reader) []sseEvent {
	t.Helper()
	var out []sseEvent
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var cur sseEvent
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			cur.Type = line[7:]
		case strings.HasPrefix(line, "data: "):
			cur.Data = json.RawMessage(line[6:])
		case line == "" && cur.Type != "":
			out = append(out, cur)
			cur = sseEvent{}
		}
	}
	return out
}

func TestOpenAssetsScopeAndKnownOpenPlan(t *testing.T) {
	e := newEnv(t, ManagerConfig{}, testToken)
	now := time.Now().UTC()
	sc := observe.Scan{ID: "seed", Profile: "fast", Started: now, Status: "running", Targets: 2}
	if err := e.store.BeginScan(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	var obs []observe.Observation
	for _, o := range []struct {
		addr  string
		port  uint16
		state string
	}{{"192.0.2.1", 22, "open"}, {"192.0.2.1", 80, "closed"}, {"192.0.2.2", 443, "open"}, {"192.0.2.2", 8080, "filtered"}, {"192.0.2.3", 22, "closed"}} {
		ob := observe.Observation{Timestamp: now, Target: netip.MustParseAddr(o.addr), Transport: "tcp", Port: o.port, State: o.state, Confidence: 100, Reason: "seed", Probe: "tcp-connect"}
		ob.Stamp(sc.ID)
		obs = append(obs, ob)
	}
	if err := e.store.AddObservations(context.Background(), obs); err != nil {
		t.Fatal(err)
	}
	var assets []storage.Asset
	_, body := e.do(t, "GET", "/api/v1/assets?open=true", "")
	if err := json.Unmarshal(body, &assets); err != nil || len(assets) != 2 || len(assets[0].Ports) != 1 || len(assets[1].Ports) != 1 {
		t.Fatalf("open assets = %s", body)
	}
	_, body = e.do(t, "GET", "/api/v1/assets?open=true&scope=192.0.2.2-192.0.2.9", "")
	if err := json.Unmarshal(body, &assets); err != nil || len(assets) != 1 || assets[0].Address.String() != "192.0.2.2" {
		t.Fatalf("scoped assets = %s", body)
	}
	if res, _ := e.do(t, "GET", "/api/v1/assets?scope=nope", ""); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad scope: %d", res.StatusCode)
	}
	res, body := e.do(t, "POST", "/api/v1/plan", `{"known_open":true,"targets":["192.0.2.0/24"]}`)
	var plan config.StagePlan
	if err := json.Unmarshal(body, &plan); err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("plan: %d %s", res.StatusCode, body)
	}
	if !plan.KnownOpen || plan.Tasks != 2 || plan.Targets != 2 || plan.Service == nil || plan.Profile != config.KnownProfile {
		t.Fatalf("known-open plan = %s", body)
	}
}
