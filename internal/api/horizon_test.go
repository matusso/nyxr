package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/horizon"
	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/packetio"
)

func apiExperiment(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../lab/horizon/sequence-v1alpha2.yaml")
	if err != nil {
		t.Fatal(err)
	}
	e, err := dsl.Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	b, err = json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func testRuns(t *testing.T, ctrl *horizon.Controller, modes []string) *horizon.Runs {
	t.Helper()
	audit, err := horizon.OpenAudit(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	runs, err := horizon.NewRuns(ctrl, horizon.RunsConfig{Modes: modes, Audit: audit, Metrics: horizon.NewMetrics()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runs.Close)
	return runs
}

func horizonGet(handler http.Handler, path, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func horizonPost(handler http.Handler, path string, body []byte, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

type blockingHorizonIO struct {
	packetio.PacketIO
	started chan struct{}
	once    sync.Once
}

func (b *blockingHorizonIO) ReceiveBatch(ctx context.Context, frames [][]byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-ctx.Done()
	return 0, ctx.Err()
}
func TestHorizonAPIIndependentPolicyAndKillSwitch(t *testing.T) {
	body := apiExperiment(t)
	disabled := Handler(ServerConfig{})
	for _, path := range []string{"plan", "resolve", "stop"} {
		if w := horizonPost(disabled, "/api/v1/horizon/"+path, body, ""); w.Code != http.StatusForbidden {
			t.Fatal("HORIZON enabled by default", w.Code)
		}
	}
	started := make(chan struct{})
	policy := model.Policy{Profile: "lab", AllowTargets: []string{"192.0.2.0/24"}, AllowPorts: []uint16{443, 8443}, Permissions: []string{"cross-port"}}
	link := horizon.Link{SourceIP: netip.MustParseAddr("192.0.2.1"), SourceMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, NextHopMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, Backend: "test"}
	opened := 0
	controller := horizon.NewController(policy, link, func() (packetio.PacketIO, error) {
		opened++
		sim, _ := horizon.NewSimulator("loss")
		return &blockingHorizonIO{PacketIO: sim, started: started}, nil
	})
	defer controller.Close()
	// The sample experiment is cross-port: reconstruct must be enabled explicitly.
	handler := Handler(ServerConfig{Horizon: testRuns(t, controller, horizon.DefaultModes), Token: "operator-token-123"})
	if w := horizonPost(handler, "/api/v1/horizon/resolve", body, "operator-token-123"); w.Code != http.StatusForbidden || opened != 0 {
		t.Fatal("reconstruct ran without being enabled", w.Code)
	}
	handler = Handler(ServerConfig{Horizon: testRuns(t, controller, horizon.Modes), Token: "operator-token-123"})
	if w := horizonPost(handler, "/api/v1/horizon/stop", []byte(`{}`), ""); w.Code != http.StatusUnauthorized {
		t.Fatal("unauthenticated kill switch", w.Code)
	}
	if w := horizonPost(handler, "/api/v1/horizon/plan", body, "operator-token-123"); w.Code != http.StatusOK || opened != 0 {
		t.Fatal("dry plan opened a backend", w.Code, w.Body.String())
	}
	bad := bytes.Replace(body, []byte(`192.0.2.10`), []byte(`198.51.100.10`), 1)
	if w := horizonPost(handler, "/api/v1/horizon/resolve", bad, "operator-token-123"); w.Code != http.StatusUnprocessableEntity || opened != 0 {
		t.Fatal("request bypassed server scope", w.Code)
	}
	// Requests may not smuggle their own operator policy.
	bad = append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"policy":{"profile":"lab"}}`)...)
	if w := horizonPost(handler, "/api/v1/horizon/plan", bad, "operator-token-123"); w.Code != http.StatusBadRequest {
		t.Fatal("remote policy accepted", w.Code)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- horizonPost(handler, "/api/v1/horizon/resolve", body, "operator-token-123") }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("API run did not start")
	}
	if w := horizonPost(handler, "/api/v1/horizon/resolve", body, "operator-token-123"); w.Code != http.StatusTooManyRequests {
		t.Fatal("aggregate concurrency bypassed", w.Code)
	}
	if w := horizonPost(handler, "/api/v1/horizon/stop", []byte(`{}`), "operator-token-123"); w.Code != http.StatusAccepted {
		t.Fatal("stop failed", w.Code)
	}
	select {
	case w := <-done:
		if w.Code != http.StatusConflict {
			t.Fatal("partial report status", w.Code)
		}
		envelope, err := horizon.Replay(bytes.NewReader(w.Body.Bytes()))
		// Each receive ends at its response window, so a slow stop (the audit
		// fsync in between) may let a few more probes go out; it must still be
		// a partial, replayable report.
		if err != nil || envelope.Report.Completed || envelope.Report.PacketsTX < 1 || envelope.Report.StopReason == "" {
			t.Fatal("partial API evidence invalid", err, envelope.Report.PacketsTX)
		}
	case <-time.After(time.Second):
		t.Fatal("API stop did not wake executor")
	}
	if w := horizonPost(handler, "/api/v1/horizon/resolve", body, "operator-token-123"); w.Code != http.StatusConflict || opened != 1 {
		t.Fatal("stopped API restarted", w.Code)
	}
}

func TestHorizonRunsAPI(t *testing.T) {
	policy := model.Policy{Profile: "lab", AllowTargets: []string{"192.0.2.0/24"}, AllowPorts: []uint16{443, 8443}, Permissions: []string{"cross-port"}}
	link := horizon.Link{SourceIP: netip.MustParseAddr("192.0.2.1"), SourceMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, NextHopMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, Backend: "test"}
	controller := horizon.NewController(policy, link, func() (packetio.PacketIO, error) { return horizon.NewSimulator("sack") })
	defer controller.Close()
	const token = "operator-token-123"
	handler := Handler(ServerConfig{Horizon: testRuns(t, controller, horizon.Modes), Token: token})
	for _, path := range []string{"/api/v1/horizon", "/api/v1/horizon/runs", "/api/v1/horizon/metrics"} {
		if w := horizonGet(handler, path, ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s without token: %d", path, w.Code)
		}
	}
	experiment := apiExperiment(t)
	request := func(mode string) []byte {
		return []byte(`{"mode":"` + mode + `","experiment":` + string(experiment) + `}`)
	}
	for body, want := range map[string]int{
		string(request("resolve")):                               http.StatusUnprocessableEntity, // mode mismatch: the sample is cross-port
		`{"mode":"reconstruct"}`:                                 http.StatusBadRequest,
		`{"mode":"reconstruct","experiment":{},"policy":{}}`:     http.StatusBadRequest,
		`{"mode":"reconstruct","experiment":{"apiVersion":"x"}}`: http.StatusBadRequest,
	} {
		if w := horizonPost(handler, "/api/v1/horizon/runs", []byte(body), token); w.Code != want {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
	w := horizonPost(handler, "/api/v1/horizon/runs", request("reconstruct"), token)
	if w.Code != http.StatusAccepted {
		t.Fatal(w.Code, w.Body.String())
	}
	var st model.RunStatus
	json.Unmarshal(w.Body.Bytes(), &st)
	if st.State != "running" || st.Mode != "reconstruct" || len(st.ID) != 24 {
		t.Fatalf("created %+v", st)
	}
	if w := horizonGet(handler, "/api/v1/horizon/runs/"+st.ID+"/report", token); w.Code != http.StatusConflict {
		t.Fatal("report of a running run", w.Code)
	}
	deadline := time.Now().Add(60 * time.Second)
	for st.State == "running" && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		json.Unmarshal(horizonGet(handler, "/api/v1/horizon/runs/"+st.ID, token).Body.Bytes(), &st)
	}
	if st.State != "completed" || st.ReportSHA256 == "" {
		t.Fatalf("finished %+v", st)
	}
	w = horizonGet(handler, "/api/v1/horizon/runs/"+st.ID+"/report", token)
	if env, err := horizon.Replay(bytes.NewReader(w.Body.Bytes())); err != nil || env.SHA256 != st.ReportSHA256 {
		t.Fatal("exported report does not replay", err)
	}
	if w := horizonGet(handler, "/api/v1/horizon/runs/"+st.ID+"/evidence-graph", token); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "EvidenceGraph") {
		t.Fatal("graph", w.Code, w.Body.String())
	}
	if w := horizonPost(handler, "/api/v1/horizon/runs/"+st.ID+"/cancel", []byte(`{}`), token); w.Code != http.StatusConflict {
		t.Fatal("cancel finished run", w.Code)
	}
	for _, path := range []string{"/api/v1/horizon/runs/nope", "/api/v1/horizon/runs/nope/report", "/api/v1/horizon/runs/nope/evidence-graph"} {
		if w := horizonGet(handler, path, token); w.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	var list struct{ Runs []model.RunStatus }
	json.Unmarshal(horizonGet(handler, "/api/v1/horizon/runs", token).Body.Bytes(), &list)
	if len(list.Runs) != 1 {
		t.Fatalf("list %+v", list)
	}
	metrics := horizonGet(handler, "/api/v1/horizon/metrics", token)
	if !strings.HasPrefix(metrics.Header().Get("Content-Type"), "text/plain") || !strings.Contains(metrics.Body.String(), `nyxr_horizon_runs_total{mode="reconstruct",state="completed"} 1`) ||
		!strings.Contains(metrics.Body.String(), `nyxr_horizon_admission_denied_total{reason="mode-mismatch"} 1`) {
		t.Fatal("metrics", metrics.Body.String())
	}
	// Oversized bodies are cut off by the API body limit before decoding.
	huge := append([]byte(`{"mode":"reconstruct","experiment":"`), bytes.Repeat([]byte("a"), maxBody+1)...)
	if w := horizonPost(handler, "/api/v1/horizon/runs", append(huge, '"', '}'), token); w.Code != http.StatusBadRequest {
		t.Fatal("oversized body", w.Code)
	}
}

func FuzzHorizonRunRequest(f *testing.F) {
	f.Add([]byte(`{"mode":"reconstruct","experiment":{"apiVersion":"horizon.nyxr.io/v1alpha2"}}`))
	f.Add([]byte(`{"mode":"resolve","experiment":[]}`))
	policy := model.Policy{Profile: "lab", AllowTargets: []string{"192.0.2.0/24"}, AllowPorts: []uint16{443}}
	link := horizon.Link{SourceIP: netip.MustParseAddr("192.0.2.1"), SourceMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, NextHopMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, Backend: "test"}
	// A transport that cannot open keeps fuzzed runs from sending anything.
	controller := horizon.NewController(policy, link, nil)
	audit, err := horizon.OpenAudit(filepath.Join(f.TempDir(), "audit.jsonl"))
	if err != nil {
		f.Fatal(err)
	}
	runs, err := horizon.NewRuns(controller, horizon.RunsConfig{Modes: horizon.Modes, Audit: audit})
	if err != nil {
		f.Fatal(err)
	}
	handler := Handler(ServerConfig{Horizon: runs, Token: "operator-token-123"})
	f.Fuzz(func(t *testing.T, b []byte) {
		w := horizonPost(handler, "/api/v1/horizon/runs", b, "operator-token-123")
		if w.Code == http.StatusAccepted || w.Code >= 500 {
			t.Fatalf("fuzzed request: %d %s", w.Code, w.Body.String())
		}
	})
}

func TestHorizonAPIRequiresToken(t *testing.T) {
	policy := model.Policy{Profile: "lab", AllowTargets: []string{"192.0.2.0/24"}, AllowPorts: []uint16{443}}
	controller := horizon.NewController(policy, horizon.Link{}, nil)
	handler := Handler(ServerConfig{Horizon: testRuns(t, controller, horizon.Modes)})
	for _, path := range []string{"/api/v1/horizon", "/api/v1/horizon/runs", "/api/v1/horizon/metrics"} {
		if w := horizonGet(handler, path, ""); w.Code != http.StatusForbidden {
			t.Fatalf("%s served without a configured token: %d", path, w.Code)
		}
	}
	if w := horizonPost(handler, "/api/v1/horizon/stop", []byte(`{}`), ""); w.Code != http.StatusForbidden {
		t.Fatal("tokenless kill switch", w.Code)
	}
}
