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
	handler := Handler(ServerConfig{Horizon: controller, Token: "operator-token-123"})
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
		if err != nil || envelope.Report.Completed || envelope.Report.PacketsTX != 1 {
			t.Fatal("partial API evidence invalid", err)
		}
	case <-time.After(time.Second):
		t.Fatal("API stop did not wake executor")
	}
	if w := horizonPost(handler, "/api/v1/horizon/resolve", body, "operator-token-123"); w.Code != http.StatusConflict || opened != 1 {
		t.Fatal("stopped API restarted", w.Code)
	}
}
