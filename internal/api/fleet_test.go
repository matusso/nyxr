package api

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/matusso/nyxr/internal/fleet"
	"github.com/matusso/nyxr/internal/storage"
)

func TestFleetAPIDisabledByDefault(t *testing.T) {
	e := newEnv(t, ManagerConfig{}, testToken)
	for _, path := range []string{"/api/v1/fleet", "/api/v1/fleet/agents", "/api/v1/fleet/scans"} {
		if res, _ := e.do(t, http.MethodGet, path, ""); res.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: status %d", path, res.StatusCode)
		}
	}
}

func TestFleetAPIJobLifecycle(t *testing.T) {
	store, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "fleet.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctrl, err := fleet.NewController(fleet.ControllerConfig{Store: store, Log: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(ManagerConfig{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(Handler(ServerConfig{Manager: m, Store: store, Token: testToken, Version: "test", Fleet: ctrl,
		AllowedHosts: []string{"127.0.0.1"}}))
	t.Cleanup(func() { srv.Close(); ctrl.Close(); m.Close(); store.Close() })
	e := &env{srv: srv, manager: m, store: store}

	if res, body := e.do(t, http.MethodPost, "/api/v1/fleet/scans", `{"request":{"targets":["10.0.0.0/23"],"ports":"80"},"bogus":1}`); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d %s", res.StatusCode, body)
	}
	if res, body := e.do(t, http.MethodPost, "/api/v1/fleet/scans", `{"request":{"targets":["10.0.0.1"],"ports":"80","interface":"eth0"}}`); res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("vantage-specific request accepted: %d %s", res.StatusCode, body)
	}
	res, body := e.do(t, http.MethodPost, "/api/v1/fleet/scans", `{"request":{"targets":["10.0.0.0/23"],"ports":"80"},"unit_size":256,"max_parallel":2}`)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", res.StatusCode, body)
	}
	var job storage.FleetJob
	if err := json.Unmarshal(body, &job); err != nil || job.Units != 2 || job.Targets != 512 || job.Status != storage.FleetRunning {
		t.Fatalf("job %+v %v", job, err)
	}
	if res.Header.Get("Location") != "/api/v1/fleet/scans/"+job.ID {
		t.Fatalf("location %q", res.Header.Get("Location"))
	}
	res, body = e.do(t, http.MethodGet, "/api/v1/fleet/scans/"+job.ID, "")
	var detail fleet.JobDetail
	if res.StatusCode != http.StatusOK || json.Unmarshal(body, &detail) != nil || len(detail.UnitList) != 2 || detail.UnitList[0].Waiting != "no agent connected" {
		t.Fatalf("detail %d %s", res.StatusCode, body)
	}
	if res, body := e.do(t, http.MethodPost, "/api/v1/fleet/scans/"+job.ID+"/cancel", "{}"); res.StatusCode != http.StatusAccepted {
		t.Fatalf("cancel %d %s", res.StatusCode, body)
	}
	if res, _ := e.do(t, http.MethodPost, "/api/v1/fleet/scans/"+job.ID+"/cancel", "{}"); res.StatusCode != http.StatusConflict {
		t.Fatalf("second cancel %d", res.StatusCode)
	}
	res, body = e.do(t, http.MethodGet, "/api/v1/fleet/scans", "")
	var list struct{ Jobs []storage.FleetJob }
	if res.StatusCode != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Jobs) != 1 || list.Jobs[0].Status != storage.FleetCanceled {
		t.Fatalf("list %d %s", res.StatusCode, body)
	}
	if res, _ := e.do(t, http.MethodPost, "/api/v1/fleet/agents/agent-none/revoke", "{}"); res.StatusCode != http.StatusNotFound {
		t.Fatalf("revoke unknown %d", res.StatusCode)
	}
}
