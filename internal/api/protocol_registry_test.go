package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/service"
	"github.com/matusso/nyxr/internal/storage"
)

func TestProtocolRegistryReloadAPIAndScanSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operator.yaml")
	write := func(name string) {
		t.Helper()
		body := "schema: nyxr/protocol/v1\nprotocol: " + name + "\ntransport: tcp\nports: [9001]\nsteps:\n  - expect: {prefix: OK}\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("first")
	registry, err := service.NewRegistry([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(context.Background(), filepath.Join(dir, "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager, err := NewManager(ManagerConfig{Store: store, ProtocolRegistry: registry})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	on := true
	request := config.Request{Targets: []string{"192.0.2.1"}, Profile: "tcp-basic", Service: &on}
	before, err := manager.Resolve(request)
	if err != nil || len(before.Service.Definitions) != 1 || before.Service.RegistryVersion != 1 {
		t.Fatalf("initial scan snapshot: %+v, %v", before.Service, err)
	}
	handler := Handler(ServerConfig{Manager: manager, Store: store, Token: "0123456789abcdef"})
	unauthenticatedHandler := Handler(ServerConfig{Manager: manager, Store: store})
	unauthenticatedRequest := httptest.NewRequest(http.MethodPost, "/api/v1/protocol-definitions/reload", strings.NewReader("{}"))
	unauthenticatedRequest.Header.Set("Content-Type", "application/json")
	unauthenticatedResponse := httptest.NewRecorder()
	unauthenticatedHandler.ServeHTTP(unauthenticatedResponse, unauthenticatedRequest)
	if unauthenticatedResponse.Code != http.StatusForbidden {
		t.Fatalf("reload without configured token: %d", unauthenticatedResponse.Code)
	}
	post := func(body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/protocol-definitions/reload", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := post("{}", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated reload: %d", w.Code)
	}
	if w := post(`{"path":"/etc/passwd"}`, "0123456789abcdef"); w.Code != http.StatusBadRequest {
		t.Fatalf("caller selected server path: %d", w.Code)
	}
	write("second")
	if w := post("{}", "0123456789abcdef"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"version":2`) {
		t.Fatalf("validated reload: %d %s", w.Code, w.Body.String())
	}
	after, err := manager.Resolve(request)
	if err != nil || before.Service.Definitions[0].Name != "first" || after.Service.Definitions[0].Name != "second" || after.Service.RegistryVersion != 2 {
		t.Fatalf("scan snapshots changed across reload: before %+v, after %+v, err %v", before.Service, after.Service, err)
	}
	request.ProtocolDefinitions = "/etc/passwd"
	if _, err := manager.Resolve(request); err == nil || !strings.Contains(err.Error(), "remote requests") {
		t.Fatalf("remote scan accepted path: %v", err)
	}
}
