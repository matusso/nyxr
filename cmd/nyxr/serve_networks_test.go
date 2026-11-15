package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/api"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/storage"
)

// The cookie selects which network database answers; without it the default
// database does. Networks are created through the authenticated registry API.
func TestNetworkRouterSelectsDatabaseByCookie(t *testing.T) {
	ctx := context.Background()
	registryPath := filepath.Join(t.TempDir(), "nyxr.db")
	registry, err := openStore(ctx, registryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	router := &networkRouter{ctx: ctx, registryPath: registryPath, registry: registry, open: map[string]*servedNetwork{}}
	router.build = func(st *storage.Store, network string) (http.Handler, *api.Manager, error) {
		m, err := api.NewManager(api.ManagerConfig{Store: st})
		cfg := api.ServerConfig{Manager: m, Store: st}
		if st == registry {
			cfg.Networks = &api.Networks{Create: router.create}
		}
		return api.Handler(cfg), m, err
	}
	defer router.close()
	h, m, err := router.build(registry, "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	router.fallback, router.registryAPI = h, h
	srv := httptest.NewServer(router)
	defer srv.Close()
	do := func(method, path, body, network string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if network != "" {
			req.AddCookie(&http.Cookie{Name: networkCookie, Value: url.QueryEscape(network)})
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, body := do("GET", "/api/v1/networks", "", ""); code != 200 || !strings.Contains(body, `"enabled":true`) || !strings.Contains(body, `"networks":[]`) {
		t.Fatalf("empty registry: %d %s", code, body)
	}
	if code, body := do("POST", "/api/v1/networks", `{"name":"office lan"}`, ""); code != 201 || !strings.Contains(body, "office-lan.db") {
		t.Fatalf("create: %d %s", code, body)
	}
	if code, _ := do("POST", "/api/v1/networks", `{"name":"  "}`, ""); code != 400 {
		t.Fatalf("blank name: %d", code)
	}
	// Put one scan in the network's database; only its cookie sees it.
	served, err := router.network("office lan")
	if err != nil || served == nil {
		t.Fatalf("open network: %v", err)
	}
	scan := observe.Scan{ID: "in-office", Name: "office lan", Profile: "test", Started: time.Now().UTC(), Status: "running"}
	if err := served.store.BeginScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	scan.Status, scan.Finished = "completed", time.Now().UTC()
	if err := served.store.FinishScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	if _, body := do("GET", "/api/v1/scans", "", "office lan"); !strings.Contains(body, "in-office") {
		t.Errorf("network scans: %s", body)
	}
	for _, other := range []string{"", "no-such-network"} {
		if _, body := do("GET", "/api/v1/scans", "", other); strings.Contains(body, "in-office") {
			t.Errorf("cookie %q reached the network database", other)
		}
	}
	// A finished scan refreshes the registry row and its digest.
	router.finished(served.store, "office lan")
	row, _, err := registry.Network(ctx, "office lan")
	sum, _ := fileSHA256(row.Path)
	if err != nil || row.Scans != 1 || row.LastScanID != "in-office" || row.SHA256 != sum {
		t.Errorf("registry after scan: %+v, %v", row, err)
	}
}
