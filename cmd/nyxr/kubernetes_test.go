package main

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHistoryCollectsKubernetesNodes(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/v1/nodes" || r.URL.Query().Get("limit") != "500" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected Kubernetes request: %s", r.URL)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			fmt.Fprint(w, `{"metadata":{"continue":"next page"},"items":[{"metadata":{"uid":"node-123"},"status":{"addresses":[{"type":"InternalIP","address":"192.0.2.10"},{"type":"Hostname","address":"node-a"}]}}]}`)
			return
		}
		if r.URL.Query().Get("continue") != "next page" {
			t.Errorf("missing pagination cursor: %s", r.URL)
		}
		fmt.Fprint(w, `{"metadata":{},"items":[{"metadata":{"uid":"node-123"},"status":{"addresses":[{"type":"ExternalIP","address":"198.51.100.10"}]}}]}`)
	}))
	defer server.Close()
	dir := t.TempDir()
	tokenFile, caFile, dbFile := filepath.Join(dir, "token"), filepath.Join(dir, "ca.pem"), filepath.Join(dir, "nyxr.db")
	if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := run([]string{"history", "--db", dbFile, "--kube-api", server.URL,
		"--kube-token-file", tokenFile, "--kube-ca-file", caFile,
		"--kube-cluster-scope", "cluster-a", "--json"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !strings.Contains(out.String(), `"profile":"kubernetes-api"`) {
		t.Fatalf("collection: %d requests, %s", calls, out.String())
	}
	out.Reset()
	if err := run([]string{"history", "--db", dbFile, "--identities", "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(out.String()), "\n"); len(lines) != 1 ||
		!strings.Contains(lines[0], "192.0.2.10") || !strings.Contains(lines[0], "198.51.100.10") {
		t.Fatalf("Kubernetes node addresses were not correlated: %s", out.String())
	}
}

func TestKubernetesCollectionRejectsInsecureConnectionAndConflictingAddresses(t *testing.T) {
	if _, err := collectKubernetesNodes(t.Context(), "http://example.com", "", "", "cluster-a"); err == nil {
		t.Fatal("insecure API origin accepted")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"items":[{"metadata":{"uid":"node-a"},"status":{"addresses":[{"type":"InternalIP","address":"192.0.2.1"}]}},{"metadata":{"uid":"node-b"},"status":{"addresses":[{"type":"InternalIP","address":"192.0.2.1"}]}}]}`)
	}))
	defer server.Close()
	dir := t.TempDir()
	tokenFile, caFile := filepath.Join(dir, "token"), filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(tokenFile, []byte("test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := collectKubernetesNodes(t.Context(), server.URL, tokenFile, "", "cluster-a"); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if _, err := collectKubernetesNodes(t.Context(), server.URL, tokenFile, caFile, "cluster-a"); err == nil || !strings.Contains(err.Error(), "disagree about address") {
		t.Fatalf("conflicting node addresses: %v", err)
	}
}
