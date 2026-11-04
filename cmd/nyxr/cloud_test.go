package main

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/storage"
)

type stubConnector struct{ inv storage.CloudInventory }

func (s stubConnector) Provider() string { return s.inv.Provider }
func (s stubConnector) Scope() string    { return s.inv.Scope }
func (s stubConnector) Collect(context.Context) (storage.CloudInventory, error) {
	return s.inv, nil
}

func TestCloudCollectionRefusesPartialInventoryUnlessAllowed(t *testing.T) {
	store, err := storage.Open(t.Context(), filepath.Join(t.TempDir(), "nyxr.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	partial := stubConnector{storage.CloudInventory{Provider: "gcp", Scope: "nyxr-lab-01", Collector: "stub",
		Notes:   []string{"unreachable locations: zones/asia-east1-a"},
		Records: []storage.CloudRecord{{Address: netip.MustParseAddr("10.2.0.2"), AddressRole: "private", ResourceID: "1"}}}}
	if _, err := collectCloudInventory(t.Context(), store, partial, false); err == nil || !strings.Contains(err.Error(), "asia-east1-a") {
		t.Fatalf("partial inventory imported without opt-in: %v", err)
	}
	result, err := collectCloudInventory(t.Context(), store, partial, true)
	if err != nil || result.Inventory.Complete || result.Reconciliation.Status != "partial_not_compared" {
		t.Fatalf("opt-in partial import: %+v, %v", result, err)
	}
}

func TestHistoryValidatesCloudFlagsBeforeContactingProviders(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("tok"), 0600); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "nyxr.db")
	for name, args := range map[string][]string{
		"orphan scope":     {"--cloud-scope", "x"},
		"two sources":      {"--cloud-provider", "gcp", "--kube-api", "https://k8s.example"},
		"unknown provider": {"--cloud-provider", "oracle", "--cloud-scope", "x", "--cloud-credentials-file", token},
		"missing scope":    {"--cloud-provider", "gcp", "--cloud-credentials-file", token},
		"region on azure":  {"--cloud-provider", "azure", "--cloud-scope", "x", "--cloud-region", "eu", "--cloud-credentials-file", token},
		"missing creds":    {"--cloud-provider", "azure", "--cloud-scope", "x"},
		"bad gcp project":  {"--cloud-provider", "gcp", "--cloud-scope", "Not A Project", "--cloud-credentials-file", token},
	} {
		var out bytes.Buffer
		if err := run(append([]string{"history", "--db", db}, args...), &out); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
