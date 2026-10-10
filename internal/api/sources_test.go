package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/storage"
)

func TestEvidenceReferenceAPIAndPruning(t *testing.T) {
	e := newEnv(t, ManagerConfig{}, testToken)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := e.store.BeginScan(ctx, observe.Scan{ID: "source-test", Profile: "test", Started: now.Add(-time.Hour), Status: "completed"}); err != nil {
		t.Fatal(err)
	}
	o := observe.Observation{ID: "source-test/1", Timestamp: now, Target: netip.MustParseAddr("192.0.2.1"), Kind: observe.KindService, Fingerprint: observe.FingerprintUnknown, Evidence: []observe.Evidence{{Probe: "banner", Layer: "tcp", Response: []byte{0, 255}}}}
	o.Stamp("source-test")
	if err := e.store.AddObservations(ctx, []observe.Observation{o}); err != nil {
		t.Fatal(err)
	}
	res, body := e.do(t, "GET", "/api/v1/scans/source-test/observations", "")
	var obs []observe.Observation
	if res.StatusCode != http.StatusOK || json.Unmarshal(body, &obs) != nil || len(obs) != 1 {
		t.Fatalf("observations: %s", body)
	}
	ref := *obs[0].Evidence[0].Source
	request, _ := json.Marshal(ref)
	res, body = e.do(t, "POST", "/api/v1/evidence/resolve", string(request))
	var result storage.SourceResult
	if res.StatusCode != http.StatusOK || json.Unmarshal(body, &result) != nil || result.Status != "available" {
		t.Fatalf("resolve: %d %s", res.StatusCode, body)
	}
	if _, err := observe.ResolveSource(result.Artifact, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Prune(ctx, storage.Retention{OlderThan: time.Minute}, now); err != nil {
		t.Fatal(err)
	}
	res, body = e.do(t, "POST", "/api/v1/evidence/resolve", string(request))
	if res.StatusCode != http.StatusOK || json.Unmarshal(body, &result) != nil || result.Status != "unavailable" || result.Reason == "" || result.Reference != ref {
		t.Fatalf("pruned: %d %s", res.StatusCode, body)
	}
	if res, _ := e.do(t, "POST", "/api/v1/evidence/resolve", string(request)+`{}`); res.StatusCode != http.StatusBadRequest {
		t.Fatal("trailing reference accepted")
	}
}

func TestCaptureDownloadChecksRetainedContainer(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, ManagerConfig{EvidenceDir: dir}, testToken)
	ctx := context.Background()
	b := []byte("capture bytes")
	path := filepath.Join(dir, "source.pcapng")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	sc := observe.Scan{ID: "capture-source", Profile: "test", Started: time.Now().UTC(), Status: "completed", Capture: &observe.CaptureStats{Path: path, Bytes: int64(len(b)), ArtifactID: observe.ArtifactID(b)}}
	if err := e.store.BeginScan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	if err := e.store.FinishScan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	res, body := e.do(t, "GET", "/api/v1/scans/capture-source/pcapng", "")
	if res.StatusCode != http.StatusOK || string(body) != string(b) {
		t.Fatalf("capture download: %d %s", res.StatusCode, body)
	}
	if err := os.WriteFile(path, []byte("changed bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	res, body = e.do(t, "GET", "/api/v1/scans/capture-source/pcapng", "")
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("changed container downloaded: %d %s", res.StatusCode, body)
	}
}
