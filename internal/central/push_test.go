package central

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/storage"
)

func TestPushFromScannerDatabase(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	src, err := storage.Open(ctx, filepath.Join(dir, "scanner.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if _, err := src.ImportExternalIdentifiers(ctx, []storage.ExternalIdentifier{
		{Address: netip.MustParseAddr("10.0.0.1"), Kind: "cloud.aws.instance_id", Scope: "123456789012", Value: "i-0abc"},
		{Address: netip.MustParseAddr("10.0.0.2"), Kind: "cloud.aws.instance_id", Scope: "123456789012", Value: "i-0abc"},
	}); err != nil {
		t.Fatal(err)
	}
	// A local scan whose capture is on this host, and one an agent ran.
	capture := bytes.Repeat([]byte{0x0a, 0x0d, 0x0d, 0x0a}, 64)
	sum := sha256.Sum256(capture)
	capturePath := filepath.Join(dir, "scan.pcapng")
	if err := os.WriteFile(capturePath, capture, 0o600); err != nil {
		t.Fatal(err)
	}
	local := observe.Scan{ID: "local-1", Profile: "default", Started: t0, Status: "running"}
	if err := src.BeginScan(ctx, local); err != nil {
		t.Fatal(err)
	}
	local.Status, local.Finished = "completed", t0.Add(time.Minute)
	local.Capture = &observe.CaptureStats{ArtifactID: "sha256:" + hex.EncodeToString(sum[:]), Path: capturePath, Bytes: int64(len(capture))}
	if err := src.FinishScan(ctx, local); err != nil {
		t.Fatal(err)
	}

	for name, dst := range testStores(t) {
		t.Run(name, func(t *testing.T) {
			res, err := Push(ctx, src, dst, PushOptions{UploadCaptures: true, BatchSize: 1})
			if err != nil {
				t.Fatal(err)
			}
			if res.Ingested.Observations != 2 || res.Uploaded != 1 || res.Pending != 0 || !res.Ingested.MembersApplied {
				t.Fatalf("first push: %+v", res)
			}
			again, err := Push(ctx, src, dst, PushOptions{UploadCaptures: true})
			if err != nil {
				t.Fatal(err)
			}
			if again.Ingested.Observations != 0 || again.Ingested.Duplicates != 0 || again.Uploaded != 0 || again.Ingested.MembersApplied {
				t.Fatalf("second push should start at the cursor: %+v", again)
			}
			ns, _ := src.Namespace(ctx)
			graph, err := src.IdentityGraph(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(graph) != 1 {
				t.Fatalf("local resolver should join both addresses: %d identities", len(graph))
			}
			entities, err := dst.Entities(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(entities) != 1 || len(entities[0].Nodes) != 1 || entities[0].Nodes[0].Key != graph[0].GlobalID ||
				entities[0].Nodes[0].Lineage != ns || len(entities[0].Nodes[0].Addresses) != 2 {
				t.Fatalf("central should reuse the local identity as its node: %+v", entities)
			}
			if entities[0].ID != "NYXC-000000000001" {
				t.Fatalf("replacing provisional nodes should not burn entity IDs: %s", entities[0].ID)
			}
			if len(entities[0].PortableIDs) != 1 || entities[0].PortableIDs[0] != graph[0].PortableIDs[0] {
				t.Fatalf("portable IDs differ from the local resolver: %v vs %v", entities[0].PortableIDs, graph[0].PortableIDs)
			}
			rc, a, err := dst.OpenArtifact(ctx, local.Capture.ArtifactID, Grant{Restricted: true})
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(rc)
			rc.Close()
			if !bytes.Equal(got, capture) || a.Kind != "pcapng" || a.ScanID != "local-1" || a.Access != AccessRestricted {
				t.Fatalf("capture artifact: %+v", a)
			}
		})
	}
}

func TestUploadDirResolvesPendingAgentCaptures(t *testing.T) {
	ctx := context.Background()
	s := testStores(t)["sqlite"]
	dir := t.TempDir()
	wanted := []byte("agent capture")
	sum := sha256.Sum256(wanted)
	id := "sha256:" + hex.EncodeToString(sum[:])
	for name, body := range map[string][]byte{"a.pcapng": wanted, "unrelated.pcapng": []byte("not referenced")} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Ingest(ctx, Batch{Lineage: lineageB, Kind: LineageController,
		Artifacts: []ArtifactRef{{ID: id, Kind: "pcapng", AgentID: "agent-1"}}}); err != nil {
		t.Fatal(err)
	}
	uploaded, scanned, err := UploadDir(ctx, s, dir, 0)
	if err != nil || uploaded != 1 || scanned != 2 {
		t.Fatalf("upload: %d of %d, %v", uploaded, scanned, err)
	}
	all, err := s.Artifacts(ctx, "", 0)
	if err != nil || len(all) != 1 || all[0].State != ArtifactAvailable {
		t.Fatalf("only the referenced capture may be uploaded: %+v %v", all, err)
	}
}

// fakeS3 checks what a real S3 checks that matters here: a SigV4
// Authorization header and a payload hash matching the body.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDTEST/") ||
		!strings.Contains(r.Header.Get("Authorization"), "x-amz-content-sha256") {
		http.Error(w, "unsigned", http.StatusForbidden)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Method {
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(body)
		if r.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(sum[:]) {
			http.Error(w, "XAmzContentSHA256Mismatch", http.StatusBadRequest)
			return
		}
		f.objects[r.URL.Path] = body
	case http.MethodGet:
		body, ok := f.objects[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	case http.MethodDelete:
		delete(f.objects, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}
}

func TestS3ObjectsRoundTrip(t *testing.T) {
	ctx := context.Background()
	fake := &fakeS3{objects: map[string][]byte{}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	objects, err := OpenObjects("s3://evidence/nyxr?region=eu-west-1&endpoint="+url.QueryEscape(srv.URL), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenObjects("s3://evidence?endpoint=http://example.com", ""); err == nil {
		t.Fatal("plaintext S3 to a remote host was accepted")
	}
	s, err := Open(ctx, filepath.Join(t.TempDir(), "c.db"), objects)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, err := s.PutArtifact(ctx, ArtifactRef{Kind: "horizon-report", Access: AccessInternal}, strings.NewReader("report"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fake.objects["/evidence/nyxr/"+a.ObjectKey]; !ok {
		t.Fatalf("object not stored at its path-style key: %v", fake.objects)
	}
	rc, _, err := s.OpenArtifact(ctx, a.ID, Grant{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || string(got) != "report" {
		t.Fatalf("read back %q: %v", got, err)
	}
	delete(fake.objects, "/evidence/nyxr/"+a.ObjectKey)
	if _, a, err := s.OpenArtifact(ctx, a.ID, Grant{}); err == nil || a.State != ArtifactMissing {
		t.Fatalf("vanished S3 object: %v %+v", err, a)
	}
}
