package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/capture"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/storage"
)

func TestEvidenceTraceFramesCloneAndReplay(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, ManagerConfig{EvidenceDir: dir}, testToken)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	target := netip.MustParseAddr("192.0.2.9")

	var pcap bytes.Buffer
	w, err := capture.NewPCAPNGWriter(&pcap, "eth0", 65535, "test")
	if err != nil {
		t.Fatal(err)
	}
	request := bytes.Repeat([]byte{0xaa}, 60)
	if err := w.WritePacket(now, request, len(request), capture.DirectionTX, 1, ""); err != nil {
		t.Fatal(err)
	}
	if err := w.WritePacket(now.Add(time.Millisecond), bytes.Repeat([]byte{0xbb}, 60), 60, capture.DirectionRX, 2, ""); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "trace.pcapng")
	if err := os.WriteFile(path, pcap.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	sc := observe.Scan{ID: "trace-scan", Profile: "tcp-common", Started: now, Status: "running"}
	if err := e.store.BeginScan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	o := observe.Observation{Kind: observe.KindService, Timestamp: now, Target: target, Transport: "tcp", Port: 6379, State: "open",
		Service: "redis", Fingerprint: observe.FingerprintMatched, Confidence: 90,
		Evidence: []observe.Evidence{{Probe: "database/redis", Layer: "tcp", Started: now, Duration: 5 * time.Millisecond,
			Request: []byte("PING\r\n"), Response: []byte("+PONG\r\n"), Matched: "database"}}}
	o.Stamp(sc.ID)
	if err := e.store.AddObservations(ctx, []observe.Observation{o}); err != nil {
		t.Fatal(err)
	}
	if err := e.store.AddPacketEvidence(ctx, []observe.PacketEvidence{{ScanID: sc.ID, Target: target, Transport: "tcp", Port: 6379, Capture: path,
		Packets: []observe.Packet{{ID: 1, Timestamp: now, Direction: "tx", Length: 60, Summary: "request"},
			{ID: 2, Timestamp: now.Add(time.Millisecond), Direction: "rx", Length: 60, Summary: "reply"}}}}); err != nil {
		t.Fatal(err)
	}
	sc.Status, sc.Finished = "completed", now.Add(time.Second)
	sc.Capture = &observe.CaptureStats{Path: path, Bytes: int64(pcap.Len()), ArtifactID: observe.ArtifactID(pcap.Bytes()), Written: 2}
	if err := e.store.FinishScan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	stored, err := e.store.Observations(ctx, storage.Filter{ScanID: sc.ID})
	if err != nil || len(stored) != 1 {
		t.Fatal(err)
	}
	id := stored[0].ID

	res, body := e.do(t, "GET", "/api/v1/evidence/trace?observation="+id, "")
	var trace storage.EvidenceTrace
	if res.StatusCode != http.StatusOK || json.Unmarshal(body, &trace) != nil || trace.Capture.Status != "available" ||
		trace.Capture.Capture != "trace.pcapng" || len(trace.Exchanges[0].Packets) != 2 {
		t.Fatalf("trace: %d %s", res.StatusCode, body)
	}
	res, body = e.do(t, "GET", "/api/v1/scans/trace-scan/frames?ids=2,9", "")
	var frames struct {
		Frames []struct {
			ID        uint64 `json:"id"`
			Direction string `json:"direction"`
			Hex       string `json:"hex"`
		} `json:"frames"`
		Missing []uint64 `json:"missing"`
	}
	if res.StatusCode != http.StatusOK || json.Unmarshal(body, &frames) != nil || len(frames.Frames) != 1 ||
		frames.Frames[0].Hex != hex.EncodeToString(bytes.Repeat([]byte{0xbb}, 60)) || frames.Frames[0].Direction != "rx" || len(frames.Missing) != 1 {
		t.Fatalf("frames: %d %s", res.StatusCode, body)
	}
	if res, _ := e.do(t, "GET", "/api/v1/scans/trace-scan/frames?ids=x", ""); res.StatusCode != http.StatusBadRequest {
		t.Fatal("invalid frame IDs accepted")
	}

	res, body = e.do(t, "POST", "/api/v1/evidence/clone", `{"observation_id":"`+id+`","exchange":0}`)
	var draft map[string]string
	if res.StatusCode != http.StatusOK || json.Unmarshal(body, &draft) != nil || !strings.Contains(draft["definition"], "ports: [6379]") {
		t.Fatalf("clone: %d %s", res.StatusCode, body)
	}
	replay := func(mode string, dryRun bool, target string) (*http.Response, []byte) {
		request, _ := json.Marshal(map[string]any{"observation_id": id, "exchange": 0, "definition": draft["definition"],
			"mode": mode, "dry_run": dryRun, "target": target})
		return e.do(t, "POST", "/api/v1/probes/replay", string(request))
	}
	res, body = replay("offline", true, "")
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"connections":0`) {
		t.Fatalf("offline dry run: %d %s", res.StatusCode, body)
	}
	res, body = replay("offline", false, "")
	var run observe.ProbeRun
	if res.StatusCode != http.StatusCreated || json.Unmarshal(body, &run) != nil || run.Status != observe.ProbeRunMatched || !run.RequestMatchesEvidence || run.ScanID != "" {
		t.Fatalf("offline replay: %d %s", res.StatusCode, body)
	}
	if res, body := replay("live", false, "192.0.2.10"); res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("live resend to another target: %d %s", res.StatusCode, body)
	}
	if res, body := replay("live", true, target.String()); res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"connections":1`) {
		t.Fatalf("live dry run: %d %s", res.StatusCode, body)
	}
	if res, body := replay("live", false, target.String()); res.StatusCode != http.StatusForbidden {
		t.Fatalf("live resend without --allow-packet-send: %d %s", res.StatusCode, body)
	}
	res, body = e.do(t, "GET", "/api/v1/evidence/trace?observation="+id, "")
	if res.StatusCode != http.StatusOK || json.Unmarshal(body, &trace) != nil || len(trace.Runs) != 1 || trace.Runs[0].ID != run.ID {
		t.Fatalf("recorded runs: %s", body)
	}
	after, _, err := e.store.ObservationByID(ctx, id)
	if err != nil || len(after.Evidence) != 1 || !bytes.Equal(after.Evidence[0].Response, []byte("+PONG\r\n")) {
		t.Fatal("source evidence changed")
	}
	if res, _ := e.do(t, "GET", "/api/v1/evidence/trace?observation=store:elsewhere/1", ""); res.StatusCode != http.StatusNotFound {
		t.Fatal("foreign observation resolved")
	}
}
