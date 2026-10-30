package storage

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

func traceFixture(t *testing.T, s *Store, scanID string, started time.Time) observe.Observation {
	t.Helper()
	o := serviceObs(started, 443, "https", "")
	o.Evidence[0].Started, o.Evidence[0].Duration = started, 10*time.Millisecond
	o.Evidence[1].Started, o.Evidence[1].Duration = started.Add(time.Second), 50*time.Millisecond
	o.ProbeUpdates = []observe.ProbeUpdate{{Probe: "banner", Outcome: "inconclusive", EvidenceStart: 0, EvidenceEnd: 1},
		{Probe: "tls", Outcome: "matched", EvidenceStart: 1, EvidenceEnd: 2}}
	storeScan(t, s, scanID, started, o)
	got, err := s.Observations(ctx, Filter{ScanID: scanID})
	if err != nil || len(got) != 1 {
		t.Fatalf("stored observation: %v %v", got, err)
	}
	return got[0]
}

func TestTraceLinksDecisionsExchangesAndPackets(t *testing.T) {
	s, _ := openTest(t)
	o := traceFixture(t, s, "traced", t0)

	trace, ok, err := s.Trace(ctx, o.ID)
	if err != nil || !ok {
		t.Fatalf("trace: %v %v", ok, err)
	}
	if trace.Schema != TraceSchema || len(trace.Exchanges) != 2 || !reflect.DeepEqual(trace.Exchanges[1].Decisions, []int{1}) ||
		*trace.Exchanges[1].Source != *o.Evidence[1].Source || !trace.Exchanges[1].Truncated || trace.Exchanges[1].Completeness != "partial" {
		t.Fatalf("exchanges: %+v", trace.Exchanges)
	}
	if trace.Capture.Status != "unavailable" || !strings.Contains(strings.Join(trace.Capture.Reasons, ";"), "no packets were indexed") {
		t.Fatalf("missing index not explicit: %+v", trace.Capture)
	}

	at := o.Evidence[1].Started
	if err := s.AddPacketEvidence(ctx, []observe.PacketEvidence{{ScanID: "traced", Target: host, Transport: "tcp", Port: 443, Capture: "scan.pcapng", Truncated: true,
		Packets: []observe.Packet{{ID: 7, Timestamp: at.Add(-time.Minute), Direction: "tx", Length: 60, Summary: "earlier flow"},
			{ID: 8, Timestamp: at.Add(5 * time.Millisecond), Direction: "tx", Length: 80, Summary: "request"},
			{ID: 9, Timestamp: at.Add(120 * time.Millisecond), Direction: "rx", Length: 90, Summary: "reply"}}}}); err != nil {
		t.Fatal(err)
	}
	scan := observe.Scan{ID: "traced", Status: "completed", Finished: t0.Add(time.Minute), Observations: 1,
		Capture: &observe.CaptureStats{Path: "/evidence/scan.pcapng", Written: 3, DroppedQueue: 2, BackendDrops: 1}}
	if err := s.FinishScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	trace, _, err = s.Trace(ctx, o.ID)
	if err != nil {
		t.Fatal(err)
	}
	reasons := strings.Join(trace.Capture.Reasons, ";")
	if trace.Capture.Status != "partial" || !trace.Capture.FlowTruncated || len(trace.Capture.Packets) != 3 ||
		!strings.Contains(reasons, "index retains") || !strings.Contains(reasons, "dropped 3 frames") || trace.Capture.Association != "time-window" {
		t.Fatalf("partial capture: %+v", trace.Capture)
	}
	if !reflect.DeepEqual(trace.Exchanges[1].Packets, []uint64{8, 9}) || len(trace.Exchanges[0].Packets) != 0 {
		t.Fatalf("time-window packets: %+v", trace.Exchanges)
	}

	if _, ok, err := s.ObservationByID(ctx, "store:other-namespace/1"); ok || err != nil {
		t.Fatalf("foreign ID resolved: %v %v", ok, err)
	}
	if _, _, err := s.ObservationByID(ctx, "stream:abc"); err == nil {
		t.Fatal("malformed ID accepted")
	}
	streamed := serviceObs(t0, 22, "ssh", "")
	streamed.ID = "streamed/3"
	storeScan(t, s, "streamed", t0, streamed)
	if got, ok, err := s.ObservationByID(ctx, "streamed/3"); err != nil || !ok || got.ID != "streamed/3" || got.Port != 22 {
		t.Fatalf("stream ID lookup: %+v %v %v", got, ok, err)
	}
	if _, ok, err := s.ObservationByID(ctx, "streamed/4"); ok || err != nil {
		t.Fatalf("missing stream ID resolved: %v %v", ok, err)
	}
}

func TestProbeRunsNeverChangeSourceEvidence(t *testing.T) {
	s, _ := openTest(t)
	o := traceFixture(t, s, "source", t0)
	ref := *o.Evidence[1].Source
	offline := observe.ProbeRun{Schema: observe.ProbeRunSchema, ID: "run-offline", Mode: observe.ProbeRunOffline, CreatedAt: t0.Add(time.Hour),
		Source: ref, Status: observe.ProbeRunMatched, Target: host, Transport: "tcp", Port: 443,
		Result: observe.Observation{Kind: observe.KindProbeReplay, Target: host, Transport: "tcp", Port: 443, State: "offline"}}
	if err := s.AddProbeRun(ctx, &offline, o.ScanID, []byte("schema: x")); err != nil || offline.ScanID != "" {
		t.Fatalf("offline run: %+v %v", offline, err)
	}
	live := offline
	live.ID, live.Mode, live.Status, live.CreatedAt = "run-live", observe.ProbeRunLive, observe.ProbeRunFailed, t0.Add(90*time.Minute)
	live.Error, live.Result.State, live.Result.Timestamp = "connection refused", "error", t0.Add(time.Hour)
	live.Result.Service = "clone-http"
	if err := s.AddProbeRun(ctx, &live, o.ScanID, []byte("schema: x")); err != nil || live.ScanID != "run-live" || live.Result.Source == nil {
		t.Fatalf("live run: %+v %v", live, err)
	}
	scan, ok, err := s.Scan(ctx, "run-live")
	if err != nil || !ok || scan.Profile != "probe-replay" || scan.Status != "completed" || scan.Error != "connection refused" {
		t.Fatalf("live scan: %+v %v %v", scan, ok, err)
	}
	after, _, err := s.ObservationByID(ctx, o.ID)
	if err != nil || !reflect.DeepEqual(after, o) {
		t.Fatalf("source observation changed: %v", err)
	}
	services, err := s.Observations(ctx, Filter{Kind: observe.KindService})
	if err != nil || len(services) != 1 || services[0].ID != o.ID {
		t.Fatalf("a replay became a service claim: %+v %v", services, err)
	}
	trace, _, err := s.Trace(ctx, o.ID)
	if err != nil || len(trace.Runs) != 2 || trace.Runs[0].ID != "run-offline" || trace.Runs[1].ScanID != "run-live" {
		t.Fatalf("runs: %+v %v", trace.Runs, err)
	}
	// Pruning the source removes its offline runs; the live run keeps its own scan.
	if _, err := s.Prune(ctx, Retention{KeepLast: 1}, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	runs, err := s.ProbeRuns(ctx, ref.ArtifactID)
	if err != nil || len(runs) != 1 || runs[0].ID != "run-live" {
		t.Fatalf("after pruning the source: %+v %v", runs, err)
	}
}
