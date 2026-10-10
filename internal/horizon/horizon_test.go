package horizon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
)

func testExperiment(t *testing.T) model.Experiment {
	t.Helper()
	b, err := os.ReadFile("../../lab/horizon/hz-001.yaml")
	if err != nil {
		t.Fatal(err)
	}
	e, err := dsl.Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	e.Spec.Execution.Replicates = 8
	e.Spec.Execution.WashoutMS = 0
	e.Spec.Limits.PacketsPerSecond = 10
	e.Spec.Limits.MaxPackets = 32
	e.Spec.Limits.MaxDurationSeconds = 10
	e.Spec.Control.Steps[1].Observe.WindowMS = 10
	e.Spec.Treatment.Steps[1].Observe.WindowMS = 10
	return e
}
func testPolicy() model.Policy {
	return model.Policy{AllowTargets: []string{"192.0.2.0/24"}, AllowPorts: []uint16{443}}
}
func testLink() Link {
	return Link{SourceIP: netip.MustParseAddr("192.0.2.1"), SourceMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, NextHopMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, Build: "test", Backend: "synthetic"}
}

func roundTrip(t *testing.T, r model.Report) model.Envelope {
	t.Helper()
	sealed, err := Seal(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := Replay(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(replayed.Report, r) {
		t.Fatal("replay changed observations")
	}
	return sealed
}

func TestSyntheticScenariosAndReplay(t *testing.T) {
	for _, scenario := range []string{"sack", "stable", "loss", "noise"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			sim, err := NewSimulator(scenario)
			if err != nil {
				t.Fatal(err)
			}
			defer sim.Close()
			r, err := Run(context.Background(), testExperiment(t), testPolicy(), testLink(), sim)
			if err != nil {
				t.Fatal(err)
			}
			if !r.Completed || len(r.Trials) != 16 || r.PacketsTX > 32 {
				t.Fatalf("bad execution %+v", r)
			}
			roundTrip(t, r)
			switch scenario {
			case "sack":
				if r.Comparison.Status != "inferred" || r.Comparison.TreatmentOnlySACK != 8 || r.Comparison.PValue != 0.0078125 || r.PacketsTX != 32 {
					t.Fatalf("injected effect not detected %+v", r.Comparison)
				}
			case "stable":
				if r.Comparison.Status != "inferred" || r.Comparison.PValue != 1 || r.Comparison.Conclusion != "no detectable difference in SACK permission" {
					t.Fatalf("null false positive %+v", r.Comparison)
				}
			case "loss", "noise":
				if r.Comparison.Status != "unresolved" {
					t.Fatalf("bad quality generated inference: %+v", r.Comparison)
				}
			}
			// Every SYN and cleanup uses the same rate gate, including across arms.
			var previous time.Time
			for _, trial := range r.Trials {
				for _, ev := range trial.Evidence {
					if ev.Direction == "rx" {
						continue
					}
					if !previous.IsZero() && ev.Timestamp.Sub(previous) < 95*time.Millisecond {
						t.Fatal("transmit rate exceeded")
					}
					previous = ev.Timestamp
				}
			}
		})
	}
}

func TestExecutionAdmissionAndCancellation(t *testing.T) {
	sim, _ := NewSimulator("sack")
	defer sim.Close()
	if _, err := Run(context.Background(), testExperiment(t), model.Policy{}, testLink(), sim); err == nil || sim.Stats().Sent != 0 {
		t.Fatal("execution bypassed scope")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := Run(ctx, testExperiment(t), testPolicy(), testLink(), sim)
	if !errors.Is(err, context.Canceled) || r.Completed || r.PacketsTX != 0 {
		t.Fatalf("cancelled execution sent: %v", err)
	}
	roundTrip(t, r)
	ctx, cancel = context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	r, err = Run(ctx, testExperiment(t), testPolicy(), testLink(), sim)
	if !errors.Is(err, context.DeadlineExceeded) || r.Completed || r.PacketsTX > 1 || r.Comparison.Status != "unresolved" {
		t.Fatalf("deadline failed: %v", err)
	}
	roundTrip(t, r)
}

func TestCaptureBudgetStopsExecution(t *testing.T) {
	sim, _ := NewSimulator("noise")
	defer sim.Close()
	e := testExperiment(t)
	e.Spec.Execution.Replicates = 50
	e.Spec.Limits.MaxPackets = 200
	e.Spec.Limits.MaxDurationSeconds = 30
	e.Spec.Capture.MaxBytes = 4096
	r, err := Run(context.Background(), e, testPolicy(), testLink(), sim)
	if err == nil || r.Completed || r.CaptureBytes > 4096 || r.PacketsTX >= 200 || r.Comparison.Status != "unresolved" {
		t.Fatalf("capture cap failed: bytes=%d tx=%d err=%v", r.CaptureBytes, r.PacketsTX, err)
	}
	roundTrip(t, r)
}

func TestReplayRejectsTamperingEvenAfterReseal(t *testing.T) {
	sim, _ := NewSimulator("sack")
	defer sim.Close()
	e := testExperiment(t)
	e.Spec.Execution.Replicates = 2
	e.Spec.Limits.MaxPackets = 8
	r, err := Run(context.Background(), e, testPolicy(), testLink(), sim)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*model.Report){
		"flow":              func(r *model.Report) { r.Trials[0].FlowID = "invented" },
		"token":             func(r *model.Report) { r.Trials[0].Evidence[1].Frame[42] ^= 1 },
		"scope":             func(r *model.Report) { r.Experiment.Spec.Scope.Targets[0] = "192.0.2.99" },
		"order":             func(r *model.Report) { r.Trials[0].Arm = "other" },
		"features":          func(r *model.Report) { r.Trials[0].Features.TTL++ },
		"accounting":        func(r *model.Report) { r.PacketsTX-- },
		"conclusion":        func(r *model.Report) { r.Comparison.Status = "observed" },
		"unknown direction": func(r *model.Report) { r.Trials[0].Evidence[1].Direction = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(r)
			var copyR model.Report
			_ = json.Unmarshal(b, &copyR)
			change(&copyR)
			envelope, _ := Seal(copyR)
			b, _ = json.Marshal(envelope)
			if _, err := Replay(bytes.NewReader(b)); err == nil {
				t.Fatal("forged structure accepted")
			}
		})
	}
	envelope, _ := Seal(r)
	envelope.SHA256 = "bad"
	b, _ := json.Marshal(envelope)
	if _, err := Replay(bytes.NewReader(b)); err == nil {
		t.Fatal("corruption accepted")
	}
}

func TestCorrelationRejectsUnrelatedAndTruncated(t *testing.T) {
	link := testLink()
	sent := packet.ForgeSpec{SourceMAC: link.SourceMAC, DestinationMAC: link.NextHopMAC, SourceIP: link.SourceIP, DestinationIP: netip.MustParseAddr("192.0.2.10"), Protocol: 6, SourcePort: 50000, DestPort: 443, TCPFlags: 2, Sequence: 42, Window: 64240, HopLimit: 64}
	frames, err := packet.ForgeFrames(sent)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := packet.NewDecoder().Decode(frames[0])
	if !ok {
		t.Fatal("decode")
	}
	reply, err := syntheticReply(frames[0], p, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := correlate(reply, sent, packet.NewDecoder()); !ok {
		t.Fatal("lost valid correlated reply")
	}
	for i := 0; i < len(reply); i++ {
		if _, ok := correlate(reply[:i], sent, packet.NewDecoder()); ok && i < 54 {
			t.Fatal("truncation accepted")
		}
	}
	for _, change := range []func(*packet.ForgeSpec){func(s *packet.ForgeSpec) { s.Sequence++ }, func(s *packet.ForgeSpec) { s.DestPort++ }, func(s *packet.ForgeSpec) { s.DestinationIP = netip.MustParseAddr("192.0.2.11") }, func(s *packet.ForgeSpec) { s.SourcePort++ }} {
		bad := sent
		change(&bad)
		if _, ok := correlate(reply, bad, packet.NewDecoder()); ok {
			t.Fatal("unrelated/stale reply matched")
		}
	}
}

type errorIO struct{ packetio.PacketIO }

func (e errorIO) SendBatch(context.Context, [][]byte) (int, error) {
	return 0, errors.New("injected send failure")
}
func TestSendFailureProducesPartialReplay(t *testing.T) {
	sim, _ := NewSimulator("sack")
	defer sim.Close()
	r, err := Run(context.Background(), testExperiment(t), testPolicy(), testLink(), errorIO{sim})
	if err == nil || r.Completed || r.PacketsTX != 0 {
		t.Fatal("send failure hidden")
	}
	roundTrip(t, r)
}

func TestPairedComparisonGates(t *testing.T) {
	r := model.Report{Completed: true}
	r.Experiment.Spec.Execution.Replicates = 8
	for i := 0; i < 8; i++ {
		r.Trials = append(r.Trials, model.Trial{Pair: i, Arm: "control", Features: model.Features{ResponseClass: "syn-ack"}}, model.Trial{Pair: i, Arm: "treatment", Features: model.Features{ResponseClass: "syn-ack", TCPOptions: []byte{4, 2}}})
	}
	if c := Compare(r); c.Status != "inferred" || c.PValue != 0.0078125 {
		t.Fatalf("exact test %+v", c)
	}
	r.BackendDrops = 1
	if Compare(r).Status != "unresolved" {
		t.Fatal("drop gate missing")
	}
	r.BackendDrops = 0
	r.Trials[0].QualityFlags = []string{"clock-instability"}
	if Compare(r).Status != "unresolved" {
		t.Fatal("quality gate missing")
	}
}

func TestIPv6ExecutionAndReplay(t *testing.T) {
	t.Parallel()
	e := testExperiment(t)
	e.Spec.Scope.Targets = []string{"2001:db8::10"}
	e.Spec.Execution.Replicates = 2
	e.Spec.Limits.MaxPackets = 8
	link := testLink()
	link.SourceIP = netip.MustParseAddr("2001:db8::1")
	sim, _ := NewSimulator("sack")
	defer sim.Close()
	r, err := Run(context.Background(), e, model.Policy{AllowTargets: []string{"2001:db8::/64"}, AllowPorts: []uint16{443}}, link, sim)
	if err != nil || !r.Completed || r.PacketsTX != 8 {
		t.Fatalf("IPv6 execution failed: %v", err)
	}
	roundTrip(t, r)
}

func FuzzCorrelation(f *testing.F) {
	sent := packet.ForgeSpec{SourceMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DestinationMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, SourceIP: netip.MustParseAddr("192.0.2.1"), DestinationIP: netip.MustParseAddr("192.0.2.10"), Protocol: 6, SourcePort: 50000, DestPort: 443, TCPFlags: 2, Sequence: 42, Window: 64240, HopLimit: 64}
	frames, err := packet.ForgeFrames(sent)
	if err != nil {
		f.Fatal(err)
	}
	p, _ := packet.NewDecoder().Decode(frames[0])
	reply, err := syntheticReply(frames[0], p, true)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(reply)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, frame []byte) {
		if len(frame) > 65535 {
			return
		}
		features, ok := correlateRich(frame, sent)
		if ok && !validOptions(features.TCPOptions) {
			t.Fatal("invalid options accepted")
		}
	})
}

func FuzzReplay(f *testing.F) {
	f.Add([]byte(`{"sha256":"bad","report":{}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		_, _ = Replay(bytes.NewReader(b))
	})
}
