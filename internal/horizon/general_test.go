package horizon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
)

func sequenceExperiment(t *testing.T) model.Experiment {
	t.Helper()
	b, err := os.ReadFile("../../lab/horizon/sequence-v1alpha2.yaml")
	if err != nil {
		t.Fatal(err)
	}
	e, err := dsl.Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func sequencePolicy() model.Policy {
	return model.Policy{Profile: "lab", Permissions: []string{"cross-port"}, AllowTargets: []string{"192.0.2.0/24"}, AllowPorts: []uint16{443, 8443}}
}
func TestGeneralExecutionReplayAndCancellation(t *testing.T) {
	t.Parallel()
	e := sequenceExperiment(t)
	sim, _ := NewSimulator("sack")
	defer sim.Close()
	r, err := Run(context.Background(), e, sequencePolicy(), testLink(), sim)
	if err != nil || !r.Completed || r.PacketsTX != 24 || len(r.Trials) != 12 || r.Comparison.Status != "unresolved" {
		t.Fatalf("sequence execution: %+v %v", r, err)
	}
	sealed := roundTrip(t, r)
	blob, _ := json.Marshal(sealed)
	refs, err := ImportReferences(bytes.NewReader(blob))
	if err != nil || refs.Source.SourceSchema != model.GeneralVersion || refs.Trials[1].Probe != 1 {
		t.Fatal("sequence reference provenance", err)
	}
	if _, err := ResolveReference(blob, refs.Trials[1].Source); err != nil {
		t.Fatal(err)
	}
	refs.Trials[1].Source.SourceSchema = model.Version
	if _, err := ResolveReference(blob, refs.Trials[1].Source); err == nil {
		t.Fatal("reference schema mismatch accepted")
	}
	plan, err := dsl.Compile(e, sequencePolicy())
	if err != nil {
		t.Fatal(err)
	}
	var previous time.Time
	for i, trial := range r.Trials {
		if trial.Probe != plan.Trials[i].Probe {
			t.Fatal("lost probe index")
		}
		tx, ok := packet.NewDecoder().Decode(trial.Evidence[0].Frame)
		if !ok || tx.DestPort != plan.Trials[i].Send.DstPort {
			t.Fatal("executor ignored exact plan")
		}
		for _, ev := range trial.Evidence {
			if ev.Direction == "rx" {
				continue
			}
			if !previous.IsZero() && ev.Timestamp.Sub(previous) < 95*time.Millisecond {
				t.Fatal("SYN/cleanup rate gate bypassed")
			}
			previous = ev.Timestamp
		}
	}
	for _, mutate := range []func(*model.Report){
		func(r *model.Report) { r.Trials[1].Probe++ },
		func(r *model.Report) { r.Trials[0].Evidence[0].Frame[36] ^= 1 },
		func(r *model.Report) { r.PacketsTX-- },
	} {
		b, _ := json.Marshal(r)
		var altered model.Report
		json.Unmarshal(b, &altered)
		mutate(&altered)
		envelope, _ := Seal(altered)
		b, _ = json.Marshal(envelope)
		if _, err := Replay(bytes.NewReader(b)); err == nil {
			t.Fatal("resealed sequence tampering accepted")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	partial, err := Run(ctx, e, sequencePolicy(), testLink(), sim)
	if !errors.Is(err, context.DeadlineExceeded) || partial.Completed || partial.PacketsTX > 1 {
		t.Fatal("sequence deadline bypassed", err)
	}
	roundTrip(t, partial)
}
func TestGeneralReceiveAndCaptureBounds(t *testing.T) {
	for _, kind := range []string{"receive", "capture"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			e := sequenceExperiment(t)
			sim, _ := NewSimulator("noise")
			defer sim.Close()
			transport := packetio.PacketIO(sim)
			if kind == "receive" {
				e.Spec.Limits.MaxReceiveFrames = 1
				transport = executorIO{PacketIO: sim, receive: func(ctx context.Context, b [][]byte) (int, error) { b[0] = b[0][:0]; return 1, nil }}
			} else {
				e.Spec.Execution.Replicates = 16
				e.Spec.Limits.MaxPackets = 192
				e.Spec.Limits.MaxDurationSeconds = 60
				e.Spec.Capture.MaxBytes = 4096
			}
			r, err := Run(context.Background(), e, sequencePolicy(), testLink(), transport)
			if err == nil || r.Completed || r.CaptureBytes > e.Spec.Capture.MaxBytes || r.PacketsTX >= e.Spec.Limits.MaxPackets {
				t.Fatalf("%s bound: %+v %v", kind, r, err)
			}
			roundTrip(t, r)
		})
	}
}
func TestControllerKillSwitchConcurrencyAndPolicy(t *testing.T) {
	var opened atomic.Int32
	received := make(chan struct{})
	var receiveStarted sync.Once
	sim, _ := NewSimulator("loss")
	controller := NewController(sequencePolicy(), testLink(), func() (packetio.PacketIO, error) {
		opened.Add(1)
		return executorIO{PacketIO: sim, receive: func(ctx context.Context, b [][]byte) (int, error) {
			receiveStarted.Do(func() { close(received) })
			<-ctx.Done()
			return 0, ctx.Err()
		}}, nil
	})
	defer controller.Close()
	e := sequenceExperiment(t)
	unauthorized := e
	unauthorized.Spec.Scope.Targets = []string{"198.51.100.10"}
	if _, err := controller.Run(context.Background(), unauthorized); err == nil || opened.Load() != 0 {
		t.Fatal("opened unauthorized backend")
	}
	done := make(chan model.Report, 1)
	go func() { r, _ := controller.Run(context.Background(), e); done <- r }()
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not start")
	}
	if _, err := controller.Run(context.Background(), e); !errors.Is(err, ErrBusy) || opened.Load() != 1 {
		t.Fatal("concurrency cap bypassed", err)
	}
	controller.Stop()
	controller.Stop()
	select {
	case r := <-done:
		if r.Completed || r.PacketsTX != 1 || r.StopReason == "" {
			t.Fatal("kill switch lost partial report")
		}
		roundTrip(t, r)
	case <-time.After(time.Second):
		t.Fatal("kill switch did not cancel receive")
	}
	if _, err := controller.Plan(e); !errors.Is(err, ErrStopped) {
		t.Fatal("stopped executor accepted plan", err)
	}
	if _, err := controller.Run(context.Background(), e); !errors.Is(err, ErrStopped) || opened.Load() != 1 {
		t.Fatal("stopped executor opened backend", err)
	}
}

func TestGeneralIPv6AndWaitCancellation(t *testing.T) {
	t.Parallel()
	e := sequenceExperiment(t)
	e.Spec.Scope.Targets = []string{"2001:db8::10"}
	p := sequencePolicy()
	p.AllowTargets = []string{"2001:db8::/64"}
	link := testLink()
	link.SourceIP = netip.MustParseAddr("2001:db8::1")
	sim, _ := NewSimulator("sack")
	defer sim.Close()
	r, err := Run(context.Background(), e, p, link, sim)
	if err != nil || !r.Completed || r.PacketsTX != 24 {
		t.Fatal("IPv6 sequence", err)
	}
	roundTrip(t, r)
	e.Spec.ChangedVariable = "sequence"
	e.Spec.Control.Steps = append([]model.Step{{Wait: &model.Wait{DurationMS: 5000}}}, e.Spec.Control.Steps...)
	e.Spec.Treatment.Steps = append([]model.Step{{Wait: &model.Wait{DurationMS: 5000}}}, e.Spec.Treatment.Steps...)
	e.Spec.Limits.MaxDurationSeconds = 60
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	r, err = Run(ctx, e, p, link, sim)
	if !errors.Is(err, context.DeadlineExceeded) || r.PacketsTX != 0 || len(r.Trials) != 0 {
		t.Fatal("wait cancellation sent traffic", err)
	}
	roundTrip(t, r)
}
