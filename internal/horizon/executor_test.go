package horizon

import (
	"context"
	"errors"
	"testing"

	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
)

type executorIO struct {
	packetio.PacketIO
	send    func(context.Context, [][]byte) (int, error)
	receive func(context.Context, [][]byte) (int, error)
	stats   func() packetio.Stats
}

func (e executorIO) Stats() packetio.Stats {
	if e.stats != nil {
		return e.stats()
	}
	return e.PacketIO.Stats()
}

func (e executorIO) SendBatch(ctx context.Context, frames [][]byte) (int, error) {
	if e.send != nil {
		return e.send(ctx, frames)
	}
	return e.PacketIO.SendBatch(ctx, frames)
}

func (e executorIO) ReceiveBatch(ctx context.Context, buffers [][]byte) (int, error) {
	if e.receive != nil {
		return e.receive(ctx, buffers)
	}
	return e.PacketIO.ReceiveBatch(ctx, buffers)
}

func TestReceiveFailuresStopTransmission(t *testing.T) {
	failure := errors.New("injected capture failure")
	for _, mode := range []string{"immediate", "after-window", "with-reply"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			sim, _ := NewSimulator("sack")
			defer sim.Close()
			io := executorIO{PacketIO: sim, receive: func(ctx context.Context, buffers [][]byte) (int, error) {
				switch mode {
				case "after-window":
					<-ctx.Done()
				case "with-reply":
					n, err := sim.ReceiveBatch(ctx, buffers)
					if err != nil {
						t.Fatal(err)
					}
					return n, failure
				}
				return 0, failure
			}}
			r, err := Run(context.Background(), testExperiment(t), testPolicy(), testLink(), io)
			if !errors.Is(err, failure) || r.Completed || r.PacketsTX != 1 || len(r.Trials) != 1 || r.Comparison.Status != "unresolved" {
				t.Fatalf("receive failure did not stop execution: tx=%d trials=%d completed=%v err=%v", r.PacketsTX, len(r.Trials), r.Completed, err)
			}
			if !hasFlag(r.Trials[0].QualityFlags, "receive-failed") {
				t.Fatal("capture failure quality flag missing")
			}
			if mode == "with-reply" && len(r.Trials[0].Evidence) != 2 {
				t.Fatal("reply returned alongside error was not retained")
			}
			roundTrip(t, r)
		})
	}
}

func TestReceiveWorkAndDuplicateLimits(t *testing.T) {
	for _, mode := range []string{"unrelated", "duplicates"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			sim, _ := NewSimulator("sack")
			defer sim.Close()
			var reply []byte
			received := 0
			io := executorIO{PacketIO: sim, receive: func(ctx context.Context, buffers [][]byte) (int, error) {
				received++
				if mode == "unrelated" {
					buffers[0] = buffers[0][:0]
					return 1, nil
				}
				if reply == nil {
					n, err := sim.ReceiveBatch(ctx, buffers)
					reply = append([]byte(nil), buffers[0]...)
					return n, err
				}
				buffers[0] = buffers[0][:copy(buffers[0], reply)]
				return 1, nil
			}}
			e := testExperiment(t)
			e.Spec.Control.Steps[1].Observe.WindowMS = 1000
			e.Spec.Treatment.Steps[1].Observe.WindowMS = 1000
			e.Spec.Limits.MaxDurationSeconds = 30
			r, err := Run(context.Background(), e, testPolicy(), testLink(), io)
			if err == nil || r.Completed || r.PacketsTX != 1 || len(r.Trials) != 1 || r.Comparison.Status != "unresolved" {
				t.Fatalf("receive limit did not fail closed: %+v %v", r, err)
			}
			trial := r.Trials[0]
			if mode == "unrelated" {
				if received != 4097 || !hasFlag(trial.QualityFlags, "receive-limit") || len(trial.Evidence) != 1 {
					t.Fatal("unrelated frame work was not bounded")
				}
			} else if received != 17 || len(trial.Evidence) != 18 || !hasFlag(trial.QualityFlags, "duplicate-limit") || !hasFlag(trial.QualityFlags, "duplicate-response") {
				t.Fatal("duplicate cap or triggering evidence missing")
			}
			roundTrip(t, r)
		})
	}
}

func TestCleanupFailurePreservesSendAccounting(t *testing.T) {
	failure := errors.New("injected cleanup failure")
	for _, sentCleanup := range []bool{false, true} {
		t.Run(map[bool]string{false: "unsent", true: "sent-with-error"}[sentCleanup], func(t *testing.T) {
			t.Parallel()
			sim, _ := NewSimulator("sack")
			defer sim.Close()
			calls := 0
			io := executorIO{PacketIO: sim, send: func(ctx context.Context, frames [][]byte) (int, error) {
				calls++
				if calls == 1 {
					return sim.SendBatch(ctx, frames)
				}
				if sentCleanup {
					n, err := sim.SendBatch(ctx, frames)
					return n, errors.Join(err, failure)
				}
				return 0, failure
			}}
			r, err := Run(context.Background(), testExperiment(t), testPolicy(), testLink(), io)
			wantTX, wantEvidence := 1, 2
			if sentCleanup {
				wantTX, wantEvidence = 2, 3
			}
			if !errors.Is(err, failure) || r.Completed || calls != 2 || len(r.Trials) != 1 || r.PacketsTX != wantTX || len(r.Trials[0].Evidence) != wantEvidence || !hasFlag(r.Trials[0].QualityFlags, "cleanup-failed") {
				t.Fatalf("cleanup failure/accounting hidden: %+v %v", r, err)
			}
			roundTrip(t, r)
		})
	}
}

func TestCancellationAfterReplyStopsCleanup(t *testing.T) {
	sim, _ := NewSimulator("sack")
	defer sim.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	received := false
	io := executorIO{PacketIO: sim, receive: func(window context.Context, buffers [][]byte) (int, error) {
		if received {
			cancel()
			<-window.Done()
			return 0, window.Err()
		}
		received = true
		return sim.ReceiveBatch(window, buffers)
	}}
	r, err := Run(ctx, testExperiment(t), testPolicy(), testLink(), io)
	if !errors.Is(err, context.Canceled) || r.Completed || r.PacketsTX != 1 || len(r.Trials) != 1 || len(r.Trials[0].Evidence) != 2 || !hasFlag(r.Trials[0].QualityFlags, "cancelled") {
		t.Fatalf("cancellation after reply transmitted cleanup: %+v %v", r, err)
	}
	roundTrip(t, r)
}

func TestSeedReproducesOrderWithFreshRunTokensAndDropAccounting(t *testing.T) {
	e := testExperiment(t)
	e.Spec.Execution.Replicates = 2
	e.Spec.Limits.MaxPackets = 8
	var previousRunID string
	var previousSequence uint32
	for run := 0; run < 2; run++ {
		sim, _ := NewSimulator("sack")
		defer sim.Close()
		// The transport was already in use: exclude its seven earlier drops.
		drops := uint64(7)
		io := executorIO{PacketIO: sim,
			send: func(ctx context.Context, frames [][]byte) (int, error) {
				drops++
				return sim.SendBatch(ctx, frames)
			},
			stats: func() packetio.Stats {
				s := sim.Stats()
				s.Dropped = drops
				return s
			},
		}
		r, err := Run(context.Background(), e, testPolicy(), testLink(), io)
		if err != nil || !r.Completed || r.PacketsTX != 8 || r.BackendDrops != 8 || r.Comparison.Status != "unresolved" {
			t.Fatalf("run drop accounting failed: %+v %v", r, err)
		}
		plan, err := dsl.Compile(e, testPolicy())
		if err != nil {
			t.Fatal(err)
		}
		captureBytes := 0
		for i, trial := range r.Trials {
			if trial.Pair != plan.Trials[i].Pair || trial.Arm != plan.Trials[i].Arm {
				t.Fatal("seeded execution changed planned order")
			}
			for _, ev := range trial.Evidence {
				captureBytes += len(ev.Frame)
			}
		}
		if captureBytes != r.CaptureBytes {
			t.Fatal("raw capture byte accounting differs from retained evidence")
		}
		probe, ok := packet.NewDecoder().Decode(r.Trials[0].Evidence[0].Frame)
		if !ok || (run > 0 && (r.RunID == previousRunID || probe.TCPSeq == previousSequence)) {
			t.Fatal("seed reused run identity or flow token")
		}
		previousRunID, previousSequence = r.RunID, probe.TCPSeq
		roundTrip(t, r)
	}
}
