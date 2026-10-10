// Package horizon runs opt-in bounded experiments on Nyxr's packet transport.
package horizon

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
)

type Link struct {
	SourceIP              netip.Addr
	SourceMAC, NextHopMAC net.HardwareAddr
	Build, Backend        string
}

// Options are fixed on the wire: both arms offer MSS 1460; only treatment
// additionally offers SACK permission. No timestamps, ECN or arbitrary bytes.
func options(arm string) []byte {
	if arm == "treatment" {
		return []byte{2, 4, 5, 180, 4, 2, 0, 0}
	}
	return []byte{2, 4, 5, 180}
}

type runner struct {
	io       packetio.PacketIO
	link     Link
	plan     model.Plan
	report   *model.Report
	nextSend time.Time
}

// Run recompiles at the execution boundary with independent authorization.
// The caller owns/ closes io. An error returns partial evidence for export.
func Run(ctx context.Context, e model.Experiment, policy model.Policy, link Link, io packetio.PacketIO) (report model.Report, runErr error) {
	p, err := dsl.Compile(e, policy)
	if err != nil {
		return report, err
	}
	if io == nil {
		return report, errors.New("packet transport is required")
	}
	target := netip.MustParseAddr(e.Spec.Scope.Targets[0])
	if !link.SourceIP.IsGlobalUnicast() || link.SourceIP.Is4In6() || link.SourceIP.Zone() != "" || link.SourceIP.Is4() != target.Is4() || link.SourceIP == target {
		return report, errors.New("source must be a distinct unicast IP of the target family")
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return report, err
	}
	report = model.Report{APIVersion: p.APIVersion, Kind: "EvidenceReport", Experiment: p.Experiment, ExperimentHash: p.Hash,
		RunID: hex.EncodeToString(nonce[:]), Build: link.Build, Backend: link.Backend, StartedAt: time.Now().UTC(),
		Limitations: []string{"Synthetic backends validate software only; live ground truth remains unvalidated.", "SACK is the sole pre-registered metric; RTT/TTL/options and response classes are descriptive.", "Paired sign test assumes independent, stationary pairs; it does not establish causality or topology.", "User-space send/receive timestamps include queueing; clock precision and transport checksums are not calibrated.", "Fresh TCP sequence and IP ID tokens differ between probes; ambient load, routing and reused flow state may confound results.", "Only direct TCP replies are classified; ICMP/NAT/path-shift replies remain unresolved.", "SHA-256 detects corruption, not forgery; this report is not digitally signed.", "RST cleanup is best effort; cancellation/error may leave remote SYN state to expire."}}
	before := io.Stats().Dropped
	defer func() {
		report.FinishedAt = time.Now().UTC()
		after := io.Stats().Dropped
		if after >= before {
			report.BackendDrops = after - before
		}
		if runErr != nil {
			report.StopReason = runErr.Error()
		}
		report.Comparison = Compare(report)
	}()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(e.Spec.Limits.MaxDurationSeconds)*time.Second)
	defer cancel()
	r := runner{io: io, link: link, plan: p, report: &report}
	baseToken := binary.BigEndian.Uint32(nonce[:4])
	basePort := int(binary.BigEndian.Uint16(nonce[4:6]))
	for i, trial := range p.Trials {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if err := pause(ctx, time.Duration(trial.WaitBeforeMS)*time.Millisecond); err != nil {
			return report, err
		}
		slot := trial.Pair
		if e.APIVersion == model.GeneralVersion {
			slot = trial.Pair*32 + trial.Probe
		}
		arm := "control"
		if trial.Send.OptionsProfile == "sack-permitted" {
			arm = "treatment"
		}
		sent := packet.ForgeSpec{SourceIP: link.SourceIP, DestinationIP: target, SourceMAC: link.SourceMAC, DestinationMAC: link.NextHopMAC,
			Protocol: 6, SourcePort: uint16(49152 + (basePort+slot)%16384), DestPort: trial.Send.DstPort, TCPFlags: 2,
			TCPOptions: options(arm), Sequence: baseToken + uint32(i), Window: 64240, HopLimit: 64, ID: baseToken + uint32(i), DontFragment: true, Experiment: true}
		t := model.Trial{Probe: trial.Probe, Pair: trial.Pair, Arm: trial.Arm, FlowID: flowID(sent), Features: model.Features{ResponseClass: "no-response"}, QualityFlags: []string{}, Evidence: []model.Evidence{}}
		err := r.trial(ctx, sent, &t, trial.WindowMS)
		report.Trials = append(report.Trials, t)
		if err != nil {
			return report, err
		}
		if err := pause(ctx, time.Duration(trial.WaitAfterMS)*time.Millisecond); err != nil {
			return report, err
		}
		endArm := i+1 == len(p.Trials) || p.Trials[i+1].Arm != trial.Arm || p.Trials[i+1].Pair != trial.Pair
		if endArm {
			if err := pause(ctx, time.Duration(e.Spec.Execution.WashoutMS)*time.Millisecond); err != nil {
				return report, err
			}
		}
	}
	report.Completed = true
	return report, nil
}

func flowID(s packet.ForgeSpec) string {
	return fmt.Sprintf("%s:%d>%s:%d/%08x", s.SourceIP, s.SourcePort, s.DestinationIP, s.DestPort, s.Sequence)
}

func pause(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if duration <= 0 {
		return nil
	}
	t := time.NewTimer(duration)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return ctx.Err()
	}
}

func (r *runner) evidence(t *model.Trial, direction string, ts time.Time, frame []byte) error {
	if len(frame) > 2048 || r.report.CaptureBytes+len(frame) > r.plan.Experiment.Spec.Capture.MaxBytes {
		t.QualityFlags = append(t.QualityFlags, "capture-limit")
		return errors.New("evidence capture budget exhausted")
	}
	r.report.CaptureBytes += len(frame)
	t.Evidence = append(t.Evidence, model.Evidence{Direction: direction, Timestamp: ts.UTC(), Frame: append([]byte(nil), frame...)})
	return nil
}

func (r *runner) send(ctx context.Context, s packet.ForgeSpec, t *model.Trial, direction string) error {
	frames, err := packet.ForgeFrames(s)
	if err != nil {
		return err
	}
	frame := frames[0]
	if len(frames) != 1 || r.report.PacketsTX >= r.plan.MaxPackets {
		return errors.New("transmission budget exhausted")
	}
	// Reserve capture before transmission so no successfully sent probe is
	// silently missing from the report, even on an exhausted capture budget.
	if r.report.CaptureBytes+len(frame) > r.plan.Experiment.Spec.Capture.MaxBytes {
		return errors.New("evidence capture budget exhausted before send")
	}
	if err := pause(ctx, time.Until(r.nextSend)); err != nil {
		return err
	}
	ts := time.Now()
	n, err := r.io.SendBatch(ctx, [][]byte{frame})
	if n > 0 {
		r.report.PacketsTX += n
		if direction == "tx" {
			t.SentAt = ts.UTC()
		}
		if captureErr := r.evidence(t, direction, ts, frame); captureErr != nil {
			return captureErr
		}
	}
	r.nextSend = time.Now().Add(time.Second / time.Duration(r.plan.Experiment.Spec.Limits.PacketsPerSecond))
	if err != nil || n != 1 {
		return fmt.Errorf("packet send %d/1: %w", n, errors.Join(err, errors.New("send failed or partial")))
	}
	if direction == "tx" {
		t.SentAt = ts.UTC()
	}
	return nil
}

func (r *runner) trial(ctx context.Context, sent packet.ForgeSpec, t *model.Trial, windowMS int) error {
	if err := r.send(ctx, sent, t, "tx"); err != nil {
		return err
	}
	window, cancel := context.WithTimeout(ctx, time.Duration(windowMS)*time.Millisecond)
	defer cancel()
	decoder := packet.NewDecoder()
	buffer := make([]byte, 65535)
	matched, received := 0, 0
	receiveLimit := 4096
	if limit := r.plan.Experiment.Spec.Limits.MaxReceiveFrames; limit != 0 {
		receiveLimit = limit
	}
	var cleanup *packet.ForgeSpec
	for window.Err() == nil {
		batch := [][]byte{buffer}
		n, err := r.io.ReceiveBatch(window, batch)
		if n < 0 || n > 1 {
			return errors.New("invalid receive batch count")
		}
		if n == 1 {
			received++
			if received > receiveLimit {
				t.QualityFlags = append(t.QualityFlags, "receive-limit")
				return errors.New("receive work budget exhausted")
			}
			if window.Err() == nil {
				features, ok := correlate(batch[0], sent, decoder)
				if ok {
					now := time.Now()
					if err := r.evidence(t, "rx", now, batch[0]); err != nil {
						return err
					}
					matched++
					if matched > 16 {
						t.QualityFlags = append(t.QualityFlags, "duplicate-limit")
						return errors.New("correlated receive budget exhausted")
					}
					if matched == 1 {
						features.RTTNS = now.Sub(t.SentAt).Nanoseconds()
						t.Features = features
						if features.ResponseClass == "syn-ack" {
							s := sent
							s.TCPFlags, s.Sequence, s.TCPOptions = 4, sent.Sequence+1, nil
							cleanup = &s
							// Cleanup spacing must not shorten the receive window.
						}
					} else {
						t.QualityFlags = appendUnique(t.QualityFlags, "duplicate-response")
					}
				}
			}
		}
		if err != nil {
			// Only the receive window's own cancellation is a normal stop.
			// A backend failure can race its deadline and must still fail closed.
			if window.Err() != nil && errors.Is(err, window.Err()) {
				break
			}
			t.QualityFlags = appendUnique(t.QualityFlags, "receive-failed")
			return fmt.Errorf("receive packet: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		t.QualityFlags = append(t.QualityFlags, "cancelled")
		return err
	}
	if cleanup != nil {
		if err := r.send(ctx, *cleanup, t, "cleanup"); err != nil {
			t.QualityFlags = append(t.QualityFlags, "cleanup-failed")
			return err
		}
	}
	if matched == 0 {
		t.QualityFlags = append(t.QualityFlags, "timeout")
	}
	return nil
}

func appendUnique(flags []string, flag string) []string {
	for _, f := range flags {
		if f == flag {
			return flags
		}
	}
	return append(flags, flag)
}

func correlate(frame []byte, sent packet.ForgeSpec, decoder *packet.Decoder) (model.Features, bool) {
	var f model.Features
	// DecodeResearch validates IP lengths/IPv4 checksums and rejects fragments;
	// Decoder then supplies the existing zero-copy TCP/TTL/options parsing.
	raw, ok := packet.DecodeResearch(frame)
	if !ok || raw.Protocol != 6 {
		return f, false
	}
	p, ok := decoder.Decode(frame)
	if !ok || p.Protocol != "tcp" || p.Source != sent.DestinationIP || p.Destination != sent.SourceIP || p.SourcePort != sent.DestPort || p.DestPort != sent.SourcePort || p.TCPAck != sent.Sequence+1 {
		return f, false
	}
	switch p.TCPFlags {
	case 0x12, 0x52:
		f.ResponseClass = "syn-ack"
	case 0x14:
		f.ResponseClass = "rst-ack"
	default:
		return f, false
	}
	if !validOptions(p.TCPOptions[:p.TCPOptionsLen]) {
		return f, false
	}
	f.TTL, f.TCPOptions = p.TTL, append([]byte(nil), p.TCPOptions[:p.TCPOptionsLen]...)
	return f, true
}

func validOptions(b []byte) bool {
	for i := 0; i < len(b); {
		switch b[i] {
		case 0:
			return true
		case 1:
			i++
		default:
			if i+2 > len(b) || b[i+1] < 2 || i+int(b[i+1]) > len(b) || (b[i] == 4 && b[i+1] != 2) {
				return false
			}
			i += int(b[i+1])
		}
	}
	return true
}
