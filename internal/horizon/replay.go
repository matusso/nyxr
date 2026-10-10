package horizon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/matusso/nyxr/internal/horizon/dsl"
	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/packet"
)

func Seal(report model.Report) (model.Envelope, error) {
	b, err := json.Marshal(report)
	if err != nil {
		return model.Envelope{}, err
	}
	h := sha256.Sum256(b)
	return model.Envelope{SHA256: hex.EncodeToString(h[:]), Report: report}, nil
}

// Replay never opens a transport. It validates structure and the raw TX/RX
// correlation, then recalculates features and the paired comparison.
func Replay(reader io.Reader) (model.Envelope, error) {
	b, err := io.ReadAll(io.LimitReader(reader, (24<<20)+1))
	if err != nil {
		return model.Envelope{}, err
	}
	if len(b) > 24<<20 {
		return model.Envelope{}, errors.New("report exceeds 24 MiB")
	}
	var envelope model.Envelope
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&envelope); err != nil {
		return envelope, err
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return envelope, errors.New("report has trailing data")
	}
	r := &envelope.Report
	sealed, err := Seal(*r)
	if err != nil || sealed.SHA256 != envelope.SHA256 {
		return envelope, errors.New("report integrity check failed")
	}
	if (r.APIVersion != model.Version && r.APIVersion != model.GeneralVersion) || r.APIVersion != r.Experiment.APIVersion || r.Kind != "EvidenceReport" {
		return envelope, errors.New("unsupported report version/kind")
	}
	// Scope here is an offline consistency check, not live authorization.
	p, err := dsl.Compile(r.Experiment, model.Policy{AllowTargets: r.Experiment.Spec.Scope.Targets, AllowPorts: r.Experiment.Spec.Scope.TCPPorts, Profile: "lab", Permissions: []string{"cross-port"}})
	if err != nil {
		return envelope, err
	}
	if r.ExperimentHash != p.Hash || len(r.Trials) > len(p.Trials) || (r.Completed && len(r.Trials) != len(p.Trials)) {
		return envelope, errors.New("experiment hash or trial count mismatch")
	}
	if r.Completed && r.StopReason != "" {
		return envelope, errors.New("completed report has a stop reason")
	}
	decoder := packet.NewDecoder()
	bytesCount, txCount := 0, 0
	seen := make(map[string]bool)
	var firstSent *packet.ForgeSpec
	for i := range r.Trials {
		t := &r.Trials[i]
		want := p.Trials[i]
		if t.Pair != want.Pair || t.Arm != want.Arm || t.Probe != want.Probe || len(t.Evidence) > 19 {
			return envelope, errors.New("trial order or evidence count mismatch")
		}
		// A failed first send may produce a final, empty partial trial.
		if len(t.Evidence) == 0 {
			if r.Completed || i != len(r.Trials)-1 || !t.SentAt.IsZero() || t.Features.ResponseClass != "no-response" {
				return envelope, errors.New("missing transmitted evidence")
			}
			continue
		}
		e := t.Evidence[0]
		s, ok := decoder.Decode(e.Frame)
		if !ok || e.Direction != "tx" || !e.Timestamp.Equal(t.SentAt) || s.Protocol != "tcp" || len(e.Frame) < 14 {
			return envelope, errors.New("invalid trial transmit evidence")
		}
		arm := "control"
		if want.Send.OptionsProfile == "sack-permitted" {
			arm = "treatment"
		}
		sent := packet.ForgeSpec{SourceMAC: e.Frame[6:12], DestinationMAC: e.Frame[:6], SourceIP: s.Source, DestinationIP: s.Destination, Protocol: 6, SourcePort: s.SourcePort, DestPort: s.DestPort, TCPFlags: 2, TCPOptions: options(arm), Sequence: s.TCPSeq, Window: 64240, HopLimit: 64, ID: s.TCPSeq, DontFragment: true, Experiment: true}
		if sent.DestinationIP.String() != r.Experiment.Spec.Scope.Targets[0] || sent.DestPort != want.Send.DstPort || sent.SourceIP == sent.DestinationIP || !sent.SourceIP.IsGlobalUnicast() || sent.SourceIP.Is4In6() {
			return envelope, errors.New("transmit evidence outside experiment scope")
		}
		frames, err := packet.ForgeFrames(sent)
		if err != nil || !bytes.Equal(frames[0], e.Frame) || flowID(sent) != t.FlowID || seen[t.FlowID] {
			return envelope, errors.New("transmit profile, flow ID or token mismatch")
		}
		seen[t.FlowID] = true
		if firstSent == nil {
			firstSent = &sent
		} else if sent.SourceIP != firstSent.SourceIP || !bytes.Equal(sent.SourceMAC, firstSent.SourceMAC) || !bytes.Equal(sent.DestinationMAC, firstSent.DestinationMAC) {
			return envelope, errors.New("source/link changed between arms")
		}
		slot := t.Pair
		if r.APIVersion == model.GeneralVersion {
			slot = t.Pair*32 + t.Probe
		}
		if firstSent.SourcePort < 49152 || sent.SourcePort != uint16(49152+(int(firstSent.SourcePort)-49152+slot)%16384) || sent.Sequence != firstSent.Sequence+uint32(i) {
			return envelope, errors.New("paired source port or sequence schedule mismatch")
		}
		features := model.Features{ResponseClass: "no-response"}
		rxCount, cleanupCount := 0, 0
		previous := e.Timestamp
		for j, e := range t.Evidence {
			if len(e.Frame) > 2048 || len(e.Frame) == 0 || e.Timestamp.Before(previous) {
				return envelope, errors.New("invalid frame size or evidence timestamp")
			}
			previous = e.Timestamp
			bytesCount += len(e.Frame)
			if bytesCount > r.Experiment.Spec.Capture.MaxBytes {
				return envelope, errors.New("capture budget exceeded")
			}
			switch e.Direction {
			case "tx":
				if j != 0 {
					return envelope, errors.New("extra SYN in trial")
				}
				txCount++
			case "rx":
				if cleanupCount > 0 {
					return envelope, errors.New("receive evidence after cleanup")
				}
				f, ok := correlate(e.Frame, sent, decoder)
				if !ok {
					return envelope, errors.New("receive evidence does not correlate to trial")
				}
				rxCount++
				if rxCount == 1 {
					f.RTTNS = e.Timestamp.Sub(t.SentAt).Nanoseconds()
					features = f
				}
			case "cleanup":
				if features.ResponseClass != "syn-ack" || cleanupCount != 0 {
					return envelope, errors.New("invalid cleanup evidence")
				}
				reset := sent
				reset.TCPFlags, reset.Sequence, reset.TCPOptions = 4, sent.Sequence+1, nil
				frames, err := packet.ForgeFrames(reset)
				if err != nil || !bytes.Equal(frames[0], e.Frame) {
					return envelope, errors.New("cleanup packet mismatch")
				}
				cleanupCount++
				txCount++
			default:
				return envelope, errors.New("unknown evidence direction")
			}
		}
		if !reflect.DeepEqual(features, t.Features) {
			return envelope, fmt.Errorf("derived features mismatch in trial %d", i)
		}
		if rxCount > 1 && !hasFlag(t.QualityFlags, "duplicate-response") {
			return envelope, errors.New("duplicate quality flag missing")
		}
		if rxCount == 0 && r.Completed && !hasFlag(t.QualityFlags, "timeout") {
			return envelope, errors.New("timeout quality flag missing")
		}
		if features.ResponseClass == "syn-ack" && r.Completed && cleanupCount != 1 {
			return envelope, errors.New("SYN/ACK cleanup missing")
		}
	}
	if bytesCount != r.CaptureBytes || txCount != r.PacketsTX || txCount > p.MaxPackets {
		return envelope, errors.New("traffic or capture accounting mismatch")
	}
	c := Compare(*r)
	if !reflect.DeepEqual(c, r.Comparison) {
		return envelope, errors.New("derived comparison mismatch")
	}
	r.Comparison = c
	return envelope, nil
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}
