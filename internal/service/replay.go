package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// offlineReplayTimeout bounds an offline replay: the retained peer answers
// at once, so a longer wait only delays reporting a short response.
const offlineReplayTimeout = time.Second

// CloneProtocol drafts an editable nyxr/protocol/v2 definition from one
// retained exchange of a sealed observation. The draft sends the retained
// request bytes, reads at most as many bytes as were retained and expects
// the first response bytes. It is compiled before it is returned, but it is
// an operator draft, not a validated protocol signature.
func CloneProtocol(o observe.Observation, index int) ([]byte, error) {
	ev, err := retainedExchange(o, index)
	if err != nil {
		return nil, err
	}
	transport := o.Transport
	var steps []string
	switch ev.Layer {
	case "tcp", "udp":
		if ev.Layer != transport {
			return nil, fmt.Errorf("exchange layer %s does not match %s observation", ev.Layer, transport)
		}
	case "tls":
		if transport != "tcp" {
			return nil, errors.New("TLS exchange requires a tcp observation")
		}
		steps = append(steps, "  - tls: true")
	default:
		return nil, fmt.Errorf("exchange layer %q is a native handshake and cannot be cloned into byte steps", ev.Layer)
	}
	if len(ev.Request) > 4096 {
		return nil, errors.New("retained request exceeds the 4096-byte send limit")
	}
	if len(ev.Request) > 0 {
		steps = append(steps, fmt.Sprintf("  - send: {hex: %q}", hex.EncodeToString(ev.Request)))
	} else if transport == "udp" {
		return nil, errors.New("UDP exchange retained no request to send")
	}
	steps = append(steps, fmt.Sprintf("  - receive: {max_bytes: %d}", min(max(len(ev.Response), 1), 4096)))
	if len(ev.Response) > 0 {
		steps = append(steps, fmt.Sprintf("  - expect: {hex: %q}", hex.EncodeToString(ev.Response[:min(len(ev.Response), 16)])))
	} else {
		steps = append(steps, `  - expect: {regex: "(?s)."} # nothing was retained; any reply matches`)
	}
	name := cloneName(ev.Probe)
	provenance := fmt.Sprintf("Draft cloned from %s#%s of scan %s; unvalidated.", o.Source.ArtifactID, ev.Source.Pointer, o.ScanID)
	var b strings.Builder
	fmt.Fprintf(&b, "# Draft cloned by nyxr from retained evidence. Edit it, then check it:\n")
	fmt.Fprintf(&b, "#   nyxr probe replay %s --exchange %d --definition FILE --dry-run\n", o.ID, index)
	fmt.Fprintf(&b, "# original: probe %s, layer %s, %s %s/%d, matched %q, completeness %s\n",
		ev.Probe, ev.Layer, o.Target, transport, o.Port, ev.Matched, ev.Completeness)
	if ev.Truncated {
		b.WriteString("# The retained exchange was truncated; the reply may be longer than max_bytes.\n")
	}
	if len(ev.Request) > 0 {
		b.WriteString("# A probe with several writes is retained as one request; split it if needed.\n")
	}
	fmt.Fprintf(&b, "schema: nyxr/protocol/v2\nprotocol: %s\nprovenance: %q\ntransport: %s\nports: [%d]\ntimeout: 3s\nsteps:\n%s\n",
		name, provenance, transport, o.Port, strings.Join(steps, "\n"))
	if _, err := ParseProtocol(strings.NewReader(b.String())); err != nil {
		return nil, fmt.Errorf("cloned definition does not compile: %w", err)
	}
	return []byte(b.String()), nil
}

func cloneName(probe string) string {
	var b strings.Builder
	b.WriteString("clone-")
	for _, r := range strings.ToLower(probe) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return strings.TrimRight(b.String()[:min(b.Len(), 64)], "-")
}

func retainedExchange(o observe.Observation, index int) (observe.Evidence, error) {
	if o.Source == nil || o.ID == "" {
		return observe.Evidence{}, errors.New("observation has no sealed source; only retained exchanges can be cloned or replayed")
	}
	if index < 0 || index >= len(o.Evidence) {
		return observe.Evidence{}, fmt.Errorf("exchange %d is not retained; the observation has %d", index, len(o.Evidence))
	}
	ev := o.Evidence[index]
	if ev.Source == nil {
		return observe.Evidence{}, errors.New("exchange has no source reference")
	}
	if !o.Target.IsValid() || o.Port == 0 || (o.Transport != "tcp" && o.Transport != "udp") {
		return observe.Evidence{}, errors.New("observation has no target port to replay against")
	}
	return ev, nil
}

// ProbePlan is the exact scope of one replay, computed before anything runs.
// Byte limits are upper bounds that already include bounded repeats.
type ProbePlan struct {
	Mode             string            `json:"mode"`
	Protocol         string            `json:"protocol"`
	Schema           string            `json:"schema"`
	DefinitionSHA256 string            `json:"definition_sha256"`
	Source           observe.SourceRef `json:"source"`
	Target           netip.Addr        `json:"target"`
	Transport        string            `json:"transport"`
	Port             uint16            `json:"port"`
	Connections      int               `json:"connections"` // network connections; 0 offline
	Timeout          time.Duration     `json:"timeout_ns"`
	MaxSteps         int               `json:"max_steps"`
	MaxSendBytes     int               `json:"max_send_bytes"`
	MaxReceiveBytes  int               `json:"max_receive_bytes"`
	TLS              bool              `json:"tls,omitempty"`
}

// ReplayInput selects one retained exchange and the edited definition to run
// against it. Mode is offline or live.
type ReplayInput struct {
	Observation observe.Observation
	Exchange    int
	Definition  []byte
	Mode        string
	// Dial is a test hook for live runs; nil uses net.Dialer.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// PlanReplay compiles a self-contained definition and pins it to the target,
// transport and port of the exchange it replays. It sends no traffic.
func PlanReplay(in ReplayInput) (ProtocolDefinition, ProbePlan, error) {
	ev, err := retainedExchange(in.Observation, in.Exchange)
	if err != nil {
		return ProtocolDefinition{}, ProbePlan{}, err
	}
	if in.Mode != observe.ProbeRunOffline && in.Mode != observe.ProbeRunLive {
		return ProtocolDefinition{}, ProbePlan{}, errors.New("replay mode must be offline or live")
	}
	d, err := ParseProtocol(bytes.NewReader(in.Definition))
	if err != nil {
		return ProtocolDefinition{}, ProbePlan{}, fmt.Errorf("definition: %w", err)
	}
	o := in.Observation
	if d.Transport != o.Transport || !slices.Contains(d.Ports, o.Port) {
		return ProtocolDefinition{}, ProbePlan{}, fmt.Errorf("definition must cover the evidence port %s/%d", o.Transport, o.Port)
	}
	native := len(d.steps) == 1 && (d.steps[0].DTLS || d.steps[0].QUIC)
	if native && in.Mode == observe.ProbeRunOffline {
		return ProtocolDefinition{}, ProbePlan{}, errors.New("native DTLS/QUIC handshakes cannot be replayed from retained bytes")
	}
	plan := ProbePlan{Mode: in.Mode, Protocol: d.Name, Schema: d.Schema, DefinitionSHA256: d.SourceSHA256, Source: *ev.Source,
		Target: o.Target, Transport: o.Transport, Port: o.Port, Timeout: d.Timeout, MaxSteps: 128}
	if in.Mode == observe.ProbeRunLive {
		plan.Connections = 1
	} else {
		plan.Timeout = min(d.Timeout, offlineReplayTimeout)
	}
	factor, sent, largestSend, received, largestReceive := 1, 0, 0, 0, 0
	for _, s := range d.steps {
		if s.Repeat != nil {
			factor *= s.Repeat.Count
		}
		if s.Send != nil {
			sent += len(s.data)
			largestSend = max(largestSend, len(s.data))
		}
		if s.Receive != nil {
			received += s.Receive.MaxBytes
			largestReceive = max(largestReceive, s.Receive.MaxBytes)
		}
		plan.TLS = plan.TLS || s.TLS || s.StartTLS || s.DTLS
	}
	plan.MaxSendBytes = min(sent*factor, plan.MaxSteps*largestSend)
	plan.MaxReceiveBytes = min(received*factor, plan.MaxSteps*largestReceive)
	return d, plan, nil
}

// Replay runs one planned definition exactly once. Offline, the peer is an
// in-memory pipe serving the retained response; nothing reaches the network.
// Live, one connection is dialed to the original target and port only. The
// original observation is never modified: the result is a new record.
func Replay(ctx context.Context, in ReplayInput) (observe.ProbeRun, error) {
	d, plan, err := PlanReplay(in)
	if err != nil {
		return observe.ProbeRun{}, err
	}
	o := in.Observation
	original := o.Evidence[in.Exchange]
	now := time.Now().UTC()
	cfg := Config{Timeout: plan.Timeout, Workers: 1, MaxEvidence: 4096, Definitions: []ProtocolDefinition{d}, Dial: in.Dial}
	if in.Mode == observe.ProbeRunOffline {
		cfg.Dial = retainedPeer(original.Response)
	} else if cfg.Dial == nil {
		dialer := &net.Dialer{}
		cfg.Dial = dialer.DialContext
	}
	e := &Engine{cfg: cfg, retainedPlaintext: in.Mode == observe.ProbeRunOffline && original.Layer == "tls"}
	result := observe.Observation{Kind: observe.KindProbeReplay, Timestamp: now, Target: o.Target, Transport: o.Transport,
		Port: o.Port, State: "open", Fingerprint: observe.FingerprintUnknown, ConfidenceMethod: "none", ConfidenceModel: "probe-replay/v1"}
	matched := e.probeProtocol(ctx, Target{Addr: o.Target, Port: o.Port, Transport: o.Transport}, d, &result)
	run := observe.ProbeRun{Schema: observe.ProbeRunSchema, ID: observe.NewScanID(now), Mode: in.Mode, CreatedAt: now,
		Source: plan.Source, Protocol: d.Name, DefinitionSHA256: d.SourceSHA256, Target: o.Target, Transport: o.Transport, Port: o.Port}
	if result.Attributes == nil {
		result.Attributes = map[string]string{}
	}
	result.Attributes["replay.mode"] = in.Mode
	result.Attributes["replay.source"] = plan.Source.ArtifactID + "#" + plan.Source.Pointer
	var last observe.Evidence
	if n := len(result.Evidence); n > 0 {
		last = result.Evidence[n-1]
	}
	run.RequestMatchesEvidence = bytes.Equal(last.Request, original.Request)
	run.Error = last.Error
	switch {
	case matched:
		run.Status = observe.ProbeRunMatched
		result.Fingerprint = observe.FingerprintMatched
	case len(last.Response) == 0 && last.Error != "":
		run.Status = observe.ProbeRunFailed
		result.State = "error"
	case last.Error != "" || last.Truncated:
		run.Status = observe.ProbeRunPartial
	default:
		run.Status = observe.ProbeRunUnmatched
	}
	if in.Mode == observe.ProbeRunOffline {
		// The target was not contacted, so this run makes no state claim.
		result.State, result.ClaimStatus = "offline", "inferred"
		result.Reason = "offline parser replay of retained evidence; no traffic was sent"
		if !run.RequestMatchesEvidence {
			result.Reason += "; the edited request differs from the retained request"
		}
	} else {
		result.Reason = "explicit live resend of an edited probe"
	}
	run.Result = result
	return run, nil
}

// retainedPeer answers every replay connection with the retained response
// and discards what the definition sends. It never opens a socket.
func retainedPeer(response []byte) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			drained := make(chan struct{})
			go func() {
				defer close(drained)
				_, _ = io.Copy(io.Discard, server)
			}()
			if len(response) > 0 {
				_, _ = server.Write(response)
			}
			// Hold the pipe open until the client closes it, like a peer that
			// sent its reply and then went quiet.
			<-drained
		}()
		return client, nil
	}
}

// PlanText renders a plan for the CLI.
func PlanText(p ProbePlan) string {
	traffic := "none: the retained response is served from memory"
	if p.Connections > 0 {
		traffic = strconv.Itoa(p.Connections) + " connection to " + net.JoinHostPort(p.Target.String(), strconv.Itoa(int(p.Port)))
	}
	return fmt.Sprintf("mode        %s\nprotocol    %s (%s, sha256 %s)\nsource      %s#%s\ntarget      %s %s/%d\ntraffic     %s\ntimeout     %s\nmax steps   %d\nmax send    %d bytes\nmax receive %d bytes\n",
		p.Mode, p.Protocol, p.Schema, p.DefinitionSHA256, p.Source.ArtifactID, p.Source.Pointer, p.Target, p.Transport, p.Port,
		traffic, p.Timeout, p.MaxSteps, p.MaxSendBytes, p.MaxReceiveBytes)
}
