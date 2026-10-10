package dsl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/horizon/model"
)

// Profiles are ceilings, never authorization. No profile permits arbitrary
// resets, malformed traffic, payloads, connection floods or application writes.
type Profile struct {
	Name             string `json:"name"`
	MaxPackets       int    `json:"maxPackets"`
	PacketsPerSecond int    `json:"packetsPerSecond"`
	MaxCaptureBytes  int    `json:"maxCaptureBytes"`
	CrossPort        bool   `json:"crossPort"`
}

func Profiles() []Profile {
	return []Profile{
		{"lab", 200, 10, 8 << 20, true},
		{"enterprise", 100, 5, 4 << 20, true},
		{"fragile", 16, 1, 1 << 20, false},
		{"ot-restricted", 8, 1, 64 << 10, false},
	}
}
func profile(policy model.Policy) (Profile, error) {
	name := policy.Profile
	if name == "" {
		name = "lab"
	} // Preserve v1alpha1 behavior.
	for _, p := range Profiles() {
		if p.Name == name {
			return p, nil
		}
	}
	return Profile{}, fmt.Errorf("unknown policy profile %q", name)
}
func permitted(p model.Policy, name string) bool {
	for _, v := range p.Permissions {
		if v == name {
			return true
		}
	}
	return false
}
func describePlan(p model.Plan, policy model.Policy) (model.Plan, error) {
	prof, err := profile(policy)
	if err != nil {
		return model.Plan{}, err
	}
	for _, permission := range policy.Permissions {
		if permission != "cross-port" {
			return model.Plan{}, fmt.Errorf("unsupported permission %q; disruptive actions are not implemented", permission)
		}
	}
	s := p.Experiment.Spec
	if s.Limits.MaxPackets > prof.MaxPackets || s.Limits.PacketsPerSecond > prof.PacketsPerSecond || s.Capture.MaxBytes > prof.MaxCaptureBytes {
		return model.Plan{}, errors.New("experiment budgets exceed policy profile ceilings")
	}
	if s.CrossPort && (!prof.CrossPort || !permitted(policy, "cross-port")) {
		return model.Plan{}, errors.New("cross-port requires independent permission and a lab/enterprise policy")
	}
	p.WireTemplate = model.WireTemplate{Protocol: "tcp", TCPFlags: 2, Window: 64240, HopLimit: 64, DontFragment: true,
		SourcePort: "49152 + (freshBasePort + pair*32 + probe) mod 16384; v1alpha1 uses pair only",
		Sequence:   "freshBaseSequence + planned trial index; IP ID uses the same token", CleanupFlags: 4, CleanupSequence: "probe sequence + 1; no TCP options"}
	p.PolicyProfile = prof.Name
	receive := 4096
	if s.Limits.MaxReceiveFrames != 0 {
		receive = s.Limits.MaxReceiveFrames
	}
	// One additional receive call may trigger the cap; include it in the plan.
	p.MaxReceiveFrames = len(p.Trials) * (receive + 1)
	p.MaxEvidenceFrames = len(p.Trials) * 19
	p.MaxMemoryBytes = s.Capture.MaxBytes + (1 << 20)
	p.MaxConcurrentFlows = 1
	for i := range p.Trials {
		t := &p.Trials[i]
		t.OptionsHex = "020405b4"
		if t.Send.OptionsProfile == "sack-permitted" {
			t.OptionsHex = "020405b404020000"
		}
		t.Cleanup = "RST only after a correlated SYN/ACK; shares packet/rate/capture budgets"
	}
	return p, nil
}

const MaxExpandedSteps = 64
const MaxRepeatDepth = 4

// Expansion is checked before allocation on every append. Each repeat body is
// validated even for a zero/invalid count, and no user-controlled multiplication
// is performed until counts and lengths have fixed ceilings.
func expand(steps []model.Step, depth int) ([]model.Step, error) {
	if depth > MaxRepeatDepth || len(steps) == 0 || len(steps) > MaxExpandedSteps {
		return nil, errors.New("sequence depth/size exceeds bounds")
	}
	var out []model.Step
	for _, s := range steps {
		kinds := 0
		for _, ok := range []bool{s.Send != nil, s.Observe != nil, s.Wait != nil, s.Repeat != nil} {
			if ok {
				kinds++
			}
		}
		if kinds != 1 {
			return nil, errors.New("each step requires exactly one primitive")
		}
		body := []model.Step{s}
		count := 1
		if s.Repeat != nil {
			if s.Repeat.Count < 1 || s.Repeat.Count > 16 {
				return nil, errors.New("repeat count must be 1..16")
			}
			var err error
			body, err = expand(s.Repeat.Steps, depth+1)
			if err != nil {
				return nil, err
			}
			count = s.Repeat.Count
		}
		if len(body)*count > MaxExpandedSteps-len(out) {
			return nil, errors.New("expanded sequence exceeds 64 steps")
		}
		for i := 0; i < count; i++ {
			out = append(out, body...)
		}
	}
	return out, nil
}
func probes(steps []model.Step, ports map[uint16]bool) ([]model.PlannedTrial, error) {
	var out []model.PlannedTrial
	wait := 0
	for i := 0; i < len(steps); i++ {
		s := steps[i]
		if s.Wait != nil {
			if s.Wait.DurationMS < 0 || s.Wait.DurationMS > 5000 {
				return nil, errors.New("wait requires 0..5000 ms")
			}
			wait += s.Wait.DurationMS
			continue
		}
		if s.Send == nil || i+1 == len(steps) || steps[i+1].Observe == nil {
			return nil, errors.New("send must be immediately followed by observe")
		}
		send := s.Send
		if send.Protocol != "tcp" || len(send.Flags) != 1 || send.Flags[0] != "SYN" || !ports[send.DstPort] || (send.OptionsProfile != "baseline" && send.OptionsProfile != "sack-permitted") {
			return nil, errors.New("only scoped TCP SYN baseline/sack-permitted sends are supported; disruptive traffic is rejected")
		}
		window := steps[i+1].Observe.WindowMS
		if window < 10 || window > 5000 {
			return nil, errors.New("observe requires 10..5000 ms")
		}
		out = append(out, model.PlannedTrial{Probe: len(out), Send: send, WindowMS: window, WaitBeforeMS: wait})
		wait = 0
		i++
	}
	if len(out) == 0 {
		return nil, errors.New("sequence needs at least one send/observe")
	}
	out[len(out)-1].WaitAfterMS = wait
	return out, nil
}
func compileGeneral(e model.Experiment, policy model.Policy) (model.Plan, error) {
	var p model.Plan
	if e.Kind != "Experiment" || !namePattern.MatchString(e.Metadata.Name) {
		return p, errors.New("require Experiment with a short lowercase name")
	}
	if policy.Profile == "" {
		return p, errors.New("v1alpha2 requires an independent policy profile")
	}
	s := e.Spec
	if len(s.Scope.Targets) != 1 || len(s.Scope.TCPPorts) < 1 || len(s.Scope.TCPPorts) > 8 {
		return p, errors.New("require one literal target and 1..8 declared ports")
	}
	target, err := netip.ParseAddr(s.Scope.Targets[0])
	if err != nil || target.Zone() != "" || target.Is4In6() || !target.IsGlobalUnicast() || target == netip.MustParseAddr("255.255.255.255") {
		return p, errors.New("require unicast IPv4/IPv6 literal without a zone")
	}
	scope, err := config.ParseScope(policy.AllowTargets)
	if err != nil || scope.Empty() || !scope.Contains(target) {
		return p, errors.New("target outside independent operator authorization")
	}
	ports := map[uint16]bool{}
	for _, port := range s.Scope.TCPPorts {
		if port == 0 || ports[port] {
			return p, errors.New("ports must be nonzero and distinct")
		}
		authorized := false
		for _, allowed := range policy.AllowPorts {
			if port == allowed {
				authorized = true
			}
		}
		if !authorized {
			return p, errors.New("port outside independent operator authorization")
		}
		ports[port] = true
	}
	if (len(ports) > 1) != s.CrossPort {
		return p, errors.New("multiple ports require an explicit crossPort declaration; single-port scope must not declare it")
	}
	var arms [2][]model.PlannedTrial
	for i, seq := range []model.Sequence{s.Control, s.Treatment} {
		steps, err := expand(seq.Steps, 0)
		if err != nil {
			return p, err
		}
		arms[i], err = probes(steps, ports)
		if err != nil {
			return p, err
		}
	}
	switch s.ChangedVariable {
	case "sackPermitted":
		if len(arms[0]) != len(arms[1]) {
			return p, errors.New("SACK arms must have equal probe counts")
		}
		for i := range arms[0] {
			a, b := arms[0][i], arms[1][i]
			if a.Send.OptionsProfile != "baseline" || b.Send.OptionsProfile != "sack-permitted" {
				return p, errors.New("SACK arms require baseline versus sack-permitted")
			}
			ac, bc := *a.Send, *b.Send
			ac.OptionsProfile, bc.OptionsProfile = "", ""
			a.Send, b.Send = nil, nil
			if !reflect.DeepEqual(ac, bc) || !reflect.DeepEqual(a, b) {
				return p, errors.New("SACK arms may differ only in SACK permission")
			}
		}
	case "sequence": // Explicit exploratory sequence difference; never feeds HZ-001 inference.
	default:
		return p, errors.New("changedVariable must be sackPermitted or sequence")
	}
	x, l := s.Execution, s.Limits
	if x.Replicates < 2 || x.Replicates > 50 || !x.RandomizedOrder || x.WashoutMS < 0 || x.WashoutMS > 5000 {
		return p, errors.New("require 2..50 randomized pairs and 0..5000 ms washout")
	}
	if l.MaxPackets < 1 || l.MaxPackets > 200 || l.PacketsPerSecond < 1 || l.PacketsPerSecond > 10 || l.MaxConcurrentFlows != 1 || l.MaxDurationSeconds < 1 || l.MaxDurationSeconds > 1800 {
		return p, errors.New("invalid packet/rate/concurrency/deadline bound")
	}
	if s.Capture.MaxBytes < 4096 || s.Capture.MaxBytes > 8<<20 || l.MaxReceiveFrames < 1 || l.MaxReceiveFrames > 4096 || l.MaxMemoryBytes < s.Capture.MaxBytes+(1<<20) || l.MaxMemoryBytes > 16<<20 {
		return p, errors.New("invalid capture/receive/memory bound")
	}
	packets := 2 * x.Replicates * (len(arms[0]) + len(arms[1]))
	if packets > l.MaxPackets {
		return p, errors.New("packet budget must reserve every SYN and possible RST cleanup")
	}
	bound := 2 * time.Second
	for _, arm := range arms {
		bound += time.Duration(x.Replicates*x.WashoutMS) * time.Millisecond
		for _, probe := range arm {
			bound += time.Duration(x.Replicates) * (time.Duration(probe.WindowMS+probe.WaitBeforeMS+probe.WaitAfterMS)*time.Millisecond + 2*time.Second/time.Duration(l.PacketsPerSecond))
		}
	}
	if bound > time.Duration(l.MaxDurationSeconds)*time.Second {
		return p, fmt.Errorf("duration below conservative bound %s", bound)
	}
	e.Spec.Scope.Targets = []string{target.String()}
	b, err := json.Marshal(e)
	if err != nil {
		return p, err
	}
	h := sha256.Sum256(b)
	p = model.Plan{APIVersion: model.GeneralVersion, Experiment: e, Hash: hex.EncodeToString(h[:]), MaxPackets: packets, MaxDurationMS: bound.Milliseconds()}
	rng := rand.New(rand.NewSource(x.Seed))
	for pair := 0; pair < x.Replicates; pair++ {
		order := []int{0, 1}
		if rng.Intn(2) != 0 {
			order[0], order[1] = 1, 0
		}
		for _, i := range order {
			for _, probe := range arms[i] {
				probe.Pair = pair
				probe.Arm = []string{"control", "treatment"}[i]
				p.Trials = append(p.Trials, probe)
			}
		}
	}
	return describePlan(p, policy)
}
