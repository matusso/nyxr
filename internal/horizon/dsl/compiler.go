// Package dsl compiles versioned, authorized and bounded TCP experiments.
// Unsupported packet actions fail closed.
package dsl

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/horizon/model"
	"gopkg.in/yaml.v3"
)

const MaxDocumentBytes = 64 << 10

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Parse also accepts JSON (a YAML subset). No aliases, extra documents or
// unknown fields are accepted, including nested packet controls.
func Parse(r io.Reader) (model.Experiment, error) {
	var e model.Experiment
	b, err := io.ReadAll(io.LimitReader(r, MaxDocumentBytes+1))
	if err != nil {
		return e, err
	}
	if len(b) > MaxDocumentBytes {
		return e, errors.New("experiment exceeds 64 KiB")
	}
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return e, err
	}
	var check func(*yaml.Node, int) error
	check = func(n *yaml.Node, depth int) error {
		if depth > 24 || n.Kind == yaml.AliasNode || n.Anchor != "" {
			return errors.New("aliases, anchors and deeply nested experiments are unsupported")
		}
		for _, c := range n.Content {
			if err := check(c, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := check(&root, 0); err != nil {
		return e, err
	}
	if len(root.Content) != 1 {
		return e, errors.New("exactly one experiment object is required")
	}
	if err := checkWireType(root.Content[0], reflect.TypeOf(e), "experiment"); err != nil {
		return e, err
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(&e); err != nil {
		return e, err
	}
	if e.APIVersion == model.Version {
		var legacyFields func(*yaml.Node) error
		legacyFields = func(n *yaml.Node) error {
			if n.Kind == yaml.MappingNode {
				for i := 0; i < len(n.Content); i += 2 {
					switch n.Content[i].Value {
					case "crossPort", "wait", "repeat", "maxReceiveFrames", "maxMemoryBytes":
						return errors.New("v1alpha2 fields require v1alpha2")
					}
				}
			}
			for _, child := range n.Content {
				if err := legacyFields(child); err != nil {
					return err
				}
			}
			return nil
		}
		if err := legacyFields(&root); err != nil {
			return e, err
		}
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return e, errors.New("exactly one experiment document is required")
	}
	return e, nil
}

// yaml.v3 otherwise coerces fractional numbers to integers, non-string scalars
// to strings, and nulls to zero values. Check the wire types before decoding so
// admission never silently changes the operator's requested scope or budgets.
func checkWireType(n *yaml.Node, typ reflect.Type, path string) error {
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	want := ""
	switch typ.Kind() {
	case reflect.Struct:
		want = "!!map"
	case reflect.Slice:
		want = "!!seq"
	case reflect.String:
		want = "!!str"
	case reflect.Bool:
		want = "!!bool"
	case reflect.Int, reflect.Int64, reflect.Uint16:
		want = "!!int"
	}
	if want == "" || n.Tag != want {
		return fmt.Errorf("%s requires %s, got %s", path, want, n.Tag)
	}
	switch typ.Kind() {
	case reflect.Struct:
		fields := make(map[string]reflect.StructField, typ.NumField())
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
			fields[name] = field
		}
		for i := 0; i < len(n.Content); i += 2 {
			key, value := n.Content[i], n.Content[i+1]
			field, ok := fields[key.Value]
			if key.Tag != "!!str" || !ok {
				return fmt.Errorf("%s has unsupported field %q", path, key.Value)
			}
			if err := checkWireType(value, field.Type, path+"."+key.Value); err != nil {
				return err
			}
			delete(fields, key.Value)
		}
		for name, field := range fields {
			if field.Type.Kind() != reflect.Pointer && !strings.HasSuffix(field.Tag.Get("yaml"), ",omitempty") {
				return fmt.Errorf("%s requires field %q", path, name)
			}
		}
	case reflect.Slice:
		for i, item := range n.Content {
			if err := checkWireType(item, typ.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func Compile(e model.Experiment, policy model.Policy) (model.Plan, error) {
	var p model.Plan
	if e.APIVersion == model.GeneralVersion {
		return compileGeneral(e, policy)
	}
	if e.Spec.CrossPort || e.Spec.Limits.MaxReceiveFrames != 0 || e.Spec.Limits.MaxMemoryBytes != 0 {
		return p, errors.New("v1alpha2 fields require v1alpha2")
	}
	for _, seq := range []model.Sequence{e.Spec.Control, e.Spec.Treatment} {
		for _, step := range seq.Steps {
			if step.Wait != nil || step.Repeat != nil {
				return p, errors.New("general primitives require v1alpha2")
			}
		}
	}
	if e.APIVersion != model.Version || e.Kind != "Experiment" || !namePattern.MatchString(e.Metadata.Name) {
		return p, errors.New("require v1alpha1 Experiment with a short lowercase name")
	}
	s := e.Spec
	if len(s.Scope.Targets) != 1 || len(s.Scope.TCPPorts) != 1 || s.Scope.TCPPorts[0] == 0 {
		return p, errors.New("PoC requires exactly one literal target and one nonzero TCP port")
	}
	target, err := netip.ParseAddr(s.Scope.Targets[0])
	if err != nil || target.Zone() != "" || target.Is4In6() || !target.IsGlobalUnicast() || target == netip.MustParseAddr("255.255.255.255") {
		return p, errors.New("target must be a unicast IPv4/IPv6 literal without a zone")
	}
	allowed, err := config.ParseScope(policy.AllowTargets)
	if err != nil {
		return p, err
	}
	if allowed.Empty() || !allowed.Contains(target) {
		return p, errors.New("target is outside explicit operator authorization")
	}
	portOK := false
	for _, port := range policy.AllowPorts {
		if port == s.Scope.TCPPorts[0] {
			portOK = true
		}
	}
	if !portOK {
		return p, errors.New("port is outside explicit operator authorization")
	}
	if s.ChangedVariable != "sackPermitted" {
		return p, errors.New("only the sackPermitted controlled variable is implemented")
	}
	window := 0
	for i, seq := range []model.Sequence{s.Control, s.Treatment} {
		if len(seq.Steps) != 2 || seq.Steps[0].Send == nil || seq.Steps[0].Observe != nil || seq.Steps[1].Send != nil || seq.Steps[1].Observe == nil {
			return p, errors.New("each arm must contain exactly one send followed by one observe")
		}
		send := seq.Steps[0].Send
		profile := "baseline"
		if i == 1 {
			profile = "sack-permitted"
		}
		if send.Protocol != "tcp" || len(send.Flags) != 1 || send.Flags[0] != "SYN" || send.DstPort != s.Scope.TCPPorts[0] || send.OptionsProfile != profile {
			return p, fmt.Errorf("arm %d must use scoped TCP SYN and profile %s", i, profile)
		}
		w := seq.Steps[1].Observe.WindowMS
		if w < 10 || w > 5000 || (i == 1 && w != window) {
			return p, errors.New("matched response windows must be between 10 and 5000 ms")
		}
		window = w
	}
	x, l := s.Execution, s.Limits
	if x.Replicates < 2 || x.Replicates > 50 || !x.RandomizedOrder || x.WashoutMS < 0 || x.WashoutMS > 5000 {
		return p, errors.New("require 2..50 randomized pairs and washout 0..5000 ms")
	}
	if l.PacketsPerSecond < 1 || l.PacketsPerSecond > 10 || l.MaxConcurrentFlows != 1 || l.MaxPackets < 4*x.Replicates || l.MaxPackets > 200 || l.MaxDurationSeconds < 1 || l.MaxDurationSeconds > 1800 {
		return p, errors.New("require rate 1..10, one flow, 4 packets/pair including RST cleanup, and duration 1..1800 seconds")
	}
	if s.Capture.MaxBytes < 4096 || s.Capture.MaxBytes > 8<<20 {
		return p, errors.New("capture budget must be 4096 bytes..8 MiB")
	}
	// Includes worst-case SYN + cleanup spacing, receive window and washout.
	bound := time.Duration(2*x.Replicates)*(time.Duration(window+x.WashoutMS)*time.Millisecond+2*time.Second/time.Duration(l.PacketsPerSecond)) + 2*time.Second
	if bound > time.Duration(l.MaxDurationSeconds)*time.Second {
		return p, fmt.Errorf("duration budget below conservative bound %s", bound)
	}
	e.Spec.Scope.Targets = []string{target.String()}
	b, err := json.Marshal(e)
	if err != nil {
		return p, err
	}
	h := sha256.Sum256(b)
	p = model.Plan{APIVersion: model.Version, Experiment: e, Hash: hex.EncodeToString(h[:]), MaxPackets: 4 * x.Replicates, MaxDurationMS: bound.Milliseconds()}
	rng := rand.New(rand.NewSource(x.Seed))
	for pair := 0; pair < x.Replicates; pair++ {
		arms := []string{"control", "treatment"}
		if rng.Intn(2) != 0 {
			arms[0], arms[1] = arms[1], arms[0]
		}
		for _, arm := range arms {
			p.Trials = append(p.Trials, model.PlannedTrial{Pair: pair, Arm: arm})
		}
	}
	for i := range p.Trials {
		seq := s.Control
		if p.Trials[i].Arm == "treatment" {
			seq = s.Treatment
		}
		p.Trials[i].Send = seq.Steps[0].Send
		p.Trials[i].WindowMS = seq.Steps[1].Observe.WindowMS
	}
	return describePlan(p, policy)
}
