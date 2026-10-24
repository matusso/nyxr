package horizon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/horizon/model"
)

// Phase 5 (#71) hypothesis families. Families without a discriminating
// experiment are listed as not evaluated rather than given unlinked claims.
var hypothesisFamilies = []string{"endpoint-stack", "firewall-tracking", "nat-state", "proxy", "load-balancer", "rate-limiter"}

const (
	maxGraphRuns     = 256
	probabilityNever = "uncalibrated: no numeric probability until a held-out calibration supports one"
)

// GraphInput holds replayed evidence. Studies map cross-port roles to reports.
type GraphInput struct {
	Reports []model.Envelope
	Studies []map[string]model.Envelope
	Changes []model.ChangeEvent
	Now     time.Time
	TTL     time.Duration
}

type outcome struct {
	run, status string    // supported, not-supported or unresolved
	started, at time.Time // a run that started before a change is stale
	location    string
	alts        []string
	reason      string
}

type graphBuilder struct {
	g        model.Graph
	nodes    map[string]bool
	runs     map[string]model.Report
	quality  map[string]model.RunQuality
	outcomes map[[2]string][]outcome // family, subject
	hosts    map[string]bool
}

// BuildGraph is deterministic for its input. Every hypothesis links to at
// least one run node; contradictions and stale evidence leave it unresolved.
func BuildGraph(in GraphInput) (model.Graph, error) {
	if in.TTL <= 0 || in.Now.IsZero() {
		return model.Graph{}, errors.New("graph requires a positive TTL and an explicit time")
	}
	b := graphBuilder{nodes: map[string]bool{}, runs: map[string]model.Report{}, quality: map[string]model.RunQuality{}, outcomes: map[[2]string][]outcome{}, hosts: map[string]bool{}}
	b.g = model.Graph{APIVersion: model.GraphVersion, Kind: "EvidenceGraph", GeneratedAt: in.Now.UTC(), TTLSeconds: int64(in.TTL / time.Second),
		Nodes: []model.GraphNode{}, Edges: []model.GraphEdge{}, Hypotheses: []model.GraphHypothesis{}, Contradictions: []model.Contradiction{}, Changes: []model.ChangeEvent{},
		Limitations: []string{"Hypothesis status is a pre-registered decision rule over the linked runs, not a calibrated probability.",
			"Only tested ports are covered; untested ports carry no inference.",
			"Change detection compares reply TTL and non-SACK option layout between runs; other host or path changes need declared change events.",
			"Run repetitions against one target are not independent hosts."}}
	count := len(in.Reports)
	for _, s := range in.Studies {
		count += len(s)
	}
	if count == 0 || count > maxGraphRuns {
		return model.Graph{}, fmt.Errorf("graph requires 1..%d runs", maxGraphRuns)
	}
	for _, e := range in.Reports {
		if err := b.addRun(e); err != nil {
			return model.Graph{}, err
		}
	}
	for _, study := range in.Studies {
		for _, role := range CrossPortRoles {
			if e, ok := study[role]; ok {
				if err := b.addRun(e); err != nil {
					return model.Graph{}, err
				}
			}
		}
	}
	for _, c := range in.Changes {
		scope, err := CanonicalChangeScope(c.Scope)
		if c.At.IsZero() || err != nil {
			return model.Graph{}, errors.New("change events need a time and a host:<address> or network scope")
		}
		c.Scope = scope
		c.Source, c.At = "declared", c.At.UTC()
		b.g.Changes = append(b.g.Changes, c)
	}
	b.detectChanges()

	// Single-experiment evidence: HZ-001 SACK negotiation and HZ-002 A/A.
	unstable := map[string][]string{}
	for _, e := range in.Reports {
		r := e.Report
		host := r.Experiment.Spec.Scope.Targets[0]
		switch v := r.Experiment.Spec.ChangedVariable; {
		case v == "none":
			if r.Comparison.Status == "inferred" && r.Comparison.PValue <= 0.05 {
				unstable[host] = append(unstable[host], runNode(r))
			}
		case v == "sackPermitted" && singleProbe(r):
			b.sackOutcome(r)
		}
	}
	for _, study := range in.Studies {
		reports := map[string]model.Report{}
		for role, e := range study {
			reports[role] = e.Report
		}
		s, err := AnalyzeCrossPort(reports)
		if err != nil {
			return model.Graph{}, err
		}
		b.studyOutcome(s, reports)
	}
	b.resolve(in, unstable)
	evaluated := map[string]bool{}
	for _, h := range b.g.Hypotheses {
		evaluated[h.Family] = true
	}
	for _, f := range hypothesisFamilies {
		if !evaluated[f] {
			b.g.NotEvaluated = append(b.g.NotEvaluated, f)
		}
	}
	if b.g.NotEvaluated == nil {
		b.g.NotEvaluated = []string{}
	}
	slices.SortFunc(b.g.Changes, func(a, c model.ChangeEvent) int { return a.At.Compare(c.At) })
	slices.Sort(b.g.Coverage.TestedTCPPorts)
	b.g.Coverage.TestedTCPPorts = slices.Compact(b.g.Coverage.TestedTCPPorts)
	return b.g, ValidateGraph(b.g)
}

func runNode(r model.Report) string { return "run:" + r.RunID }

func singleProbe(r model.Report) bool {
	for _, t := range r.Trials {
		if t.Probe != 0 && t.Arm != "reference" {
			return false
		}
	}
	return true
}

func (b *graphBuilder) node(id, typ, statement string, attrs map[string]string) {
	if b.nodes[id] {
		return
	}
	b.nodes[id] = true
	b.g.Nodes = append(b.g.Nodes, model.GraphNode{ID: id, Type: typ, Statement: statement, Attributes: attrs})
}

func (b *graphBuilder) edge(from, to, relation string) {
	b.g.Edges = append(b.g.Edges, model.GraphEdge{From: from, To: to, Relation: relation})
}

func (b *graphBuilder) addRun(e model.Envelope) error {
	r := e.Report
	if r.RunID == "" || len(r.Experiment.Spec.Scope.Targets) != 1 {
		return errors.New("graph run requires a run ID and one target")
	}
	id := runNode(r)
	if b.nodes[id] {
		return fmt.Errorf("duplicate run %s", r.RunID)
	}
	host := r.Experiment.Spec.Scope.Targets[0]
	b.hosts[host] = true
	b.runs[id] = r
	attrs := map[string]string{"sha256": e.SHA256, "experimentHash": r.ExperimentHash, "build": r.Build, "backend": r.Backend,
		"startedAt": r.StartedAt.UTC().Format(time.RFC3339Nano), "finishedAt": r.FinishedAt.UTC().Format(time.RFC3339Nano),
		"completed": strconv.FormatBool(r.Completed), "changedVariable": r.Experiment.Spec.ChangedVariable,
		"comparison": r.Comparison.Status + ": " + r.Comparison.Conclusion, "correlationVersion": r.CorrelationVersion}
	if r.Environment != nil {
		attrs["environmentVersion"] = r.Environment.Version
	}
	b.node(id, "run", "observed", attrs)
	b.node("experiment:"+r.ExperimentHash, "experiment", "", map[string]string{"name": r.Experiment.Metadata.Name, "apiVersion": r.Experiment.APIVersion})
	b.node("build:"+r.Build, "build", "", nil)
	b.node("host:"+host, "host", "", nil)
	b.edge(id, "experiment:"+r.ExperimentHash, "instance-of")
	b.edge(id, "build:"+r.Build, "built-by")
	b.edge(id, "host:"+host, "targets")
	if a := r.CaptureArtifact; a != nil {
		b.node("capture:"+a.ArtifactID, "capture", "observed", map[string]string{"packets": strconv.Itoa(a.Packets), "dropped": strconv.Itoa(a.Dropped)})
		b.edge(id, "capture:"+a.ArtifactID, "captured-in")
	}
	for i, t := range r.Trials {
		port := ""
		if tx := t.Evidence; len(tx) > 0 {
			if p, ok := decodePort(tx[0].Frame); ok {
				port = fmt.Sprintf("%s/tcp/%d", host, p)
			}
		}
		trial := fmt.Sprintf("trial:%s/%d", r.RunID, i)
		attrs := map[string]string{"arm": t.Arm, "pair": strconv.Itoa(t.Pair), "probe": strconv.Itoa(t.Probe), "flow": t.FlowID,
			"responseClass": t.Features.ResponseClass, "qualityFlags": strings.Join(t.QualityFlags, ",")}
		if t.Features.TTL != 0 {
			attrs["ttl"] = strconv.Itoa(int(t.Features.TTL))
		}
		var packets []string
		for _, ev := range t.Evidence {
			if ev.PacketID != 0 {
				packets = append(packets, strconv.FormatUint(ev.PacketID, 10))
			}
		}
		if len(packets) > 0 {
			attrs["packetIds"] = strings.Join(packets, ",")
		}
		b.node(trial, "trial", "observed", attrs)
		b.edge(trial, id, "part-of")
		if port != "" {
			b.node("port:"+port, "port", "", nil)
			b.edge(trial, "port:"+port, "probes")
			b.g.Coverage.TestedTCPPorts = append(b.g.Coverage.TestedTCPPorts, port)
		}
	}
	q := model.RunQuality{Run: id, Grade: "good", Reasons: []string{}, ObservedAt: r.FinishedAt.UTC()}
	if !r.Completed || r.BackendDrops > 0 {
		q.Grade, q.Reasons = "poor", append(q.Reasons, "incomplete run or backend drops")
	}
	if r.Environment != nil {
		for _, f := range r.Environment.GatingFlags {
			q.Grade, q.Reasons = "poor", append(q.Reasons, f)
		}
		for _, f := range r.Environment.QualityFlags {
			if f != "clock-precision-unknown" && q.Grade == "good" {
				q.Grade = "degraded"
			}
			q.Reasons = append(q.Reasons, f)
		}
	} else {
		q.Reasons = append(q.Reasons, "no saved environment assessment")
	}
	flagged := 0
	for _, t := range r.Trials {
		for _, f := range t.QualityFlags {
			if f != "timeout" || r.Experiment.Spec.ChangedVariable != "precondition" {
				flagged++
				break
			}
		}
	}
	if flagged > 0 {
		if q.Grade == "good" {
			q.Grade = "degraded"
		}
		q.Reasons = append(q.Reasons, fmt.Sprintf("%d flagged trials", flagged))
	}
	b.quality[id] = q
	b.g.Quality = append(b.g.Quality, q)
	return nil
}

func decodePort(frame []byte) (uint16, bool) {
	if len(frame) < 14 {
		return 0, false
	}
	offset := 14
	switch {
	case frame[12] == 0x08 && frame[13] == 0x00 && len(frame) >= 34:
		offset += int(frame[14]&0x0f) * 4
	case frame[12] == 0x86 && frame[13] == 0xdd && len(frame) >= 54:
		offset += 40
	default:
		return 0, false
	}
	if len(frame) < offset+4 {
		return 0, false
	}
	return uint16(frame[offset+2])<<8 | uint16(frame[offset+3]), true
}

// detectChanges compares consecutive runs per host: a different reply TTL or
// non-SACK option layout from the target itself is a detected change.
func (b *graphBuilder) detectChanges() {
	type print struct {
		ttl     map[uint8]bool
		options string
		at      time.Time
		run     string
	}
	byHost := map[string][]print{}
	for id, r := range b.runs {
		host := r.Experiment.Spec.Scope.Targets[0]
		p := print{ttl: map[uint8]bool{}, at: r.StartedAt, run: id}
		for _, t := range r.Trials {
			if t.Features.ResponseClass != "syn-ack" || (t.Features.ResponseSource != "" && t.Features.ResponseSource != host) {
				continue
			}
			p.ttl[t.Features.TTL] = true
			if p.options == "" {
				p.options = fmt.Sprintf("%x", withoutSACK(t.Features.TCPOptions))
			}
		}
		if len(p.ttl) > 0 {
			byHost[host] = append(byHost[host], p)
		}
	}
	for host, prints := range byHost {
		slices.SortFunc(prints, func(a, c print) int {
			if n := a.at.Compare(c.at); n != 0 {
				return n
			}
			return strings.Compare(a.run, c.run)
		})
		for i := 1; i < len(prints); i++ {
			a, c := prints[i-1], prints[i]
			var details []string
			shared := false
			for ttl := range c.ttl {
				shared = shared || a.ttl[ttl]
			}
			if !shared {
				details = append(details, "reply TTL changed")
			}
			if a.options != c.options {
				details = append(details, "non-SACK TCP options changed")
			}
			if len(details) > 0 {
				b.g.Changes = append(b.g.Changes, model.ChangeEvent{At: c.at.UTC(), Scope: "host:" + host, Source: "detected",
					Detail: strings.Join(details, "; ") + " between " + a.run + " and " + c.run})
			}
		}
	}
}

var sackAlternatives = []string{"middlebox or proxy normalizing TCP options", "load-balanced backends with different stacks", "path change between arms"}

func (b *graphBuilder) sackOutcome(r model.Report) {
	port := r.Experiment.Spec.Scope.TCPPorts[0]
	subject := fmt.Sprintf("%s/tcp/%d", r.Experiment.Spec.Scope.Targets[0], port)
	c := r.Comparison
	o := outcome{run: runNode(r), status: "unresolved", started: r.StartedAt, at: r.FinishedAt, alts: sackAlternatives, reason: c.Conclusion}
	if c.Status == "inferred" {
		switch {
		case c.PValue > 0.05:
			o.status = "not-supported"
		case c.TreatmentOnlySACK > c.ControlOnlySACK:
			o.status = "supported"
		default:
			o.reason = "SACK difference in the unexpected direction"
		}
	}
	key := [2]string{"endpoint-stack", subject}
	b.outcomes[key] = append(b.outcomes[key], o)
}

func (b *graphBuilder) studyOutcome(s model.CrossPortStudy, reports map[string]model.Report) {
	main := reports[RoleMain]
	ports := []string{}
	for _, p := range append(slices.Clone(s.Roles[0].PreconditionPorts), s.Roles[0].MeasurementPort) {
		ports = append(ports, strconv.Itoa(int(p)))
	}
	slices.Sort(ports)
	subject := fmt.Sprintf("%s/tcp/{%s}", s.Target, strings.Join(slices.Compact(ports), ","))
	started, at := main.StartedAt, main.FinishedAt
	for _, r := range reports {
		if r.FinishedAt.After(at) {
			at = r.FinishedAt
		}
		if r.StartedAt.Before(started) {
			started = r.StartedAt
		}
	}
	// The study's evidence node is its main run; the other roles are linked
	// as controls through their own run nodes.
	run := runNode(main)
	for role, r := range reports {
		if role != RoleMain {
			b.edge(runNode(r), run, "control-for:"+role)
		}
	}
	shared := outcome{run: run, status: "unresolved", started: started, at: at, alts: crossPortAlternatives, reason: strings.Join(s.Reasons, "; ")}
	switch s.Classification {
	case "shared-state":
		shared.status = "supported"
	case "no-coupling", "per-port-state":
		shared.status = "not-supported"
	}
	b.outcomes[[2]string{"shared-state", subject}] = append(b.outcomes[[2]string{"shared-state", subject}], shared)
	if len(s.Candidates) == 0 {
		return
	}
	for _, h := range s.Candidates[0].Hypotheses {
		o := outcome{run: run, status: "unresolved", started: started, at: at, alts: crossPortAlternatives, reason: h.Reason, location: h.Location}
		if h.Status == "hypothesis" {
			o.status = "supported"
		}
		key := [2]string{h.Family, subject}
		b.outcomes[key] = append(b.outcomes[key], o)
	}
}

var familyStatements = map[string]string{
	"endpoint-stack":    "the TCP stack at %s grants SACK permission only when it is offered",
	"shared-state":      "flows to %s share state: a precondition on one port changes answers on another",
	"rate-limiter":      "a rate limiter shared by %s explains the dependence",
	"firewall-tracking": "path firewall state tracking shared by %s explains the dependence",
}

var familyAssumptions = map[string][]string{
	"endpoint-stack":    {"paired SYNs reach the same TCP stack", "pairs are independent and stationary"},
	"shared-state":      {"matched controls differ only by the precondition flow", "pairs are independent and stationary"},
	"rate-limiter":      {"suppression that decays with time separation indicates a token-like budget"},
	"firewall-tracking": {"a TTL difference between precondition and measurement replies indicates a different responder"},
}

func (b *graphBuilder) resolve(in GraphInput, unstable map[string][]string) {
	keys := make([][2]string, 0, len(b.outcomes))
	for k := range b.outcomes {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, c [2]string) int {
		if n := strings.Compare(a[1], c[1]); n != 0 {
			return n
		}
		return strings.Compare(a[0], c[0])
	})
	for i, key := range keys {
		family, subject := key[0], key[1]
		host := strings.SplitN(subject, "/", 2)[0]
		h := model.GraphHypothesis{ID: fmt.Sprintf("HYP-%d", i+1), Family: family, Subject: subject, Statement: fmt.Sprintf(familyStatements[family], subject),
			Status: "unresolved", ProbabilityMethod: probabilityNever, Support: []string{}, Against: []string{}, Reasons: []string{}, Assumptions: familyAssumptions[family]}
		// Evidence observed before the latest change in scope is stale.
		var cutoff time.Time
		for _, c := range b.g.Changes {
			if (c.Scope == "network" || c.Scope == "host:"+host) && !c.At.After(in.Now) && c.At.After(cutoff) {
				cutoff = c.At
			}
		}
		var current []outcome
		stale := 0
		for _, o := range b.outcomes[key] {
			if !cutoff.IsZero() && o.started.Before(cutoff) {
				stale++
				h.Against = append(h.Against, o.run)
				continue
			}
			current = append(current, o)
		}
		if stale > 0 {
			h.Reasons = append(h.Reasons, fmt.Sprintf("%d runs observed before a change at %s are stale", stale, cutoff.Format(time.RFC3339)))
		}
		var support, against, unresolved []string
		locations := map[string]bool{}
		for _, o := range current {
			h.Alternatives = o.alts
			if o.at.After(h.ObservedAt) {
				h.ObservedAt = o.at.UTC()
			}
			switch o.status {
			case "supported":
				support = append(support, o.run)
				if o.location != "" {
					locations[o.location] = true
				}
			case "not-supported":
				against = append(against, o.run)
			default:
				unresolved = append(unresolved, o.run)
				h.Reasons = append(h.Reasons, o.reason)
			}
		}
		h.Support, h.Against = append(h.Support, support...), append(h.Against, against...)
		switch {
		case len(current) == 0:
			h.Status = "stale"
			h.Support = append(h.Support, unresolved...)
		case len(support) > 0 && len(against) > 0:
			h.Reasons = append(h.Reasons, "linked runs disagree")
			b.g.Contradictions = append(b.g.Contradictions, model.Contradiction{Subject: subject, Family: family, Runs: append(slices.Clone(support), against...),
				Detail: fmt.Sprintf("%d supporting and %d non-supporting runs", len(support), len(against))})
		case len(support) > 0:
			h.Status = "supported"
		case len(against) > 0:
			h.Status = "not-supported"
		default:
			h.Support = append(h.Support, unresolved...)
		}
		if runs := unstable[host]; len(runs) > 0 && h.Status != "stale" {
			h.Status = "unresolved"
			h.Reasons = append(h.Reasons, "A/A control on this host showed a difference between identical arms")
			h.Against = append(h.Against, runs...)
			b.g.Contradictions = append(b.g.Contradictions, model.Contradiction{Subject: subject, Family: family, Runs: runs, Detail: "A/A instability on the host"})
		}
		if family == "rate-limiter" || family == "firewall-tracking" {
			// Different or unresolved locations across runs stay unresolved.
			h.Location = "endpoint-or-path-unresolved"
			if len(locations) == 1 {
				for l := range locations {
					h.Location = l
				}
			}
		}
		h.ValidUntil = h.ObservedAt.Add(in.TTL)
		if h.Status != "stale" && !h.ObservedAt.IsZero() && in.Now.After(h.ValidUntil) {
			h.Status = "stale"
			h.Reasons = append(h.Reasons, "evidence older than the confidence TTL")
		}
		h.ObservationGrade = "good"
		rank := map[string]int{"good": 0, "degraded": 1, "poor": 2}
		basis := h.Support
		if len(basis) == 0 {
			basis = h.Against
		}
		for _, run := range basis {
			if q := b.quality[run]; rank[q.Grade] > rank[h.ObservationGrade] {
				h.ObservationGrade = q.Grade
			}
		}
		if h.Alternatives == nil {
			h.Alternatives = []string{}
		}
		h.Statement = map[string]string{"supported": "inferred", "not-supported": "inferred", "unresolved": "unresolved", "stale": "unresolved"}[h.Status]
		if (family == "rate-limiter" || family == "firewall-tracking") && h.Status == "supported" {
			h.Statement = "hypothesis"
		}
		id := "hypothesis:" + h.ID
		b.node(id, "hypothesis", h.Statement, map[string]string{"family": family, "subject": subject, "status": h.Status})
		for _, run := range h.Support {
			b.edge(id, run, "supported-by")
		}
		for _, run := range h.Against {
			b.edge(id, run, "weighed-against")
		}
		b.g.Hypotheses = append(b.g.Hypotheses, h)
	}
}

// ValidateGraph checks the version and that every hypothesis is traceable to
// at least one run node in the graph.
func ValidateGraph(g model.Graph) error {
	if g.APIVersion != model.GraphVersion || g.Kind != "EvidenceGraph" {
		return errors.New("unsupported graph version/kind")
	}
	nodes := map[string]string{}
	for _, n := range g.Nodes {
		if _, dup := nodes[n.ID]; dup {
			return fmt.Errorf("duplicate graph node %s", n.ID)
		}
		nodes[n.ID] = n.Type
	}
	for _, e := range g.Edges {
		if nodes[e.From] == "" || nodes[e.To] == "" {
			return fmt.Errorf("edge %s -> %s references a missing node", e.From, e.To)
		}
	}
	for _, h := range g.Hypotheses {
		if len(h.Support)+len(h.Against) == 0 || h.Probability != nil {
			return fmt.Errorf("%s lacks evidence or publishes an uncalibrated probability", h.ID)
		}
		for _, run := range append(slices.Clone(h.Support), h.Against...) {
			if nodes[run] != "run" {
				return fmt.Errorf("%s links to missing run %s", h.ID, run)
			}
		}
	}
	return nil
}

// LoadGraph strictly decodes and validates a saved graph.
func LoadGraph(r io.Reader) (model.Graph, error) {
	var g model.Graph
	data, err := io.ReadAll(io.LimitReader(r, (64<<20)+1))
	if err != nil {
		return g, err
	}
	if len(data) > 64<<20 {
		return g, errors.New("graph exceeds 64 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&g); err != nil {
		return g, err
	}
	if d.More() {
		return g, errors.New("graph has trailing data")
	}
	return g, ValidateGraph(g)
}

// ExplainHypothesis traces one hypothesis to its runs, builds and captures.
func ExplainHypothesis(g model.Graph, id string) (string, error) {
	var h *model.GraphHypothesis
	for i := range g.Hypotheses {
		if g.Hypotheses[i].ID == id {
			h = &g.Hypotheses[i]
		}
	}
	if h == nil {
		return "", fmt.Errorf("hypothesis %s not found", id)
	}
	nodes := map[string]model.GraphNode{}
	for _, n := range g.Nodes {
		nodes[n.ID] = n
	}
	var s strings.Builder
	fmt.Fprintf(&s, "%s [%s] %s: %s\n", h.ID, h.Status, h.Family, h.Statement)
	fmt.Fprintf(&s, "Subject: %s", h.Subject)
	if h.Location != "" {
		fmt.Fprintf(&s, "; location: %s", h.Location)
	}
	fmt.Fprintf(&s, "\nObservation quality: %s (separate from status)\nProbability: none (%s)\nValid until: %s\n", h.ObservationGrade, h.ProbabilityMethod, h.ValidUntil.Format(time.RFC3339))
	trace := func(label string, runs []string) {
		for _, run := range runs {
			n := nodes[run]
			a := n.Attributes
			fmt.Fprintf(&s, "%s %s: experiment %s, build %s, backend %s, finished %s, report sha256 %s\n  %s\n", label, run, a["experimentHash"], a["build"], a["backend"], a["finishedAt"], a["sha256"], a["comparison"])
			for _, e := range g.Edges {
				if e.From == run && strings.HasPrefix(e.To, "capture:") {
					fmt.Fprintf(&s, "  capture %s\n", strings.TrimPrefix(e.To, "capture:"))
				}
				if e.To == run && strings.HasPrefix(e.Relation, "control-for:") {
					fmt.Fprintf(&s, "  %s control %s\n", strings.TrimPrefix(e.Relation, "control-for:"), e.From)
				}
			}
		}
	}
	trace("Supported by", h.Support)
	trace("Weighed against", h.Against)
	for _, label := range []struct {
		name   string
		values []string
	}{{"Alternative", h.Alternatives}, {"Assumption", h.Assumptions}, {"Reason", h.Reasons}} {
		for _, v := range label.values {
			fmt.Fprintf(&s, "%s: %s\n", label.name, v)
		}
	}
	return s.String(), nil
}
