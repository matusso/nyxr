package horizon

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

	"github.com/matusso/nyxr/internal/horizon/model"
)

// Metrics are process-local counters in the Prometheus text format. A nil
// *Metrics records nothing.
type Metrics struct {
	mu        sync.Mutex
	runs      map[string]uint64 // mode,state
	denied    map[string]uint64 // reason
	stops     map[string]uint64 // rule
	packets   uint64
	drops     uint64
	ambiguous uint64
	trials    uint64
	auditFail uint64
	active    int
	killed    bool
}

func NewMetrics() *Metrics {
	return &Metrics{runs: map[string]uint64{}, denied: map[string]uint64{}, stops: map[string]uint64{}}
}

func (m *Metrics) Denied(reason string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.denied[reason]++
	m.mu.Unlock()
}

// AuditFailure counts audit writes that failed; the trail then refuses runs.
func (m *Metrics) AuditFailure() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.auditFail++
	m.mu.Unlock()
}

func (m *Metrics) Started() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.active++
	m.mu.Unlock()
}

func (m *Metrics) KillSwitch() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.killed = true
	m.mu.Unlock()
}

// Finished records a run's outcome and what its evidence says about the
// measurement itself: traffic, capture drops, ambiguous correlation and the
// stop rule (curtailment, cancellation, deadline or kill switch) that ended it.
func (m *Metrics) Finished(mode, state string, r model.Report) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active--
	m.runs[mode+","+state]++
	m.packets += uint64(r.PacketsTX)
	m.drops += r.BackendDrops
	if r.CaptureArtifact != nil {
		m.drops += uint64(r.CaptureArtifact.Dropped)
	}
	for _, t := range r.Trials {
		m.trials++
		if t.Features.Correlation == "ambiguous-path" {
			m.ambiguous++
		}
	}
	switch {
	case r.Curtailment != nil:
		m.stops["curtailed"]++
	case state == "cancelled" || state == "stopped":
		m.stops[state]++
	case strings.Contains(r.StopReason, "deadline"):
		m.stops["deadline"]++
	}
}

func (m *Metrics) WritePrometheus(w io.Writer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	family := func(name, typ, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	labeled := func(name string, values map[string]uint64, labels ...string) {
		keys := make([]string, 0, len(values))
		for k := range values {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			parts := strings.Split(k, ",")
			var pairs []string
			for i, l := range labels {
				pairs = append(pairs, fmt.Sprintf("%s=%q", l, parts[i]))
			}
			fmt.Fprintf(&b, "%s{%s} %d\n", name, strings.Join(pairs, ","), values[k])
		}
	}
	family("nyxr_horizon_runs_total", "counter", "Finished HORIZON runs by mode and final state.")
	labeled("nyxr_horizon_runs_total", m.runs, "mode", "state")
	family("nyxr_horizon_admission_denied_total", "counter", "Requests refused before any traffic, by reason.")
	labeled("nyxr_horizon_admission_denied_total", m.denied, "reason")
	family("nyxr_horizon_stop_rules_total", "counter", "Runs ended early by a stop rule.")
	labeled("nyxr_horizon_stop_rules_total", m.stops, "rule")
	family("nyxr_horizon_packets_tx_total", "counter", "Transmitted experiment packets, including RST cleanup.")
	fmt.Fprintf(&b, "nyxr_horizon_packets_tx_total %d\n", m.packets)
	family("nyxr_horizon_capture_drops_total", "counter", "Frames the backend or capture artifact reported dropped.")
	fmt.Fprintf(&b, "nyxr_horizon_capture_drops_total %d\n", m.drops)
	family("nyxr_horizon_trials_total", "counter", "Recorded trials.")
	fmt.Fprintf(&b, "nyxr_horizon_trials_total %d\n", m.trials)
	family("nyxr_horizon_ambiguous_correlations_total", "counter", "Trials whose reply correlated only ambiguously (changed path or responder).")
	fmt.Fprintf(&b, "nyxr_horizon_ambiguous_correlations_total %d\n", m.ambiguous)
	family("nyxr_horizon_audit_failures_total", "counter", "Audit writes that failed; after one, no further run starts.")
	fmt.Fprintf(&b, "nyxr_horizon_audit_failures_total %d\n", m.auditFail)
	family("nyxr_horizon_active_runs", "gauge", "Runs currently executing.")
	fmt.Fprintf(&b, "nyxr_horizon_active_runs %d\n", m.active)
	family("nyxr_horizon_kill_switch_engaged", "gauge", "1 after the kill switch was engaged.")
	killed := 0
	if m.killed {
		killed = 1
	}
	fmt.Fprintf(&b, "nyxr_horizon_kill_switch_engaged %d\n", killed)
	_, err := io.WriteString(w, b.String())
	return err
}
