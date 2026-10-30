package observe

import (
	"net/netip"
	"time"
)

// ProbeRunSchema versions a replay of one retained application exchange.
const ProbeRunSchema = "nyxr/probe-run/v1"

// Probe run modes. Offline replays feed retained response bytes to the
// definition's parser and send nothing; live resends open one connection to
// the original target and are recorded as a new scan.
const (
	ProbeRunOffline = "offline"
	ProbeRunLive    = "live"
)

// Probe run outcomes. A partial run kept some bytes but ended in a timeout,
// I/O error or truncation; a failed run retained no response at all.
const (
	ProbeRunMatched   = "matched"
	ProbeRunUnmatched = "unmatched"
	ProbeRunPartial   = "partial"
	ProbeRunFailed    = "failed"
)

// ProbeRun is one replay of an edited Protocol DSL definition against the
// exchange it was cloned from. Source points at the original retained
// exchange, which a run never modifies. Result is the observation the
// definition produced; for an offline run its response bytes are the
// retained evidence, not a new reply from the target.
type ProbeRun struct {
	Schema           string     `json:"schema"`
	ID               string     `json:"run_id"`
	Mode             string     `json:"mode"`
	CreatedAt        time.Time  `json:"created_at"`
	Source           SourceRef  `json:"source"`
	Protocol         string     `json:"protocol"`
	DefinitionSHA256 string     `json:"definition_sha256"`
	Target           netip.Addr `json:"target"`
	Transport        string     `json:"transport"`
	Port             uint16     `json:"port"`
	Status           string     `json:"status"`
	Error            string     `json:"error,omitempty"`
	// RequestMatchesEvidence is false when the edited definition sent bytes
	// that differ from the retained request. An offline result then shows
	// how the parser reads the original reply, not how the target would
	// answer the edited request.
	RequestMatchesEvidence bool `json:"request_matches_evidence"`
	// ScanID names the new scan that stores a live run's observation.
	ScanID string      `json:"scan_id,omitempty"`
	Result Observation `json:"result"`
}
