package observe

import "time"

// TCPStack preserves bounded, token-correlated network evidence. Candidate
// confidence is a heuristic about the responder, separate from port state.
type TCPStack struct {
	Signature              string           `json:"signature"`
	Status                 string           `json:"status"`
	ProbeProfile           string           `json:"probe_profile"`
	ObservationWindow      time.Duration    `json:"observation_window_ns"`
	CollectionComplete     bool             `json:"collection_complete"`
	Candidates             []StackCandidate `json:"candidates,omitempty"`
	Samples                []StackSample    `json:"samples"`
	IPIDBehavior           string           `json:"ip_id_behavior"`
	RetransmissionBehavior string           `json:"retransmission_behavior"`
	RepeatIntervals        []time.Duration  `json:"repeat_intervals_ns,omitempty"`
	RSTBehavior            string           `json:"rst_behavior"`
	Truncated              bool             `json:"truncated,omitempty"`
}

type StackCandidate struct {
	Family     string   `json:"family"`
	Confidence int      `json:"confidence"`
	Reasons    []string `json:"reasons"`
}

type StackSample struct {
	Received       time.Time `json:"received"`
	Response       string    `json:"response"`
	IPVersion      uint8     `json:"ip_version"`
	TTL            uint8     `json:"ttl"`
	InitialTTL     uint8     `json:"initial_ttl"`     // nearest common initial TTL, an estimate
	DF             *bool     `json:"df,omitempty"`    // IPv4 only
	IPID           *uint16   `json:"ip_id,omitempty"` // IPv4 only
	Window         uint16    `json:"window"`
	Flags          uint8     `json:"flags"`
	Sequence       uint32    `json:"sequence"`
	Acknowledgment uint32    `json:"acknowledgment"`
	OptionsHex     string    `json:"options_hex,omitempty"`
	OptionOrder    []int     `json:"option_order,omitempty"`
	MSS            *uint16   `json:"mss,omitempty"`
	WindowScale    *uint8    `json:"window_scale,omitempty"`
	SACK           bool      `json:"sack"`
	TimestampValue *uint32   `json:"timestamp_value,omitempty"`
	TimestampEcho  *uint32   `json:"timestamp_echo,omitempty"`
	ECN            string    `json:"ecn"`
	OptionsValid   bool      `json:"options_valid"`
}
