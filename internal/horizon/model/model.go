// Package model defines the versioned HZ-001 and bounded sequence wire formats.
package model

import "time"

const Version = "horizon.nyxr.io/v1alpha1"
const GeneralVersion = "horizon.nyxr.io/v1alpha2"

type Experiment struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Metadata   Metadata `json:"metadata" yaml:"metadata"`
	Spec       Spec     `json:"spec" yaml:"spec"`
}
type Metadata struct {
	Name string `json:"name" yaml:"name"`
}
type Scope struct {
	Targets  []string `json:"targets" yaml:"targets"`
	TCPPorts []uint16 `json:"tcpPorts" yaml:"tcpPorts"`
}
type Spec struct {
	CrossPort       bool      `json:"crossPort,omitempty" yaml:"crossPort,omitempty"`
	Scope           Scope     `json:"scope" yaml:"scope"`
	ChangedVariable string    `json:"changedVariable" yaml:"changedVariable"`
	Control         Sequence  `json:"control" yaml:"control"`
	Treatment       Sequence  `json:"treatment" yaml:"treatment"`
	Execution       Execution `json:"execution" yaml:"execution"`
	Limits          Limits    `json:"limits" yaml:"limits"`
	Capture         Capture   `json:"capture" yaml:"capture"`
}
type Sequence struct {
	Steps []Step `json:"steps" yaml:"steps"`
}
type Step struct {
	Wait    *Wait    `json:"wait,omitempty" yaml:"wait,omitempty"`
	Repeat  *Repeat  `json:"repeat,omitempty" yaml:"repeat,omitempty"`
	Send    *Send    `json:"send,omitempty" yaml:"send,omitempty"`
	Observe *Observe `json:"observe,omitempty" yaml:"observe,omitempty"`
}
type Wait struct {
	DurationMS int `json:"durationMs" yaml:"durationMs"`
}
type Repeat struct {
	Count int    `json:"count" yaml:"count"`
	Steps []Step `json:"steps" yaml:"steps"`
}
type Send struct {
	Protocol       string   `json:"protocol" yaml:"protocol"`
	Flags          []string `json:"flags" yaml:"flags"`
	DstPort        uint16   `json:"dstPort" yaml:"dstPort"`
	OptionsProfile string   `json:"optionsProfile" yaml:"optionsProfile"`
}
type Observe struct {
	WindowMS int `json:"windowMs" yaml:"windowMs"`
}
type Execution struct {
	Replicates      int   `json:"replicates" yaml:"replicates"`
	RandomizedOrder bool  `json:"randomizedOrder" yaml:"randomizedOrder"`
	Seed            int64 `json:"seed" yaml:"seed,omitempty"`
	WashoutMS       int   `json:"washoutMs" yaml:"washoutMs,omitempty"`
}
type Limits struct {
	MaxReceiveFrames   int `json:"maxReceiveFrames,omitempty" yaml:"maxReceiveFrames,omitempty"`
	MaxMemoryBytes     int `json:"maxMemoryBytes,omitempty" yaml:"maxMemoryBytes,omitempty"`
	MaxPackets         int `json:"maxPackets" yaml:"maxPackets"`
	MaxDurationSeconds int `json:"maxDurationSeconds" yaml:"maxDurationSeconds"`
	PacketsPerSecond   int `json:"packetsPerSecond" yaml:"packetsPerSecond"`
	MaxConcurrentFlows int `json:"maxConcurrentFlows" yaml:"maxConcurrentFlows"`
}
type Capture struct {
	MaxBytes int `json:"maxBytes" yaml:"maxBytes"`
}

// Policy is independent operator authorization, never taken from the DSL.
type Policy struct {
	Profile      string   `json:"profile,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
	AllowTargets []string
	AllowPorts   []uint16
}
type PlannedTrial struct {
	Probe        int    `json:"probe,omitempty"`
	Send         *Send  `json:"send,omitempty"`
	WindowMS     int    `json:"windowMs,omitempty"`
	WaitBeforeMS int    `json:"waitBeforeMs,omitempty"`
	WaitAfterMS  int    `json:"waitAfterMs,omitempty"`
	OptionsHex   string `json:"optionsHex,omitempty"`
	Cleanup      string `json:"cleanup,omitempty"`
	Pair         int    `json:"pair"`
	Arm          string `json:"arm"`
}
type Plan struct {
	WireTemplate       WireTemplate   `json:"wireTemplate"`
	PolicyProfile      string         `json:"policyProfile"`
	MaxReceiveFrames   int            `json:"maxReceiveFrames"`
	MaxMemoryBytes     int            `json:"maxMemoryBytes"`
	MaxEvidenceFrames  int            `json:"maxEvidenceFrames"`
	MaxConcurrentFlows int            `json:"maxConcurrentFlows"`
	APIVersion         string         `json:"apiVersion"`
	Experiment         Experiment     `json:"experiment"`
	Hash               string         `json:"experimentHash"`
	MaxPackets         int            `json:"maxPackets"`
	MaxDurationMS      int64          `json:"maxDurationMs"`
	Trials             []PlannedTrial `json:"trials"`
}

// WireTemplate states fixed fields and the runtime substitutions in every send.
// Live bytes require interface addresses and fresh per-run cryptographic tokens.
type WireTemplate struct {
	Protocol        string `json:"protocol"`
	TCPFlags        uint8  `json:"tcpFlags"`
	Window          uint16 `json:"window"`
	HopLimit        uint8  `json:"hopLimit"`
	DontFragment    bool   `json:"dontFragment"`
	SourcePort      string `json:"sourcePort"`
	Sequence        string `json:"sequence"`
	CleanupFlags    uint8  `json:"cleanupFlags"`
	CleanupSequence string `json:"cleanupSequence"`
}
type Evidence struct {
	Timing        *Timing   `json:"timing,omitempty"`
	RelatedFlowID string    `json:"relatedFlowId,omitempty"`
	PacketID      uint64    `json:"packetId,omitempty"`
	Direction     string    `json:"direction"`
	Timestamp     time.Time `json:"timestamp"`
	Frame         []byte    `json:"frame"` // base64 Ethernet packet, bounded by Capture
}

// Timing distinguishes encoding resolution from measured clock precision.
// Nil precision/queue delay means unavailable, never zero delay or calibrated.
type Timing struct {
	ClockSource  string `json:"clockSource"`
	ResolutionNS int64  `json:"resolutionNs"`
	PrecisionNS  *int64 `json:"precisionNs"`
	QueueDelayNS *int64 `json:"queueDelayNs"`
	OperationNS  int64  `json:"operationNs"`
	BackendDrops uint64 `json:"backendDrops"`
}
type CaptureArtifact struct {
	ArtifactID      string `json:"artifactId"`
	Bytes           int64  `json:"bytes"`
	MaxBytes        int64  `json:"maxBytes"`
	Packets         int    `json:"packets"`
	Dropped         int    `json:"dropped"`
	MinimizePayload bool   `json:"minimizePayload"`
}
type Features struct {
	ResponseSource string `json:"responseSource,omitempty"`
	Correlation    string `json:"correlation,omitempty"`
	ICMPType       uint8  `json:"icmpType,omitempty"`
	ICMPCode       uint8  `json:"icmpCode,omitempty"`
	ResponseClass  string `json:"responseClass"`
	TTL            uint8  `json:"ttl,omitempty"`
	TCPOptions     []byte `json:"tcpOptions,omitempty"`
	RTTNS          int64  `json:"rttNs,omitempty"`
}
type Trial struct {
	Probe        int        `json:"probe,omitempty"`
	Pair         int        `json:"pair"`
	Arm          string     `json:"arm"`
	FlowID       string     `json:"flowId"`
	SentAt       time.Time  `json:"sentAt"`
	Features     Features   `json:"features"`
	QualityFlags []string   `json:"qualityFlags"`
	Evidence     []Evidence `json:"evidence"`
}
type Comparison struct {
	Status            string  `json:"status"` // inferred or unresolved; never a causal claim
	Conclusion        string  `json:"conclusion"`
	CompletePairs     int     `json:"completePairs"`
	DiscordantPairs   int     `json:"discordantPairs"`
	ControlOnlySACK   int     `json:"controlOnlySack"`
	TreatmentOnlySACK int     `json:"treatmentOnlySack"`
	PValue            float64 `json:"pValue"`
}
type Report struct {
	CorrelationVersion string           `json:"correlationVersion,omitempty"`
	CaptureArtifact    *CaptureArtifact `json:"captureArtifact,omitempty"`
	APIVersion         string           `json:"apiVersion"`
	Kind               string           `json:"kind"`
	Experiment         Experiment       `json:"experiment"`
	ExperimentHash     string           `json:"experimentHash"`
	RunID              string           `json:"runId"`
	Build              string           `json:"build"`
	Backend            string           `json:"backend"`
	StartedAt          time.Time        `json:"startedAt"`
	FinishedAt         time.Time        `json:"finishedAt"`
	Completed          bool             `json:"completed"`
	StopReason         string           `json:"stopReason,omitempty"`
	PacketsTX          int              `json:"packetsTx"`
	CaptureBytes       int              `json:"captureBytes"`
	BackendDrops       uint64           `json:"backendDrops"`
	Trials             []Trial          `json:"trials"`
	Comparison         Comparison       `json:"comparison"`
	Limitations        []string         `json:"limitations"`
}

// Envelope provides corruption detection, not authentication or a signature.
type Envelope struct {
	SHA256 string `json:"sha256"`
	Report Report `json:"report"`
}
