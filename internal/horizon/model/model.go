// Package model defines the versioned, deliberately small HZ-001 wire format.
package model

import "time"

const Version = "horizon.nyxr.io/v1alpha1"

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
	Send    *Send    `json:"send,omitempty" yaml:"send,omitempty"`
	Observe *Observe `json:"observe,omitempty" yaml:"observe,omitempty"`
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
	AllowTargets []string
	AllowPorts   []uint16
}
type PlannedTrial struct {
	Pair int    `json:"pair"`
	Arm  string `json:"arm"`
}
type Plan struct {
	APIVersion    string         `json:"apiVersion"`
	Experiment    Experiment     `json:"experiment"`
	Hash          string         `json:"experimentHash"`
	MaxPackets    int            `json:"maxPackets"`
	MaxDurationMS int64          `json:"maxDurationMs"`
	Trials        []PlannedTrial `json:"trials"`
}
type Evidence struct {
	Direction string    `json:"direction"`
	Timestamp time.Time `json:"timestamp"`
	Frame     []byte    `json:"frame"` // base64 Ethernet packet, bounded by Capture
}
type Features struct {
	ResponseClass string `json:"responseClass"`
	TTL           uint8  `json:"ttl,omitempty"`
	TCPOptions    []byte `json:"tcpOptions,omitempty"`
	RTTNS         int64  `json:"rttNs,omitempty"`
}
type Trial struct {
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
	APIVersion     string     `json:"apiVersion"`
	Kind           string     `json:"kind"`
	Experiment     Experiment `json:"experiment"`
	ExperimentHash string     `json:"experimentHash"`
	RunID          string     `json:"runId"`
	Build          string     `json:"build"`
	Backend        string     `json:"backend"`
	StartedAt      time.Time  `json:"startedAt"`
	FinishedAt     time.Time  `json:"finishedAt"`
	Completed      bool       `json:"completed"`
	StopReason     string     `json:"stopReason,omitempty"`
	PacketsTX      int        `json:"packetsTx"`
	CaptureBytes   int        `json:"captureBytes"`
	BackendDrops   uint64     `json:"backendDrops"`
	Trials         []Trial    `json:"trials"`
	Comparison     Comparison `json:"comparison"`
	Limitations    []string   `json:"limitations"`
}

// Envelope provides corruption detection, not authentication or a signature.
type Envelope struct {
	SHA256 string `json:"sha256"`
	Report Report `json:"report"`
}
