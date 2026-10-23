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
	Confounders     []string  `json:"confounders,omitempty" yaml:"confounders,omitempty"`
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
	ReferenceEvery  int   `json:"referenceEvery,omitempty" yaml:"referenceEvery,omitempty"`
	// StopRule "curtail" ends a precondition experiment once its fixed-n
	// sign-test decision can no longer change (exact curtailment).
	StopRule string `json:"stopRule,omitempty" yaml:"stopRule,omitempty"`
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
	Metric            string  `json:"metric,omitempty"` // empty means SACK permission
	ControlOnly       int     `json:"controlOnly,omitempty"`
	TreatmentOnly     int     `json:"treatmentOnly,omitempty"`
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
	Curtailment        *Curtailment     `json:"curtailment,omitempty"`
	PacketsTX          int              `json:"packetsTx"`
	CaptureBytes       int              `json:"captureBytes"`
	BackendDrops       uint64           `json:"backendDrops"`
	Trials             []Trial          `json:"trials"`
	Comparison         Comparison       `json:"comparison"`
	Environment        *Environment     `json:"environment,omitempty"`
	Limitations        []string         `json:"limitations"`
}

// Curtailment records an exact early stop: after Pairs complete pairs, every
// possible outcome of the remaining pairs yields the same fixed-n decision.
type Curtailment struct {
	Rule     string `json:"rule"`
	Pairs    int    `json:"pairs"`
	Decision string `json:"decision"` // significant or not-significant
}

// Environment is a deterministic post-run quality assessment. Its flags are
// observations about the run, never statements about the target's mechanism.
type Environment struct {
	Version      string     `json:"version"`
	Treatment    string     `json:"treatment"`
	Confounders  []string   `json:"confounders"`
	QualityFlags []string   `json:"qualityFlags"`
	GatingFlags  []string   `json:"gatingFlags"`
	Responses    Responses  `json:"responses"`
	Drift        Drift      `json:"drift"`
	Carryover    Carryover  `json:"carryover"`
	Stability    Stability  `json:"stability"`
	Clock        ClockCheck `json:"clock"`
	Latency      Latency    `json:"latency"`
}
type Responses struct {
	FirstHalf          int     `json:"firstHalf"`
	FirstHalfAnswered  int     `json:"firstHalfAnswered"`
	SecondHalf         int     `json:"secondHalf"`
	SecondHalfAnswered int     `json:"secondHalfAnswered"`
	ThrottlingPValue   float64 `json:"throttlingPValue"`
	References         int     `json:"references"`
	ReferencesAnswered int     `json:"referencesAnswered"`
}
type Drift struct {
	Samples            int    `json:"samples"`
	FirstHalfMedianNS  *int64 `json:"firstHalfMedianNs"`
	SecondHalfMedianNS *int64 `json:"secondHalfMedianNs"`
}
type Carryover struct {
	ControlFirstPairs        int     `json:"controlFirstPairs"`
	ControlFirstDiscordant   int     `json:"controlFirstDiscordant"`
	TreatmentFirstPairs      int     `json:"treatmentFirstPairs"`
	TreatmentFirstDiscordant int     `json:"treatmentFirstDiscordant"`
	PValue                   float64 `json:"pValue"`
}
type Stability struct {
	CompletePairs        int `json:"completePairs"`
	ResponseClassChanges int `json:"responseClassChanges"`
	TTLChanges           int `json:"ttlChanges"`
	OtherOptionChanges   int `json:"otherOptionChanges"`
}
type ClockCheck struct {
	TimedEvidence       int   `json:"timedEvidence"`
	UnknownPrecision    int   `json:"unknownPrecision"`
	MaxResolutionNS     int64 `json:"maxResolutionNs"`
	UnstableTrials      int   `json:"unstableTrials"`
	InvalidTimingTrials int   `json:"invalidTimingTrials"`
}

// Latency is descriptive userspace RTT. Intervals are distribution-free order
// statistic bounds for a median, assuming independent pairs; nil is unavailable.
type Latency struct {
	ControlMedianNS   *int64  `json:"controlMedianNs"`
	TreatmentMedianNS *int64  `json:"treatmentMedianNs"`
	PairedSamples     int     `json:"pairedSamples"`
	PairedMedianNS    *int64  `json:"pairedDifferenceMedianNs"`
	PairedLowerNS     *int64  `json:"pairedDifferenceLowerNs"`
	PairedUpperNS     *int64  `json:"pairedDifferenceUpperNs"`
	Confidence        float64 `json:"confidence"`
}

// Envelope provides corruption detection, not authentication or a signature.
type Envelope struct {
	SHA256 string `json:"sha256"`
	Report Report `json:"report"`
}

// CrossPortStudy combines separately executed precondition experiments
// (HZ-003/HZ-004) against one target. A candidate is never a topology claim.
type CrossPortStudy struct {
	Version                string       `json:"version"`
	Target                 string       `json:"target"`
	Roles                  []RoleEffect `json:"roles"`
	Classification         string       `json:"classification"`
	IsolatedClassification string       `json:"isolatedClassification"`
	Reasons                []string     `json:"reasons"`
	Candidates             []Candidate  `json:"candidates"`
	Limitations            []string     `json:"limitations"`
}

// RoleEffect is one experiment's measurement-probe effect. Rates are the
// share of complete pairs whose measurement was answered, with two-sided 95%
// Clopper-Pearson intervals that assume independent pairs.
type RoleEffect struct {
	Role              string   `json:"role"`
	RunID             string   `json:"runId"`
	ExperimentHash    string   `json:"experimentHash"`
	PreconditionPorts []uint16 `json:"preconditionPorts"`
	MeasurementPort   uint16   `json:"measurementPort"`
	MatchedWaitMS     int      `json:"matchedWaitMs"`
	Status            string   `json:"status"`
	Conclusion        string   `json:"conclusion"`
	CompletePairs     int      `json:"completePairs"`
	Suppressed        int      `json:"suppressed"`
	Enabled           int      `json:"enabled"`
	PValue            float64  `json:"pValue"`
	Significant       bool     `json:"significant"`
	ControlAnswered   Interval `json:"controlAnswered"`
	TreatmentAnswered Interval `json:"treatmentAnswered"`
	PreconditionTTLs  []uint8  `json:"preconditionTtls"`
	MeasurementTTLs   []uint8  `json:"measurementTtls"`
}
type Interval struct {
	Estimate float64 `json:"estimate"`
	Lower    float64 `json:"lower"`
	Upper    float64 `json:"upper"`
}
type Candidate struct {
	ID                string       `json:"id"`
	Type              string       `json:"type"`
	Status            string       `json:"status"`
	Subjects          []string     `json:"subjects"`
	Direction         string       `json:"direction"`
	Evidence          []string     `json:"evidence"`
	Alternatives      []string     `json:"alternatives"`
	OrthogonalSignals []string     `json:"orthogonalSignals"`
	Hypotheses        []Hypothesis `json:"hypotheses"`
}

// Hypothesis is an infrastructure explanation. It stays not-elevated unless
// an orthogonal signal supports it; probability is null until calibrated.
type Hypothesis struct {
	Family      string   `json:"family"`
	Status      string   `json:"status"`
	Location    string   `json:"location,omitempty"`
	Probability *float64 `json:"probability"`
	Reason      string   `json:"reason"`
}

const GraphVersion = "horizon.nyxr.io/graph/v1"

// Graph is a provenance-aware projection of replayed reports. Observation
// quality (how good the evidence is) is kept apart from hypothesis status
// (what it supports); no numeric probability is published until calibrated.
type Graph struct {
	APIVersion     string            `json:"apiVersion"`
	Kind           string            `json:"kind"`
	GeneratedAt    time.Time         `json:"generatedAt"`
	TTLSeconds     int64             `json:"ttlSeconds"`
	Coverage       GraphCoverage     `json:"coverage"`
	Nodes          []GraphNode       `json:"nodes"`
	Edges          []GraphEdge       `json:"edges"`
	Quality        []RunQuality      `json:"observationQuality"`
	Hypotheses     []GraphHypothesis `json:"hypotheses"`
	Contradictions []Contradiction   `json:"contradictions"`
	Changes        []ChangeEvent     `json:"changes"`
	NotEvaluated   []string          `json:"notEvaluated"`
	Limitations    []string          `json:"limitations"`
}
type GraphCoverage struct {
	TestedTCPPorts  []string `json:"testedTcpPorts"`
	FullTCPCoverage bool     `json:"fullTcpCoverage"`
}
type GraphNode struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Statement  string            `json:"statement,omitempty"` // observed, inferred, hypothesis or unresolved
	Attributes map[string]string `json:"attributes,omitempty"`
}
type GraphEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"`
}

// RunQuality grades evidence, independent of what it is evidence for.
type RunQuality struct {
	Run        string    `json:"run"`
	Grade      string    `json:"grade"` // good, degraded or poor
	Reasons    []string  `json:"reasons"`
	ObservedAt time.Time `json:"observedAt"`
}
type GraphHypothesis struct {
	ID                string    `json:"id"`
	Family            string    `json:"family"`
	Subject           string    `json:"subject"`
	Statement         string    `json:"statement"`
	Status            string    `json:"status"` // supported, not-supported, unresolved or stale
	Location          string    `json:"location,omitempty"`
	ObservationGrade  string    `json:"observationGrade"`
	Probability       *float64  `json:"probability"`
	ProbabilityMethod string    `json:"probabilityMethod"`
	Support           []string  `json:"support"`
	Against           []string  `json:"against"`
	Alternatives      []string  `json:"alternatives"`
	Assumptions       []string  `json:"assumptions"`
	Reasons           []string  `json:"reasons"`
	ObservedAt        time.Time `json:"observedAt"`
	ValidUntil        time.Time `json:"validUntil"`
}
type Contradiction struct {
	Subject string   `json:"subject"`
	Family  string   `json:"family"`
	Runs    []string `json:"runs"`
	Detail  string   `json:"detail"`
}

// ChangeEvent invalidates hypotheses observed before it for its scope.
type ChangeEvent struct {
	At     time.Time `json:"at"`
	Scope  string    `json:"scope"`  // host:<address> or network
	Source string    `json:"source"` // declared or detected
	Detail string    `json:"detail"`
}

const AdaptiveVersion = "horizon.nyxr.io/adaptive/v1"

// AdaptiveStudy records a budgeted, sequentially chosen cross-port study:
// every candidate the planner weighed, why it stopped and, for each statement
// and port, whether it was tested now, inferred from a profile or not tested.
type AdaptiveStudy struct {
	APIVersion  string              `json:"apiVersion"`
	Kind        string              `json:"kind"`
	Task        AdaptiveTask        `json:"task"`
	Budget      Budget              `json:"budget"`
	Spent       Budget              `json:"spent"`
	Steps       []AdaptiveStep      `json:"steps"`
	StopReason  string              `json:"stopReason"` // sufficient, budget, indistinguishable, model-inconsistent, main-unresolved or full-coverage
	StopDetail  string              `json:"stopDetail"`
	Consistent  []string            `json:"consistentHypotheses"`
	Study       CrossPortStudy      `json:"study"`
	Statements  []CoverageStatement `json:"statements"`
	Ports       []PortCoverage      `json:"ports"`
	Profile     *ProfileCheck       `json:"profile,omitempty"`
	Limitations []string            `json:"limitations"`
}

// AdaptiveTask is what the planner must resolve. The cross-port classification
// is always resolved; Refine adds "direction" and/or "cooldown".
type AdaptiveTask struct {
	Refine       []string `json:"refine"`
	Require      []string `json:"require"`
	FullCoverage bool     `json:"fullCoverage"`
	// LambdaBitsPerPacket trades expected information against packet cost.
	LambdaBitsPerPacket float64 `json:"lambdaBitsPerPacket"`
}

// Budget bounds packets and wall time; zero means unlimited for that axis.
type Budget struct {
	Packets    int   `json:"packets"`
	DurationMS int64 `json:"durationMs"`
}
type AdaptiveStep struct {
	Role       string      `json:"role"`
	Candidates []RoleScore `json:"candidates"`
	Outcome    string      `json:"outcome"` // dependence, no-dependence or unresolved
	RunID      string      `json:"runId"`
	Packets    int         `json:"packets"`
	DurationMS int64       `json:"durationMs"`
	Curtailed  bool        `json:"curtailed"`
	Consistent []string    `json:"consistentHypotheses"`
}

// RoleScore is one candidate experiment: expected information about the task
// (bits, under the declared prior), its worst-case cost and the net score.
type RoleScore struct {
	Role          string  `json:"role"`
	GainBits      float64 `json:"gainBits"`
	MaxPackets    int     `json:"maxPackets"`
	MaxDurationMS int64   `json:"maxDurationMs"`
	Score         float64 `json:"score"`
	Excluded      string  `json:"excluded,omitempty"`
}

// CoverageStatement is tested, profile-inferred or not-tested.
type CoverageStatement struct {
	Statement string   `json:"statement"`
	Value     string   `json:"value"`
	Coverage  string   `json:"coverage"`
	Evidence  []string `json:"evidence"`
}
type PortCoverage struct {
	Port     string   `json:"port"`
	Coverage string   `json:"coverage"`
	Roles    []string `json:"roles"`
}

const ProfileVersion = "horizon.nyxr.io/profile/v1"

// BehaviorProfile is a versioned, expiring summary of a validated cross-port
// study against one target from one vantage point. It is a prediction to be
// checked, never a substitute for tests in full-coverage mode.
type BehaviorProfile struct {
	APIVersion     string       `json:"apiVersion"`
	Kind           string       `json:"kind"`
	ID             string       `json:"id"`
	Class          string       `json:"class"`
	Target         string       `json:"target"`
	CreatedAt      time.Time    `json:"createdAt"`
	EvidenceFrom   time.Time    `json:"evidenceFrom"` // earliest run start
	ValidUntil     time.Time    `json:"validUntil"`
	Vantage        Vantage      `json:"vantage"`
	Fingerprint    Fingerprint  `json:"fingerprint"`
	Classification string       `json:"classification"`
	Direction      string       `json:"direction"`
	Cooldown       string       `json:"cooldown"`
	Subjects       []string     `json:"subjects"`
	Hypotheses     []Hypothesis `json:"hypotheses"`
	Evidence       []string     `json:"evidence"`
}
type Vantage struct {
	SourceIP           string `json:"sourceIp"`
	Backend            string `json:"backend"`
	CorrelationVersion string `json:"correlationVersion"`
}

// Fingerprint is what the target itself replied with: reply TTLs (hop
// distance) and the non-SACK TCP option layout of its SYN/ACKs.
type Fingerprint struct {
	ReplyTTLs []int  `json:"replyTtls"`
	Options   string `json:"options"`
}
type ProfileCheck struct {
	ProfileID string   `json:"profileId"`
	Valid     bool     `json:"valid"`
	Reasons   []string `json:"reasons"`
}

const RunVersion = "horizon.nyxr.io/run/v1"

// RunStatus is the API resource for one HORIZON run.
type RunStatus struct {
	APIVersion     string       `json:"apiVersion"`
	Kind           string       `json:"kind"`
	ID             string       `json:"id"`
	Mode           string       `json:"mode"`
	State          string       `json:"state"` // running, completed, cancelled, stopped or failed
	Experiment     string       `json:"experiment"`
	ExperimentHash string       `json:"experimentHash"`
	Target         string       `json:"target"`
	Ports          []uint16     `json:"ports"`
	CreatedAt      time.Time    `json:"createdAt"`
	FinishedAt     *time.Time   `json:"finishedAt"`
	PacketsTX      int          `json:"packetsTx"`
	Trials         int          `json:"trials"`
	StopReason     string       `json:"stopReason,omitempty"`
	Error          string       `json:"error,omitempty"`
	Comparison     *Comparison  `json:"comparison,omitempty"`
	Curtailment    *Curtailment `json:"curtailment,omitempty"`
	ReportSHA256   string       `json:"reportSha256,omitempty"`
}
