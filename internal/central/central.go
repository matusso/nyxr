// Package central consolidates evidence from many nyxr databases into one
// controller store. Each source database is a lineage, named by its identity
// namespace: a standalone scanner, or a fleet controller whose agents
// delivered results through it. Lineages keep their own SQLite stores and
// resolvers; the central store ingests their sealed observation sources
// idempotently, keeps provenance and time quality, holds large evidence
// artifacts in object storage, and reconciles identities across lineages.
//
// Reconciliation is conservative. Only scoped identifiers (cloud instance IDs
// qualified by account, subscription or project, and Kubernetes node UIDs
// qualified by cluster) join local identities from different lineages.
// Device-scoped values such as SSH host keys, SMB GUIDs, SNMP engine IDs and
// MACs join addresses inside their own lineage, where the local resolver
// applied them, but across lineages they are only clues: images clone keys
// and MACs are link-local. Clues, conflicts, manual separations and joins
// are kept, every membership change is audited, and every manual decision
// can be reverted.
//
// The same SQL runs on SQLite (standalone, single host) and PostgreSQL
// (shared controller storage).
package central

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// Store is the controller storage interface. DB implements it on SQLite and
// PostgreSQL.
type Store interface {
	// Ingest applies one batch from a lineage. It is idempotent: replaying a
	// batch, or delivering its parts in another order, converges to the same
	// state.
	Ingest(ctx context.Context, b Batch) (IngestResult, error)
	Lineages(ctx context.Context) ([]Lineage, error)

	// PutArtifact stores bytes whose SHA-256 must match ref.ID when set.
	PutArtifact(ctx context.Context, ref ArtifactRef, r io.Reader) (Artifact, error)
	OpenArtifact(ctx context.Context, id string, grant Grant) (io.ReadCloser, Artifact, error)
	Artifacts(ctx context.Context, state string, limit int) ([]Artifact, error)
	PruneArtifacts(ctx context.Context, now time.Time) (int, error)

	Entities(ctx context.Context) ([]Entity, error)
	Relations(ctx context.Context) ([]Relation, error)
	Conflicts(ctx context.Context) ([]Conflict, error)
	Decide(ctx context.Context, d Decision) (DecisionRecord, error)
	Revert(ctx context.Context, id int64, note, actor string, expect []EntityVersion) (DecisionRecord, error)
	Decisions(ctx context.Context) ([]DecisionRecord, error)
	History(ctx context.Context, node string) ([]Event, error)

	Export(ctx context.Context, w io.Writer) error
	Restore(ctx context.Context, r io.Reader) error
	SchemaVersion(ctx context.Context) (int, error)
	Close() error
}

var (
	// ErrStaleRevision means an entity changed since the caller read it.
	ErrStaleRevision = errors.New("entity revision changed; reload and retry")
	// ErrArtifactUnavailable means an artifact is referenced but its bytes
	// are not stored: not uploaded yet, missing from object storage, or
	// expired by retention.
	ErrArtifactUnavailable = errors.New("artifact is not available")
	// ErrAccessDenied means the artifact's access policy exceeds the grant.
	ErrAccessDenied = errors.New("artifact access policy denies this read")
	// ErrNotEmpty means a restore target already holds data.
	ErrNotEmpty = errors.New("restore target is not empty")
)

// Lineage kinds.
const (
	LineageStandalone = "standalone"
	LineageController = "controller"
)

// Time quality of an observation timestamp.
const (
	// TimeLocalClock is a scanner's own clock; nothing measured its sync.
	TimeLocalClock = "local_clock"
	// TimeAgentCorrected is an agent clock corrected by the offset its
	// controller measured, which was within MaxClockSkew.
	TimeAgentCorrected = "agent_offset_corrected"
	// TimeAgentSkewed is corrected too, but the measured offset exceeded
	// MaxClockSkew, so ordering against other agents is doubtful.
	TimeAgentSkewed = "agent_skewed"
)

// MaxClockSkew matches the fleet controller's clock skew warning.
const MaxClockSkew = 5 * time.Second

// Bounds on ingested input.
const (
	MaxSourceBytes     = 1 << 20 // one sealed observation
	MaxBatchRecords    = 10000
	DefaultMaxArtifact = 4 << 30
)

// Lineage is one source database known to the central store.
type Lineage struct {
	Namespace     string    `json:"namespace"`
	Kind          string    `json:"kind"`
	Label         string    `json:"label,omitempty"`
	FirstIngested time.Time `json:"first_ingested"`
	LastIngested  time.Time `json:"last_ingested"`
	// Cursor is the highest source row whose batch was applied.
	Cursor int64 `json:"cursor"`
	// MemberRevision is the source revision of the applied membership.
	MemberRevision int64 `json:"member_revision"`
	Observations   int64 `json:"observations"`
}

// ObservationRecord is one sealed observation with its delivery provenance.
type ObservationRecord struct {
	// ArtifactID is "sha256:<hex>" of Source and the idempotency key.
	ArtifactID string `json:"artifact_id"`
	Source     []byte `json:"source"`
	AgentID    string `json:"agent_id,omitempty"`
	LeaseID    string `json:"lease_id,omitempty"`
	JobID      string `json:"job_id,omitempty"`
	Attempt    int    `json:"attempt,omitempty"`
	// Fleet marks a measured ClockOffset (agent minus controller clock).
	Fleet       bool          `json:"fleet,omitempty"`
	ClockOffset time.Duration `json:"clock_offset_ns,omitempty"`
}

// ScanRecord is a scan summary. A finished summary replaces a running one;
// a running one never replaces a finished one, whatever the arrival order.
type ScanRecord struct {
	Scan    observe.Scan `json:"scan"`
	AgentID string       `json:"agent_id,omitempty"`
}

// MemberSnapshot is the lineage's local membership at Revision.
type MemberSnapshot struct {
	Revision int64                 `json:"revision"`
	Members  map[netip.Addr]string `json:"members"`
}

// Batch is one ingestion unit from one lineage.
type Batch struct {
	Lineage      string              `json:"lineage"`
	Kind         string              `json:"kind,omitempty"`
	Label        string              `json:"label,omitempty"`
	Scans        []ScanRecord        `json:"scans,omitempty"`
	Observations []ObservationRecord `json:"observations,omitempty"`
	Artifacts    []ArtifactRef       `json:"artifacts,omitempty"`
	Members      *MemberSnapshot     `json:"members,omitempty"`
	// Cursor is the highest source row this batch covers; the lineage
	// cursor only moves forward.
	Cursor int64 `json:"cursor,omitempty"`
}

// IngestResult counts what a batch changed.
type IngestResult struct {
	Observations int `json:"observations"`
	Duplicates   int `json:"duplicates"`
	// Conflicts are records reusing a stored observation ID with different
	// bytes. They are kept in ingest_conflicts, never overwrite.
	Conflicts      int   `json:"conflicts"`
	Scans          int   `json:"scans"`
	Artifacts      int   `json:"artifacts"`
	MembersApplied bool  `json:"members_applied"`
	Moved          int   `json:"moved"`
	Revision       int64 `json:"revision"`
}

// Artifact access policies.
const (
	// AccessInternal artifacts are readable by any central reader.
	AccessInternal = "internal"
	// AccessRestricted artifacts (packet payloads, credentials-adjacent
	// evidence) need an explicit grant.
	AccessRestricted = "restricted"
)

// Artifact states.
const (
	ArtifactPending   = "pending"   // referenced, bytes not uploaded yet
	ArtifactAvailable = "available" // bytes stored and verified
	ArtifactMissing   = "missing"   // registered but the object is gone
	ArtifactExpired   = "expired"   // deleted by retention; metadata kept
)

// ArtifactRef registers an artifact, with or without its bytes.
type ArtifactRef struct {
	ID        string `json:"artifact_id,omitempty"`
	Kind      string `json:"kind"`
	MediaType string `json:"media_type,omitempty"`
	Size      int64  `json:"size,omitempty"`
	Lineage   string `json:"lineage,omitempty"`
	ScanID    string `json:"scan_id,omitempty"`
	AgentID   string `json:"agent_id,omitempty"`
	Access    string `json:"access,omitempty"`
	// RetainUntil is when retention may delete the bytes; zero keeps them.
	RetainUntil time.Time `json:"retain_until,omitzero"`
}

// Artifact is a registered artifact.
type Artifact struct {
	ArtifactRef
	State      string    `json:"state"`
	ObjectKey  string    `json:"object_key,omitempty"`
	Registered time.Time `json:"registered"`
	Stored     time.Time `json:"stored,omitzero"`
}

// Grant is what an artifact reader is allowed to see.
type Grant struct{ Restricted bool }

// Node is one local identity of one lineage, the unit central reconciliation
// moves. An address the lineage has not reported membership for is its own
// provisional node.
type Node struct {
	Key       string       `json:"node"`
	Lineage   string       `json:"lineage"`
	Addresses []netip.Addr `json:"addresses"`
}

// Entity is a reconciled cross-lineage asset.
type Entity struct {
	ID          string    `json:"id"`
	GlobalID    string    `json:"global_id"`
	Revision    int64     `json:"revision"`
	Updated     time.Time `json:"updated"`
	Nodes       []Node    `json:"nodes"`
	PortableIDs []string  `json:"portable_ids"`
	// Link says why nodes share this entity: "single", "scoped_signal",
	// "manual" or "scoped_signal+manual". All of these are inferred from
	// observed signals or operator decisions, never observed directly.
	Link string `json:"link"`
}

// EntityVersion pins an entity revision for optimistic concurrency.
type EntityVersion struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
}

// Relation is an ambiguous clue shared by several entities. It never changes
// membership.
type Relation struct {
	Kind     string   `json:"kind"`
	Value    string   `json:"value"`
	Strength string   `json:"strength"` // "device" (unscoped strong) or "weak"
	Entities []string `json:"entities"`
}

// Conflict is a join reconciliation refused or a contradiction it kept.
type Conflict struct {
	Reason string `json:"reason"`
	Kind   string `json:"kind,omitempty"`
	NodeA  string `json:"node_a"`
	NodeB  string `json:"node_b"`
	ValueA string `json:"value_a,omitempty"`
	ValueB string `json:"value_b,omitempty"`
}

// Decision actions.
const (
	DecisionJoin     = "join"
	DecisionSeparate = "separate"
	DecisionRevert   = "revert"
)

// Decision is an operator review of two nodes.
type Decision struct {
	Action string `json:"action"`
	NodeA  string `json:"node_a"`
	NodeB  string `json:"node_b"`
	Note   string `json:"note"`
	Actor  string `json:"actor,omitempty"`
	// Expect, when set, must match the current entity revisions.
	Expect []EntityVersion `json:"expect,omitempty"`
}

// DecisionRecord is a stored decision.
type DecisionRecord struct {
	ID         int64     `json:"id"`
	Action     string    `json:"action"`
	NodeA      string    `json:"node_a,omitempty"`
	NodeB      string    `json:"node_b,omitempty"`
	Target     int64     `json:"target,omitempty"`
	Note       string    `json:"note"`
	Actor      string    `json:"actor,omitempty"`
	DecidedAt  time.Time `json:"decided_at"`
	RevertedBy int64     `json:"reverted_by,omitempty"`
	Moved      int       `json:"moved"`
}

// Event is one audited membership change of a node.
type Event struct {
	ID         int64     `json:"id"`
	Node       string    `json:"node"`
	FromEntity string    `json:"from_entity,omitempty"`
	ToEntity   string    `json:"to_entity"`
	Cause      string    `json:"cause"`
	Decision   int64     `json:"decision,omitempty"`
	Revision   int64     `json:"revision"`
	At         time.Time `json:"at"`
}
