package horizon

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/observe"
)

// ReportReferences is a reference-only adapter. It does not copy captures,
// recalculate a graph or promote experiment hypotheses into inventory claims.
type ReportReferences struct {
	CaptureArtifact *model.CaptureArtifact `json:"capture_artifact,omitempty"`
	Schema          string                 `json:"schema"`
	Kind            string                 `json:"kind"`
	Source          observe.SourceRef      `json:"source"`
	Experiment      observe.SourceRef      `json:"experiment"`
	ExperimentHash  string                 `json:"experiment_hash"`
	ClaimStatus     string                 `json:"claim_status"`
	Completed       bool                   `json:"completed"`
	Trials          []TrialReferences      `json:"trials"`
}

type TrialReferences struct {
	Packets      []PacketReference   `json:"packets,omitempty"`
	Probe        int                 `json:"probe,omitempty"`
	Source       observe.SourceRef   `json:"source"`
	Pair         int                 `json:"pair"`
	Arm          string              `json:"arm"`
	FlowID       string              `json:"flow_id"`
	ClaimStatus  string              `json:"claim_status"`
	QualityFlags []string            `json:"quality_flags,omitempty"`
	Evidence     []observe.SourceRef `json:"evidence"`
}

type PacketReference struct {
	ArtifactID string            `json:"artifact_id"`
	PacketID   uint64            `json:"packet_id"`
	Source     observe.SourceRef `json:"source"`
}

// ImportReferences validates the existing sealed report with Replay, then
// references its exact original bytes. Callers must retain the input envelope
// unchanged; Replay's re-encoded output is a different source container.
// This offline adapter adds no live experiment capabilities or API admission.
func ImportReferences(reader io.Reader) (ReportReferences, error) {
	b, err := io.ReadAll(io.LimitReader(reader, (24<<20)+1))
	if err != nil {
		return ReportReferences{}, err
	}
	if len(b) > 24<<20 {
		return ReportReferences{}, errors.New("report exceeds 24 MiB")
	}
	envelope, err := Replay(bytes.NewReader(b))
	if err != nil {
		return ReportReferences{}, err
	}
	r := envelope.Report
	if r.RunID == "" {
		return ReportReferences{}, errors.New("report has no run ID")
	}
	ref := observe.SourceRef{Owner: "horizon", SourceSchema: r.APIVersion, ArtifactID: observe.ArtifactID(b), Pointer: "/report", RunID: r.RunID}
	result := ReportReferences{Schema: observe.SchemaVersion, Kind: observe.KindExperimentReference, Source: ref, Experiment: ref,
		CaptureArtifact: r.CaptureArtifact,
		ExperimentHash:  r.ExperimentHash, ClaimStatus: r.Comparison.Status, Completed: r.Completed,
		Trials: make([]TrialReferences, 0, len(r.Trials))}
	if result.ClaimStatus != "inferred" {
		result.ClaimStatus = "unknown"
	}
	result.Experiment.Pointer = "/report/experiment"
	for i, trial := range r.Trials {
		t := TrialReferences{Source: ref, Probe: trial.Probe, Pair: trial.Pair, Arm: trial.Arm, FlowID: trial.FlowID, ClaimStatus: "unknown",
			QualityFlags: trial.QualityFlags, Evidence: make([]observe.SourceRef, 0, len(trial.Evidence))}
		for _, evidence := range trial.Evidence {
			if evidence.Direction == "rx" {
				t.ClaimStatus = "observed"
				break
			}
		}
		t.Source.Pointer = fmt.Sprintf("/report/trials/%d", i)
		for j := range trial.Evidence {
			e := ref
			e.Pointer = fmt.Sprintf("/report/trials/%d/evidence/%d", i, j)
			t.Evidence = append(t.Evidence, e)
			if trial.Evidence[j].PacketID != 0 && r.CaptureArtifact != nil {
				t.Packets = append(t.Packets, PacketReference{ArtifactID: r.CaptureArtifact.ArtifactID, PacketID: trial.Evidence[j].PacketID, Source: e})
			}
		}
		result.Trials = append(result.Trials, t)
	}
	return result, nil
}

// ResolveReference reuses HORIZON validation before resolving any source
// pointer. Raw evidence stays owned by the original sealed envelope.
func ResolveReference(source []byte, ref observe.SourceRef) ([]byte, error) {
	if ref.Owner != "horizon" || (ref.SourceSchema != model.Version && ref.SourceSchema != model.GeneralVersion) {
		return nil, errors.New("unsupported HORIZON reference")
	}
	r, err := ImportReferences(bytes.NewReader(source))
	if err != nil {
		return nil, err
	}
	if ref.RunID != r.Source.RunID || ref.SourceSchema != r.Source.SourceSchema {
		return nil, errors.New("HORIZON run provenance mismatch")
	}
	return observe.ResolveSource(source, ref)
}
