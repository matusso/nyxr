package horizon

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/observe"
)

func TestReferencesReuseSealedHORIZONArtifact(t *testing.T) {
	sim, err := NewSimulator("loss")
	if err != nil {
		t.Fatal(err)
	}
	defer sim.Close()
	report, err := Run(context.Background(), testExperiment(t), testPolicy(), testLink(), sim)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Seal(report)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := json.MarshalIndent(envelope, "", "  ")
	refs, err := ImportReferences(bytes.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	if refs.Source.ArtifactID != observe.ArtifactID(source) || refs.Source.RunID != report.RunID || refs.ExperimentHash != report.ExperimentHash || len(refs.Trials) != len(report.Trials) || refs.ClaimStatus != "unknown" {
		t.Fatalf("provenance lost: %+v", refs)
	}
	for i, trial := range refs.Trials {
		if trial.FlowID != report.Trials[i].FlowID || trial.Pair != report.Trials[i].Pair || trial.Arm != report.Trials[i].Arm {
			t.Fatal("trial provenance lost")
		}
		for j, ref := range trial.Evidence {
			value, err := ResolveReference(source, ref)
			if err != nil {
				t.Fatal(err)
			}
			var evidence model.Evidence
			if err := json.Unmarshal(value, &evidence); err != nil || !bytes.Equal(evidence.Frame, report.Trials[i].Evidence[j].Frame) {
				t.Fatal("frame reference changed")
			}
		}
	}
	ref := refs.Source
	ref.RunID = "wrong-run"
	if _, err := ResolveReference(source, ref); err == nil {
		t.Fatal("wrong run accepted")
	}
	if _, err := ResolveReference(append(source, '\n'), refs.Source); err == nil {
		t.Fatal("different container accepted")
	}
	envelope.Report.RunID = "altered"
	corrupted, _ := json.Marshal(envelope)
	if _, err := ImportReferences(bytes.NewReader(corrupted)); err == nil {
		t.Fatal("adapter bypassed replay validation")
	}
}
