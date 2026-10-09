package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/scan"
	"github.com/matusso/nyxr/internal/storage"
)

func TestCancelledFullBatchRetainsEquivalentStreamAndHistory(t *testing.T) {
	r, err := (config.Request{Targets: []string{"192.0.2.1"}, Ports: "9999", Protocols: "udp", Profile: "udp-basic"}).Resolve(config.ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store, err := storage.Open(ctx, filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var out bytes.Buffer
	sink := NewStoreSink(ctx, store)
	opts := FromResolved(r)
	opts.Sinks = []Sink{NewJSONSink(&out), sink}
	opts.Discover = func(_ context.Context, _ config.Config, emit func(scan.Observation) error) error {
		for i := 0; i < 300; i++ {
			if i == 250 {
				cancel()
			}
			if err := emit(scan.Observation{Timestamp: time.Unix(1, 0).UTC(), Target: r.Config.Targets[0], Transport: "udp", Port: 9999, State: "open", Evidence: []observe.Evidence{{Probe: "unknown", Layer: "udp", Response: []byte{0, 255}}}}); err != nil {
				return err
			}
			if len(sink.batch) >= 256 {
				t.Fatal("store batch exceeded its bound")
			}
		}
		return context.Canceled
	}
	sc, err := Run(ctx, r.Config, opts)
	if !errors.Is(err, context.Canceled) || sc.Observations != 300 || sc.Status != "failed" {
		t.Fatalf("partial scan: %+v %v", sc, err)
	}
	stored, err := store.Observations(context.Background(), storage.Filter{ScanID: sc.ID})
	if err != nil || len(stored) != 300 {
		t.Fatalf("cancelled batch lost: %d %v", len(stored), err)
	}
	d := json.NewDecoder(&out)
	for i := 0; i < 300; i++ {
		var o observe.Observation
		if err := d.Decode(&o); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(o, stored[i]) {
			t.Fatalf("stream/history record %d diverged", i)
		}
		if i > 0 && o.Source.ArtifactID == stored[i-1].Source.ArtifactID {
			t.Fatal("distinct occurrence alias")
		}
		r, err := store.ResolveSource(context.Background(), *o.Evidence[0].Source)
		if err != nil || r.Status != "available" {
			t.Fatalf("unresolvable partial exchange: %+v %v", r, err)
		}
	}
	var final observe.Scan
	if err := d.Decode(&final); err != nil || final != sc {
		t.Fatalf("final summary: %+v %v", final, err)
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		t.Fatal("unexpected trailing stream")
	}
}
