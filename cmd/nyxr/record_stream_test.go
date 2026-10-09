package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/ui"
)

func TestPlainNoDBDiscoveryUsesVersionedStream(t *testing.T) {
	port := closedPort(t)
	var output bytes.Buffer
	if err := runScan([]string{"--no-db", "--json", "--ports", fmt.Sprint(port), "--rate", "0", "127.0.0.1"}, &output, ui.Plain(), progressOptions{}); err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(&output)
	var o observe.Observation
	if err := d.Decode(&o); err != nil {
		t.Fatal(err)
	}
	if o.Schema != observe.SchemaVersion || o.Kind != observe.KindPort || o.ScanID == "" || o.Source == nil || o.ID == "" || o.State != "closed" {
		t.Fatalf("legacy discovery path: %+v", o)
	}
	// A no-db consumer can export this immutable source mapping itself.
	source, err := o.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observe.ResolveSource(source, *o.Source); err != nil {
		t.Fatal(err)
	}
	var sc observe.Scan
	if err := d.Decode(&sc); err != nil || sc.ID != o.ScanID || sc.Kind != observe.KindScan || sc.Status != "completed" || sc.Observations != 1 {
		t.Fatalf("missing discovery summary: %+v %v", sc, err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		t.Fatal("extra records after scan summary")
	}
}
