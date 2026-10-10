package observe

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

func TestSourceIdentityRoundTripAndMutation(t *testing.T) {
	o := Observation{ID: "run/1", ScanID: "run", Timestamp: time.Now().UTC(), Target: netip.MustParseAddr("192.0.2.1"),
		Kind: KindService, Fingerprint: FingerprintUnknown, Evidence: []Evidence{{Probe: "banner", Layer: "tcp", Response: []byte{0, 1, 255}, Truncated: true}}}
	source, err := o.Seal()
	if err != nil {
		t.Fatal(err)
	}
	retry, err := o.Seal()
	if err != nil || !bytes.Equal(retry, source) {
		t.Fatalf("unstable sealing: %v", err)
	}
	b, _ := json.Marshal(o)
	var delivered Observation
	if err := json.Unmarshal(b, &delivered); err != nil {
		t.Fatal(err)
	}
	regenerated, err := delivered.Seal()
	if err != nil || !bytes.Equal(regenerated, source) {
		t.Fatalf("stream source mapping: %v", err)
	}
	ev := delivered.Evidence[0]
	value, err := ResolveSource(source, *ev.Source)
	if err != nil {
		t.Fatal(err)
	}
	var exchange Evidence
	if err := json.Unmarshal(value, &exchange); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(exchange.Response, []byte{0, 1, 255}) || ev.ClaimStatus != "unknown" || ev.Completeness != "partial" || ev.ParserVersion != ParserVersion {
		t.Fatalf("evidence metadata lost: %+v", ev)
	}
	ref := *ev.Source
	ref.Pointer = "/evidence/1"
	if _, err := ResolveSource(source, ref); err == nil {
		t.Fatal("out-of-range evidence accepted")
	}
	if _, err := ResolveSource(append(source, '\n'), *ev.Source); err == nil {
		t.Fatal("changed container accepted")
	}
	delivered.Evidence[0].Response[0] = 9
	if _, err := delivered.Seal(); err == nil {
		t.Fatal("changed sealed measurement accepted")
	}
	o.Source, o.Evidence[0].Source = nil, nil
	o.ID = "run/2"
	other, err := o.Seal()
	if err != nil || ArtifactID(other) == ArtifactID(source) {
		t.Fatal("distinct occurrence reused a reference")
	}
}

func TestJSONPointerEscapesAndValidation(t *testing.T) {
	b := []byte(`{"a/b":{"~":[42]}}`)
	r := SourceRef{Owner: "next-gen", SourceSchema: SchemaVersion, ArtifactID: ArtifactID(b), Pointer: "/a~1b/~0/0"}
	value, err := ResolveSource(b, r)
	if err != nil || string(value) != "42" {
		t.Fatalf("RFC 6901: %s %v", value, err)
	}
	for _, pointer := range []string{"not-a-pointer", "/a~", "/a~2b", "/a~1b/~0/00", "/a~1b/~0/-1", "/a~1b/~0/0/extra"} {
		r.Pointer = pointer
		if _, err := ResolveSource(b, r); err == nil {
			t.Fatalf("bad pointer accepted: %q", pointer)
		}
	}
}

func FuzzSourceReference(f *testing.F) {
	f.Add([]byte(`{"evidence":[{"response":"AA=="}]}`), "/evidence/0")
	f.Add([]byte("  "), "/x")
	f.Fuzz(func(t *testing.T, b []byte, pointer string) {
		if len(b) > 64<<10 || len(pointer) > 1024 {
			return
		}
		_, _ = ResolveSource(b, SourceRef{Owner: "next-gen", SourceSchema: SchemaVersion, ArtifactID: ArtifactID(b), Pointer: pointer})
	})
}

func TestOptionalSourceFieldsDoNotChangeRetainedIdentity(t *testing.T) {
	source := []byte(`{"schema":"nyxr/v1","kind":"service","observation_id":"run/1","scan_id":"run","evidence":[{"probe":"future","future_field":42}],"future_metadata":{"x":1}}`)
	o, err := ReadSource(source, ArtifactID(source))
	if err != nil {
		t.Fatal(err)
	}
	if o.Source.ArtifactID != ArtifactID(source) || o.Evidence[0].Source.ArtifactID != ArtifactID(source) {
		t.Fatal("unknown v1 fields changed source mapping")
	}
	if _, err := ResolveSource(source, *o.Evidence[0].Source); err != nil {
		t.Fatal(err)
	}
}
