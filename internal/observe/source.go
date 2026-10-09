package observe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ParserVersion identifies the native interpretation contract, independently
// of the wire schema. Imported historical records use "unknown".
const ParserVersion = "nyxr-parser/v1"

// SourceRef identifies exact retained JSON bytes and an RFC 6901 pointer.
// A filename, IP, timestamp or payload hash alone cannot identify a measurement.
type SourceRef struct {
	Owner        string `json:"owner"`
	SourceSchema string `json:"sourceSchema"`
	ArtifactID   string `json:"artifactID"`
	Pointer      string `json:"pointer"`
	RunID        string `json:"runID,omitempty"`
}

func ArtifactID(source []byte) string {
	h := sha256.Sum256(source)
	return "sha256:" + hex.EncodeToString(h[:])
}

func (r SourceRef) Validate() error {
	if (r.Owner != "next-gen" && r.Owner != "horizon") || r.SourceSchema == "" {
		return errors.New("unsupported source owner or missing schema")
	}
	h := strings.TrimPrefix(r.ArtifactID, "sha256:")
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 || r.ArtifactID != "sha256:"+hex.EncodeToString(b) {
		return errors.New("source artifact ID must be sha256:<64 lowercase hex digits>")
	}
	_, err = pointerTokens(r.Pointer)
	return err
}

// ResolveSource verifies container identity before dereferencing. Reformatting
// or redacting source bytes produces a different artifact, even for equal JSON.
func ResolveSource(source []byte, ref SourceRef) (json.RawMessage, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	if ArtifactID(source) != ref.ArtifactID {
		return nil, errors.New("source artifact hash mismatch")
	}
	if !json.Valid(source) {
		return nil, errors.New("source is not JSON")
	}
	tokens, err := pointerTokens(ref.Pointer)
	if err != nil {
		return nil, err
	}
	var value json.RawMessage = source
	for _, token := range tokens {
		if len(value) == 0 {
			return nil, errors.New("source pointer unavailable")
		}
		trimmed := strings.TrimSpace(string(value))
		switch trimmed[0] {
		case '{':
			var object map[string]json.RawMessage
			if err := json.Unmarshal(value, &object); err != nil {
				return nil, err
			}
			var ok bool
			value, ok = object[token]
			if !ok {
				return nil, errors.New("source pointer unavailable")
			}
		case '[':
			var array []json.RawMessage
			if err := json.Unmarshal(value, &array); err != nil {
				return nil, err
			}
			i, err := strconv.Atoi(token)
			if err != nil || strconv.Itoa(i) != token || i < 0 || i >= len(array) {
				return nil, errors.New("source array index unavailable")
			}
			value = array[i]
		default:
			return nil, errors.New("source pointer traverses scalar")
		}
	}
	if !json.Valid(value) {
		return nil, errors.New("source is not JSON")
	}
	return value, nil
}

func pointerTokens(pointer string) ([]string, error) {
	if pointer == "" {
		return nil, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, errors.New("source pointer must be RFC 6901")
	}
	tokens := strings.Split(pointer[1:], "/")
	for i, token := range tokens {
		for j := 0; j < len(token); j++ {
			if token[j] == '~' {
				j++
				if j == len(token) || (token[j] != '0' && token[j] != '1') {
					return nil, errors.New("invalid source pointer escape")
				}
			}
		}
		tokens[i] = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
	}
	return tokens, nil
}

// Seal returns an immutable JSON source artifact with derived references
// omitted (avoiding a self-referential hash). All other fields, including
// parser/claim metadata, decoded bytes and evidence order, are retained.
// The stream/store observation points at this artifact; exchange refs point
// at its evidence indices. Calling Seal again yields exactly the same bytes.
func (o *Observation) Seal() ([]byte, error) {
	if o.ScanID == "" || o.ID == "" {
		return nil, errors.New("source requires scan and observation IDs")
	}
	o.Stamp(o.ScanID)
	if o.ClaimStatus == "" {
		o.ClaimStatus = "observed"
		if o.Kind == KindDevice || o.State == "filtered" || o.State == "open|filtered" || o.State == "no-response" {
			o.ClaimStatus = "inferred"
		}
		if o.State == "unknown" || o.State == "error" || o.State == "unsupported" || o.Fingerprint == FingerprintUnknown {
			o.ClaimStatus = "unknown"
		}
	}
	o.Evidence = append([]Evidence(nil), o.Evidence...)
	for i := range o.Evidence {
		ev := &o.Evidence[i]
		if ev.ParserVersion == "" {
			ev.ParserVersion = ParserVersion
		}
		if ev.ClaimStatus == "" {
			ev.ClaimStatus = "unknown"
			if ev.Matched != "" {
				ev.ClaimStatus = "observed"
			}
		}
		// No truncation flag proves only retained bytes, not a full session.
		if ev.Completeness == "" {
			ev.Completeness = "unknown"
			if ev.Truncated || ev.Error != "" {
				ev.Completeness = "partial"
			}
		}
	}
	canonical := *o
	canonical.Source = nil
	canonical.Evidence = append([]Evidence(nil), o.Evidence...)
	for i := range canonical.Evidence {
		canonical.Evidence[i].Source = nil
	}
	b, err := json.Marshal(canonical)
	if err != nil {
		return nil, err
	}
	ref := SourceRef{Owner: "next-gen", SourceSchema: SchemaVersion, ArtifactID: ArtifactID(b), RunID: o.ScanID}
	if err := o.attachSources(ref); err != nil {
		return nil, err
	}
	return b, nil
}

// ReadSource projects a retained artifact without re-encoding its bytes.
// Optional fields from another v1 producer must not change its source identity
// simply because this binary does not understand those fields yet.
func ReadSource(source []byte, artifactID string) (Observation, error) {
	var o Observation
	if ArtifactID(source) != artifactID {
		return o, errors.New("stored source artifact hash mismatch")
	}
	if err := json.Unmarshal(source, &o); err != nil {
		return o, err
	}
	if o.Schema != SchemaVersion || o.ID == "" || o.ScanID == "" {
		return o, errors.New("unsupported source observation envelope")
	}
	ref := SourceRef{Owner: "next-gen", SourceSchema: o.Schema, ArtifactID: artifactID, RunID: o.ScanID}
	if err := o.attachSources(ref); err != nil {
		return o, err
	}
	return o, nil
}

func (o *Observation) attachSources(ref SourceRef) error {
	if o.Source != nil && *o.Source != ref {
		return errors.New("observation differs from sealed source")
	}
	// Check every existing reference before modifying any of them.
	for i := range o.Evidence {
		r := ref
		r.Pointer = fmt.Sprintf("/evidence/%d", i)
		if o.Evidence[i].Source != nil && *o.Evidence[i].Source != r {
			return errors.New("exchange differs from sealed source")
		}
	}
	o.Source = &ref
	for i := range o.Evidence {
		r := ref
		r.Pointer = fmt.Sprintf("/evidence/%d", i)
		o.Evidence[i].Source = &r
	}
	return nil
}
