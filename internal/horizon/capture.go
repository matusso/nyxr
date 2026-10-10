package horizon

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/matusso/nyxr/internal/capture"
	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/packet"
)

// WritePCAPNG reuses Nyxr's recorder format, with a strict encoded file cap.
// It exports retained TX/RX/cleanup evidence without opening another backend.
// References are installed only after a successful flush. Raw JSON evidence
// remains authoritative, including packets omitted/minimized in this export.
func WritePCAPNG(out io.Writer, r *model.Report, maxBytes int64, minimize bool) error {
	a, ids, err := encodeCapture(out, *r, maxBytes, minimize)
	if err != nil {
		return err
	}
	r.CaptureArtifact = &a
	for i := range r.Trials {
		for j := range r.Trials[i].Evidence {
			r.Trials[i].Evidence[j].PacketID = ids[i][j]
		}
	}
	r.Comparison = Compare(*r)
	return nil
}

func captureData(e model.Evidence, minimize bool) []byte {
	if minimize {
		if p, ok := packet.DecodeResearch(e.Frame); ok && p.HeaderLength > 0 && p.HeaderLength < len(e.Frame) {
			return e.Frame[:p.HeaderLength]
		}
	}
	return e.Frame
}

func encodeCapture(out io.Writer, r model.Report, maxBytes int64, minimize bool) (model.CaptureArtifact, [][]uint64, error) {
	a := model.CaptureArtifact{MaxBytes: maxBytes, MinimizePayload: minimize}
	if maxBytes < 256 || maxBytes > 8<<20 {
		return a, nil, errors.New("PCAPNG cap must be 256 bytes..8 MiB")
	}
	h := sha256.New()
	w, err := capture.NewPCAPNGWriter(io.MultiWriter(out, h), "", 2048, "nyxr horizon")
	if err != nil {
		return a, nil, err
	}
	ids := make([][]uint64, len(r.Trials))
	full := false
	for i, t := range r.Trials {
		ids[i] = make([]uint64, len(t.Evidence))
		for j, e := range t.Evidence {
			data := captureData(e, minimize)
			comment := fmt.Sprintf("%s /report/trials/%d/evidence/%d %s", r.RunID, i, j, e.Direction)
			if full || w.Bytes()+capture.BlockSize(len(data), len(comment)) > maxBytes {
				full = true
				a.Dropped++
				continue
			}
			dir := capture.DirectionTX
			if e.Direction == "rx" || e.Direction == "late-rx" {
				dir = capture.DirectionRX
			}
			a.Packets++
			ids[i][j] = uint64(a.Packets)
			if err := w.WritePacket(e.Timestamp, data, len(e.Frame), dir, uint64(a.Packets), comment); err != nil {
				return a, nil, err
			}
		}
	}
	if err := w.Flush(); err != nil {
		return a, nil, err
	}
	a.Bytes, a.ArtifactID = w.Bytes(), "sha256:"+hex.EncodeToString(h.Sum(nil))
	return a, ids, nil
}

func validateCaptureReferences(r model.Report) error {
	if r.CaptureArtifact == nil {
		for _, t := range r.Trials {
			for _, e := range t.Evidence {
				if e.PacketID != 0 {
					return errors.New("packet reference without capture artifact")
				}
			}
		}
		return nil
	}
	a, ids, err := encodeCapture(io.Discard, r, r.CaptureArtifact.MaxBytes, r.CaptureArtifact.MinimizePayload)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(a, *r.CaptureArtifact) {
		return errors.New("capture artifact provenance mismatch")
	}
	for i, t := range r.Trials {
		for j, e := range t.Evidence {
			if e.PacketID != ids[i][j] {
				return errors.New("capture packet reference mismatch")
			}
		}
	}
	return nil
}

// VerifyPCAPNG checks the actual artifact bytes and all referenced packets.
// A minimized capture cannot replace the sealed raw evidence used by Replay.
func VerifyPCAPNG(r model.Report, source io.Reader) error {
	if r.CaptureArtifact == nil {
		return errors.New("report has no PCAPNG artifact")
	}
	if err := validateCaptureReferences(r); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(source, r.CaptureArtifact.MaxBytes+1))
	if err != nil {
		return err
	}
	if n != r.CaptureArtifact.Bytes || "sha256:"+hex.EncodeToString(h.Sum(nil)) != r.CaptureArtifact.ArtifactID {
		return errors.New("PCAPNG integrity check failed")
	}
	return nil
}

// ReplayCaptureFixtures validates complete PCAPNG records against sent probes
// without any network access. Malformed/unrelated records remain unmatched.
func ReplayCaptureFixtures(source io.Reader, sent packet.ForgeSpec, maxBytes int64) ([]model.Features, error) {
	if maxBytes < 256 || maxBytes > 8<<20 {
		return nil, errors.New("invalid fixture budget")
	}
	b, err := io.ReadAll(io.LimitReader(source, maxBytes+1))
	if err != nil || int64(len(b)) > maxBytes {
		return nil, errors.Join(err, errors.New("fixture budget exceeded"))
	}
	if err := validateFixtureBlocks(b); err != nil {
		return nil, err
	}
	r, err := capture.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	var out []model.Features
	for i := 0; i <= 4096; i++ {
		rec, err := r.NextRecord()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if i == 4096 {
			return nil, errors.New("fixture receive budget exceeded")
		}
		if len(rec.Data) <= 2048 && len(rec.Data) == rec.Length {
			if f, ok := correlateRich(rec.Data, sent); ok {
				out = append(out, f)
			}
		}
	}
	return nil, errors.New("fixture receive budget exceeded")
}

// Bound pcapng block allocations before handing hostile files to pcapgo.
// Classic pcap is bounded by packet.PCAPReader's record-length checks.
func validateFixtureBlocks(b []byte) error {
	if len(b) < 4 || binary.LittleEndian.Uint32(b[:4]) != 0x0a0d0d0a {
		return nil
	}
	var order binary.ByteOrder = binary.LittleEndian
	for len(b) > 0 {
		if len(b) < 12 {
			return errors.New("truncated fixture block")
		}
		if binary.LittleEndian.Uint32(b[:4]) == 0x0a0d0d0a {
			switch binary.LittleEndian.Uint32(b[8:12]) {
			case 0x1a2b3c4d:
				order = binary.LittleEndian
			case 0x4d3c2b1a:
				order = binary.BigEndian
			default:
				return errors.New("invalid fixture byte order")
			}
		}
		n := int(order.Uint32(b[4:8]))
		if n < 12 || n > 65536 || n%4 != 0 || n > len(b) || order.Uint32(b[n-4:n]) != uint32(n) {
			return errors.New("invalid or oversized fixture block")
		}
		b = b[n:]
	}
	return nil
}
