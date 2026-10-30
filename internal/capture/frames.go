package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

// MaxFrameLookup bounds the packet IDs one ReadPackets call resolves.
const MaxFrameLookup = 256

// OpenVerified opens a retained capture file. When artifactID is set, the
// file must still be exactly that artifact; the returned file is positioned
// at its start, so the verified bytes are the bytes read afterwards.
func OpenVerified(path string, size int64, artifactID string) (*os.File, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, errors.New("capture file is missing")
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, errors.New("capture file is missing")
	}
	if artifactID == "" {
		return f, fi, nil
	}
	if fi.Size() != size {
		f.Close()
		return nil, nil, errors.New("capture artifact is unavailable: size changed")
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, io.LimitReader(f, size+1)); err != nil || "sha256:"+hex.EncodeToString(digest.Sum(nil)) != artifactID {
		f.Close()
		return nil, nil, errors.New("capture artifact is unavailable: hash mismatch")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, nil, errors.New("cannot read capture")
	}
	return f, fi, nil
}

// ReadPackets returns the frames whose nyxr packet ID is in ids. IDs absent
// from the capture are absent from the result. It reads the file once.
func ReadPackets(r io.Reader, ids []uint64) (map[uint64]Record, error) {
	if len(ids) == 0 || len(ids) > MaxFrameLookup {
		return nil, errors.New("request 1..256 packet IDs")
	}
	wanted := make(map[uint64]bool, len(ids))
	for _, id := range ids {
		wanted[id] = true
	}
	fr, err := NewReader(r)
	if err != nil {
		return nil, err
	}
	out := make(map[uint64]Record, len(ids))
	for len(out) < len(wanted) {
		rec, err := fr.NextRecord()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, err
		}
		if rec.PacketID != 0 && wanted[rec.PacketID] {
			rec.Data = append([]byte(nil), rec.Data...)
			out[rec.PacketID] = rec
		}
	}
	return out, nil
}
