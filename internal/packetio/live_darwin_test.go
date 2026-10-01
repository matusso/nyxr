//go:build darwin

package packetio

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBPFRecordUsesUserlandHeader(t *testing.T) {
	frame := bytes.Repeat([]byte{0xab}, 42)
	record := make([]byte, 20+len(frame)+2)
	binary.NativeEndian.PutUint32(record[8:12], uint32(len(frame)))
	binary.NativeEndian.PutUint32(record[12:16], uint32(len(frame)))
	binary.NativeEndian.PutUint16(record[16:18], 18)
	copy(record[18:], frame)
	got, advance, ok := bpfRecord(record)
	if !ok || !bytes.Equal(got, frame) || advance != 60 {
		t.Fatalf("frame=%x advance=%d ok=%t", got, advance, ok)
	}
	if _, _, ok := bpfRecord(record[:17]); ok {
		t.Fatal("accepted truncated header")
	}
}
