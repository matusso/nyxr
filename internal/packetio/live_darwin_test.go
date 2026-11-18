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

func TestTunnelToEthernet(t *testing.T) {
	ip4 := append([]byte{0x45}, bytes.Repeat([]byte{0}, 19)...)
	dst := make([]byte, 64)
	null := append([]byte{2, 0, 0, 0}, ip4...)
	n, ok := tunnelToEthernet(dltNull, null, dst)
	if !ok || n != 34 || !bytes.Equal(dst[12:14], []byte{0x08, 0x00}) || !bytes.Equal(dst[14:n], ip4) {
		t.Fatalf("null: n=%d ok=%t frame=%x", n, ok, dst[:n])
	}
	ip6 := append([]byte{0x60}, bytes.Repeat([]byte{0}, 39)...)
	n, ok = tunnelToEthernet(dltRaw, ip6, dst)
	if !ok || n != 54 || !bytes.Equal(dst[12:14], []byte{0x86, 0xdd}) {
		t.Fatalf("raw: n=%d ok=%t", n, ok)
	}
	if _, ok := tunnelToEthernet(dltRaw, ip6, dst[:40]); ok {
		t.Fatal("accepted packet larger than buffer")
	}
	if _, ok := tunnelToEthernet(dltNull, []byte{2, 0, 0, 0, 0x10}, dst); ok {
		t.Fatal("accepted non-IP packet")
	}
}
