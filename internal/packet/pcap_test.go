package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestPCAPReader(t *testing.T) {
	var data bytes.Buffer
	_ = binary.Write(&data, binary.LittleEndian, uint32(0xa1b2c3d4))
	_ = binary.Write(&data, binary.LittleEndian, uint16(2))
	_ = binary.Write(&data, binary.LittleEndian, uint16(4))
	_ = binary.Write(&data, binary.LittleEndian, uint64(0))
	_ = binary.Write(&data, binary.LittleEndian, uint32(65535))
	_ = binary.Write(&data, binary.LittleEndian, uint32(1))
	_ = binary.Write(&data, binary.LittleEndian, uint64(0))
	_ = binary.Write(&data, binary.LittleEndian, uint32(3))
	_ = binary.Write(&data, binary.LittleEndian, uint32(3))
	data.Write([]byte{1, 2, 3})
	r, err := NewPCAPReader(&data)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := r.Next()
	if err != nil || !bytes.Equal(packet, []byte{1, 2, 3}) {
		t.Fatalf("packet %x, error %v", packet, err)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}
