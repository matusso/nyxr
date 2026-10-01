package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// PCAPReader supports classic Ethernet pcap in either byte order and both
// microsecond and nanosecond variants. File decoding is outside the RX hot path.
type PCAPReader struct {
	r     io.Reader
	order binary.ByteOrder
	nanos bool
}

func NewPCAPReader(r io.Reader) (*PCAPReader, error) {
	var header [24]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	var order binary.ByteOrder
	switch [4]byte(header[:4]) {
	case [4]byte{0xd4, 0xc3, 0xb2, 0xa1}, [4]byte{0x4d, 0x3c, 0xb2, 0xa1}:
		order = binary.LittleEndian
	case [4]byte{0xa1, 0xb2, 0xc3, 0xd4}, [4]byte{0xa1, 0xb2, 0x3c, 0x4d}:
		order = binary.BigEndian
	default:
		return nil, errors.New("not a classic pcap file")
	}
	if order.Uint16(header[4:6]) != 2 || order.Uint16(header[6:8]) != 4 {
		return nil, errors.New("unsupported pcap version")
	}
	if order.Uint32(header[20:24]) != 1 {
		return nil, errors.New("pcap must contain Ethernet frames")
	}
	nanos := header[1] == 0x3c || header[2] == 0x3c
	return &PCAPReader{r: r, order: order, nanos: nanos}, nil
}

func (p *PCAPReader) Next() ([]byte, error) {
	data, _, _, err := p.NextRecord()
	return data, err
}

// NextRecord returns the next frame with its capture timestamp and original
// (untruncated) length.
func (p *PCAPReader) NextRecord() ([]byte, time.Time, int, error) {
	var header [16]byte
	n, err := io.ReadFull(p.r, header[:])
	if err == io.EOF && n == 0 {
		return nil, time.Time{}, 0, io.EOF
	}
	if err != nil {
		return nil, time.Time{}, 0, err
	}
	length := p.order.Uint32(header[8:12])
	if length > 16<<20 {
		return nil, time.Time{}, 0, fmt.Errorf("pcap packet too large: %d bytes", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(p.r, data); err != nil {
		return nil, time.Time{}, 0, err
	}
	frac := int64(p.order.Uint32(header[4:8]))
	if !p.nanos {
		frac *= 1000
	}
	ts := time.Unix(int64(p.order.Uint32(header[0:4])), frac)
	return data, ts, int(p.order.Uint32(header[12:16])), nil
}
