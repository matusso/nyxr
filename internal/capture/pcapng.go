// Package capture records scan traffic as pcapng evidence. A dedicated
// reader goroutine copies matching frames into a bounded queue; a separate
// writer goroutine encodes, indexes and writes them, so no scan RX worker ever
// waits on disk.
package capture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// Direction is relative to the scanner.
type Direction uint8

const (
	DirectionUnknown Direction = iota
	DirectionRX
	DirectionTX
)

func (d Direction) String() string {
	switch d {
	case DirectionRX:
		return "rx"
	case DirectionTX:
		return "tx"
	default:
		return "unknown"
	}
}

const (
	blockSHB = 0x0A0D0D0A
	blockIDB = 0x00000001
	blockEPB = 0x00000006

	optEnd      = 0
	optComment  = 1
	optUserAppl = 4 // shb_userappl
	optIfName   = 2 // if_name
	optTSResol  = 9 // if_tsresol
	optFlags    = 2 // epb_flags
	optPacketID = 5 // epb_packetid

	linkTypeEthernet = 1
)

// PCAPNGWriter writes one section with one Ethernet interface using
// nanosecond timestamps. It is not safe for concurrent use; the recorder's
// writer goroutine owns it.
type PCAPNGWriter struct {
	w     *bufio.Writer
	buf   []byte
	bytes int64
}

// NewPCAPNGWriter writes the section and interface headers.
func NewPCAPNGWriter(w io.Writer, iface string, snaplen int, application string) (*PCAPNGWriter, error) {
	if snaplen <= 0 || snaplen > 262144 {
		return nil, errors.New("pcapng snaplen must be 1..262144")
	}
	p := &PCAPNGWriter{w: bufio.NewWriterSize(w, 1<<16), buf: make([]byte, 0, 2048)}

	b := p.buf[:0]
	b = le32(b, blockSHB)
	b = le32(b, 0) // total length, patched below
	b = le32(b, 0x1A2B3C4D)
	b = le16(b, 1)
	b = le16(b, 0)
	b = le64(b, ^uint64(0)) // section length unknown
	b = option(b, optUserAppl, []byte(application))
	b = option(b, optEnd, nil)
	if err := p.finish(b); err != nil {
		return nil, err
	}

	b = p.buf[:0]
	b = le32(b, blockIDB)
	b = le32(b, 0)
	b = le16(b, linkTypeEthernet)
	b = le16(b, 0)
	b = le32(b, uint32(snaplen))
	if iface != "" {
		b = option(b, optIfName, []byte(iface))
	}
	b = option(b, optTSResol, []byte{9}) // 10^-9 seconds
	b = option(b, optEnd, nil)
	if err := p.finish(b); err != nil {
		return nil, err
	}
	return p, nil
}

// WritePacket appends one Enhanced Packet Block. data may be shorter than
// origLen when the frame was truncated to the snap length.
func (p *PCAPNGWriter) WritePacket(ts time.Time, data []byte, origLen int, dir Direction, id uint64, comment string) error {
	nanos := uint64(ts.UnixNano())
	b := p.buf[:0]
	b = le32(b, blockEPB)
	b = le32(b, 0)
	b = le32(b, 0) // interface 0
	b = le32(b, uint32(nanos>>32))
	b = le32(b, uint32(nanos))
	b = le32(b, uint32(len(data)))
	b = le32(b, uint32(origLen))
	b = append(b, data...)
	b = pad(b)
	if dir != DirectionUnknown {
		// epb_flags bits 0-1: 01 inbound, 10 outbound.
		var flags [4]byte
		if dir == DirectionRX {
			binary.LittleEndian.PutUint32(flags[:], 1)
		} else {
			binary.LittleEndian.PutUint32(flags[:], 2)
		}
		b = option(b, optFlags, flags[:])
	}
	var idBytes [8]byte
	binary.LittleEndian.PutUint64(idBytes[:], id)
	b = option(b, optPacketID, idBytes[:])
	if comment != "" {
		b = option(b, optComment, []byte(comment))
	}
	b = option(b, optEnd, nil)
	return p.finish(b)
}

// BlockSize reports the encoded size of a packet block, so callers can
// enforce a disk budget before writing.
func BlockSize(dataLen, commentLen int) int64 {
	n := 28 + align(dataLen) + 4 + 4 + 12 + 4 + 4
	if commentLen > 0 {
		n += 4 + align(commentLen)
	}
	return int64(n)
}

func (p *PCAPNGWriter) Bytes() int64 { return p.bytes }
func (p *PCAPNGWriter) Flush() error { return p.w.Flush() }

func (p *PCAPNGWriter) finish(b []byte) error {
	total := uint32(len(b) + 4)
	binary.LittleEndian.PutUint32(b[4:8], total)
	b = le32(b, total)
	p.buf = b[:0]
	n, err := p.w.Write(b)
	p.bytes += int64(n)
	return err
}

func option(b []byte, code uint16, value []byte) []byte {
	if len(value) > 0xffff {
		value = value[:0xffff]
	}
	b = le16(b, code)
	b = le16(b, uint16(len(value)))
	b = append(b, value...)
	return pad(b)
}

func align(n int) int { return (n + 3) &^ 3 }

func pad(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func le16(b []byte, v uint16) []byte { return binary.LittleEndian.AppendUint16(b, v) }
func le32(b []byte, v uint32) []byte { return binary.LittleEndian.AppendUint32(b, v) }
func le64(b []byte, v uint64) []byte { return binary.LittleEndian.AppendUint64(b, v) }
