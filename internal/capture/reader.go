package capture

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/matusso/nyxr/internal/packet"
)

// FrameReader yields Ethernet frames from a capture file.
type FrameReader interface {
	Next() ([]byte, error)
	// NextRecord returns the next frame with its capture metadata.
	NextRecord() (Record, error)
}

// Record is one captured frame with the metadata the file carries for it.
// pcapng-only fields are zero for classic pcap.
type Record struct {
	Data      []byte
	Timestamp time.Time
	Length    int // original length on the wire; may exceed len(Data)
	Direction Direction
	PacketID  uint64 // nyxr's evidence packet ID; 0 when absent
	Comment   string
}

// NewReader detects classic pcap or pcapng (such as nyxr's own evidence
// files) and returns a reader of Ethernet frames.
func NewReader(r io.Reader) (FrameReader, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(4)
	if err != nil {
		return nil, err
	}
	if magic[0] != 0x0a || magic[1] != 0x0d || magic[2] != 0x0d || magic[3] != 0x0a {
		p, err := packet.NewPCAPReader(br)
		if err != nil {
			return nil, err
		}
		return pcapReader{p}, nil
	}
	ng, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return nil, err
	}
	if ng.LinkType() != layers.LinkTypeEthernet {
		return nil, errors.New("pcapng must contain Ethernet frames")
	}
	return ngReader{ng}, nil
}

type ngReader struct{ r *pcapgo.NgReader }

func (n ngReader) Next() ([]byte, error) {
	data, _, err := n.r.ReadPacketData()
	return data, err
}

func (n ngReader) NextRecord() (Record, error) {
	data, ci, opts, err := n.r.ReadPacketDataWithOptions()
	if err != nil {
		return Record{}, err
	}
	rec := Record{Data: data, Timestamp: ci.Timestamp, Length: ci.Length, Comment: strings.Join(opts.Comments, "; ")}
	if opts.Flags != nil {
		switch opts.Flags.Direction & pcapgo.NgEpbFlagDirectionMask {
		case pcapgo.NgEpbFlagDirectionInbound:
			rec.Direction = DirectionRX
		case pcapgo.NgEpbFlagDirectionOutbound:
			rec.Direction = DirectionTX
		}
	}
	if opts.PacketID != nil {
		rec.PacketID = *opts.PacketID
	}
	return rec, nil
}

type pcapReader struct{ *packet.PCAPReader }

func (p pcapReader) NextRecord() (Record, error) {
	data, ts, length, err := p.PCAPReader.NextRecord()
	if err != nil {
		return Record{}, err
	}
	return Record{Data: data, Timestamp: ts, Length: length}, nil
}
