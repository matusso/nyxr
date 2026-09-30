package capture

import (
	"bufio"
	"errors"
	"io"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/matusso/nyxr/internal/packet"
)

// FrameReader yields Ethernet frames from a capture file.
type FrameReader interface {
	Next() ([]byte, error)
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
		return packet.NewPCAPReader(br)
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
