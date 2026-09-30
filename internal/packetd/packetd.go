// Package packetd separates raw packet privilege from the rest of nyxr. The
// privileged nyxr-packetd process owns live Ethernet I/O on an allowlist of
// interfaces and relays frames over a Unix socket; the unprivileged CLI or
// API process uses Client, which implements packetio.PacketIO.
//
// Wire protocol, per connection: the client sends one JSON hello line naming
// the interface and the server answers with one JSON line. After that both
// sides exchange messages of a 1-byte type, a 4-byte big-endian length and
// the payload: 'T' transmit frame (client to server), 'R' received frame and
// 'S' 24-byte stats (server to client).
package packetd

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ProtocolVersion changes when the wire format changes incompatibly.
const ProtocolVersion = 1

// MaxFrame bounds every relayed frame so neither side allocates on a peer's
// say-so beyond a jumbo Ethernet frame.
const MaxFrame = 9216

// MinFrame is an Ethernet header; shorter transmit frames are refused.
const MinFrame = 14

const (
	msgTX    byte = 'T'
	msgRX    byte = 'R'
	msgStats byte = 'S'
)

const statsSize = 24

type hello struct {
	Version   int    `json:"version"`
	Interface string `json:"interface"`
}

type helloReply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// maxHello bounds the handshake line.
const maxHello = 1024

func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		line = append(line, chunk...)
		if len(line) > maxHello {
			return nil, errors.New("packetd handshake line too long")
		}
		if !isPrefix {
			return line, nil
		}
	}
}

func writeJSONLine(w *bufio.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		return err
	}
	return w.Flush()
}

func writeMsg(w *bufio.Writer, typ byte, payload []byte) error {
	var h [5]byte
	h[0] = typ
	binary.BigEndian.PutUint32(h[1:], uint32(len(payload)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readMsg reads one message into buf, which must hold MaxFrame bytes.
func readMsg(r *bufio.Reader, buf []byte) (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if n > uint32(len(buf)) {
		return 0, nil, fmt.Errorf("packetd message of %d bytes exceeds %d", n, len(buf))
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return 0, nil, err
	}
	return h[0], buf[:n], nil
}
