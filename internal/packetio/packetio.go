package packetio

import (
	"context"
	"errors"
)

var ErrUnavailable = errors.New("live raw packet I/O unavailable on this platform")

type Stats struct{ Received, Sent, Dropped uint64 }

// PacketIO transports Ethernet frames. Decoding is deliberately outside this
// interface so every backend can use the same preallocated decoder workers.
type PacketIO interface {
	ReceiveBatch(context.Context, [][]byte) (int, error)
	SendBatch(context.Context, [][]byte) (int, error)
	Stats() Stats
	Close() error
}
