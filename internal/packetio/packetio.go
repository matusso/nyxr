package packetio

import (
	"context"
	"errors"
	"time"
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

// ReceiveMetadata is optional provenance supplied by a timestamp-capable
// backend. Nil precision or queue delay explicitly means unavailable.
type ReceiveMetadata struct {
	Timestamp                 time.Time
	ClockSource               string
	ResolutionNS              int64
	PrecisionNS, QueueDelayNS *int64
}

// TimestampedReceiver preserves PacketIO compatibility. Implementations fill
// one metadata entry per returned frame; timestamps use the report's UTC epoch.
type TimestampedReceiver interface {
	ReceiveBatchMetadata(context.Context, [][]byte, []ReceiveMetadata) (int, error)
}

// Opener opens live Ethernet I/O on a named interface. OpenLive is the local
// privileged implementation; a packetd client is the unprivileged one.
type Opener func(device string) (PacketIO, error)
