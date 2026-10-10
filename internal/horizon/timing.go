package horizon

import (
	"context"
	"time"

	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/packetio"
)

func validTiming(t *model.Timing) bool {
	return t != nil && t.ClockSource != "" && len(t.ClockSource) <= 128 && t.ResolutionNS > 0 && t.OperationNS >= 0 &&
		(t.PrecisionNS == nil || *t.PrecisionNS > 0) && (t.QueueDelayNS == nil || *t.QueueDelayNS >= 0)
}

func copyOptional(value *int64) *int64 {
	if value == nil {
		return nil
	}
	v := *value
	return &v
}

func receiveTimed(ctx context.Context, transport packetio.PacketIO, batch [][]byte) (int, error, time.Time, *model.Timing) {
	start := time.Now()
	meta := []packetio.ReceiveMetadata{{}}
	var n int
	var err error
	if backend, ok := transport.(packetio.TimestampedReceiver); ok {
		n, err = backend.ReceiveBatchMetadata(ctx, batch, meta)
	} else {
		n, err = transport.ReceiveBatch(ctx, batch)
	}
	now := time.Now()
	timing := &model.Timing{ClockSource: "userspace/time.Now", ResolutionNS: 1, OperationNS: now.Sub(start).Nanoseconds(), BackendDrops: transport.Stats().Dropped}
	if !meta[0].Timestamp.IsZero() {
		now = meta[0].Timestamp
		timing.ClockSource, timing.ResolutionNS = meta[0].ClockSource, meta[0].ResolutionNS
		timing.PrecisionNS, timing.QueueDelayNS = copyOptional(meta[0].PrecisionNS), copyOptional(meta[0].QueueDelayNS)
	}
	return n, err, now, timing
}
