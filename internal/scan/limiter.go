package scan

import (
	"context"
	"time"
)

// A single ticker is shared by workers, so every transmitted probe consumes
// one global rate slot, including retries and additional UDP campaign steps.
type probeLimiter struct{ ticker *time.Ticker }

func newProbeLimiter(rate int) *probeLimiter {
	if rate <= 0 {
		return &probeLimiter{}
	}
	interval := time.Second / time.Duration(rate)
	if interval < time.Nanosecond {
		interval = time.Nanosecond
	}
	return &probeLimiter{ticker: time.NewTicker(interval)}
}

func (l *probeLimiter) Wait(ctx context.Context) error {
	if l.ticker == nil {
		return ctx.Err()
	}
	select {
	case <-l.ticker.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *probeLimiter) Close() {
	if l.ticker != nil {
		l.ticker.Stop()
	}
}
