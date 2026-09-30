package scan

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/matusso/nyxr/internal/config"
)

// probeLimiter reserves one send slot across the configured scopes. State is
// bounded by the configured targets and their subnet prefixes.
type probeLimiter struct {
	mu                                              sync.Mutex
	globalRate, hostRate, subnetRate, interfaceRate int
	nextGlobal, nextInterface                       time.Time
	nextHost, nextSubnet                            map[netip.Addr]time.Time
}

func newProbeLimiter(rate int) *probeLimiter { return &probeLimiter{globalRate: rate} }

func newScopedProbeLimiter(cfg config.Config) *probeLimiter {
	return &probeLimiter{globalRate: cfg.Rate, hostRate: cfg.HostRate,
		subnetRate: cfg.SubnetRate, interfaceRate: cfg.InterfaceRate,
		nextHost: make(map[netip.Addr]time.Time), nextSubnet: make(map[netip.Addr]time.Time)}
}

func (l *probeLimiter) Wait(ctx context.Context) error {
	return l.WaitFor(ctx, netip.Addr{})
}

func (l *probeLimiter) WaitFor(ctx context.Context, target netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now()
	l.mu.Lock()
	ready := now
	if l.globalRate > 0 && l.nextGlobal.After(ready) {
		ready = l.nextGlobal
	}
	if l.interfaceRate > 0 && l.nextInterface.After(ready) {
		ready = l.nextInterface
	}
	var subnet netip.Addr
	if target.IsValid() {
		if l.hostRate > 0 && l.nextHost[target].After(ready) {
			ready = l.nextHost[target]
		}
		if l.subnetRate > 0 {
			bits := 24
			if target.Is6() {
				bits = 64
			}
			subnet = netip.PrefixFrom(target, bits).Masked().Addr()
			if l.nextSubnet[subnet].After(ready) {
				ready = l.nextSubnet[subnet]
			}
		}
	}
	if l.globalRate > 0 {
		l.nextGlobal = ready.Add(rateInterval(l.globalRate))
	}
	if l.interfaceRate > 0 {
		l.nextInterface = ready.Add(rateInterval(l.interfaceRate))
	}
	if target.IsValid() {
		if l.hostRate > 0 {
			l.nextHost[target] = ready.Add(rateInterval(l.hostRate))
		}
		if l.subnetRate > 0 {
			l.nextSubnet[subnet] = ready.Add(rateInterval(l.subnetRate))
		}
	}
	l.mu.Unlock()
	if delay := time.Until(ready); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}

func rateInterval(rate int) time.Duration {
	interval := time.Second / time.Duration(rate)
	if interval < time.Nanosecond {
		return time.Nanosecond
	}
	return interval
}

func (l *probeLimiter) Close() {}
