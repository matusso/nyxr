package scan

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/config"
)

func TestScopedProbeLimiter(t *testing.T) {
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")
	other := netip.MustParseAddr("198.51.100.1")
	l := newScopedProbeLimiter(config.Config{HostRate: 10, SubnetRate: 5})
	if err := l.WaitFor(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := l.WaitFor(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 175*time.Millisecond {
		t.Fatalf("same subnet sent too soon: %s", elapsed)
	}
	start = time.Now()
	if err := l.WaitFor(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("independent subnet was delayed: %s", elapsed)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := l.WaitFor(ctx, first); err == nil {
		t.Fatal("cancelled reservation should not send")
	}
}
