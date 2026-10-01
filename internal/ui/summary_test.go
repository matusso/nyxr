package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/netmon"
)

func TestRunSummaryPlain(t *testing.T) {
	got := Plain().RunSummary(RunStats{
		Elapsed: 12500 * time.Millisecond, Tasks: 1000, Planned: 1000, Found: 12, Workers: 256,
		Traffic:    netmon.Counters{TxPackets: 1250, RxPackets: 800, TxBytes: 96000, RxBytes: 64000},
		HasTraffic: true, Interface: "en0",
	})
	want := "✓ scan finished in 0:13 (12.5s)\n" +
		"  tasks      1,000/1,000 • 12 found • 80/s\n" +
		"  workers    256\n" +
		"  packets    ↑ 1,250 sent (96.0 KB, 100 pkt/s) • ↓ 800 recv (64.0 KB, 64 pkt/s) on en0\n"
	if got != want {
		t.Fatalf("summary:\n%s\nwant:\n%s", got, want)
	}
}

func TestRunSummaryFailedWithoutTraffic(t *testing.T) {
	got := Plain().RunSummary(RunStats{Elapsed: time.Second, Tasks: 3, Planned: 10, Workers: 4, Failed: true})
	if !strings.HasPrefix(got, "✗ scan failed in 0:01") || strings.Contains(got, "packets") {
		t.Fatalf("summary:\n%s", got)
	}
}
