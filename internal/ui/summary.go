package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/netmon"
)

// RunStats describes a finished scan for the closing summary.
type RunStats struct {
	Elapsed time.Duration
	Tasks   int // probe tasks finished
	Planned int // probe tasks scheduled
	Found   int // open ports and responsive hosts
	Workers int
	Failed  bool
	// Traffic is the interface counter delta over the scan, valid when
	// HasTraffic is set. It counts every packet on the interface, not only
	// the scan's own.
	Traffic    netmon.Counters
	HasTraffic bool
	Interface  string // label of the monitored interface
}

// RunSummary renders the closing statistics block, one row per line, with a
// trailing newline:
//
//	✓ scan finished in 0:12 (12.3s)
//	  tasks      1,000/1,000 • 12 found • 81/s
//	  workers    256
//	  packets    ↑ 1,234 sent (96.0 KB, 100/s) • ↓ 800 recv (64.0 KB, 65/s) on en0
func (s *Styler) RunSummary(st RunStats) string {
	var b strings.Builder
	secs := st.Elapsed.Seconds()
	perSec := func(n uint64) float64 {
		if secs <= 0 {
			return 0
		}
		return float64(n) / secs
	}

	glyph, status := s.Green("✓"), "finished"
	if st.Failed {
		glyph, status = s.Red("✗"), "failed"
	}
	exact := fmt.Sprintf("%.1fs", secs)
	if st.Elapsed < time.Second {
		exact = st.Elapsed.Round(time.Millisecond).String()
	}
	fmt.Fprintf(&b, "%s %s %s %s %s\n", glyph, s.Bold("scan "+status), s.Dim("in"),
		s.Yellow(clock(st.Elapsed)), s.Dim("("+exact+")"))

	row := func(k, v string) { fmt.Fprintf(&b, "  %s %s\n", s.Key(fmt.Sprintf("%-10s", k)), v) }
	sep := s.Dim(" • ")

	tasks := s.Bold(groupDigits(st.Tasks))
	if st.Planned > 0 {
		tasks += s.Dim("/" + groupDigits(st.Planned))
	}
	tasks += sep + s.Green(groupDigits(st.Found)+" found")
	if r := perSec(uint64(st.Tasks)); r > 0 {
		tasks += sep + s.Magenta(formatRate(r))
	}
	row("tasks", tasks)
	row("workers", s.Bold(groupDigits(st.Workers)))

	if st.HasTraffic {
		t := st.Traffic
		dir := func(arrow, verb string, pkts, bytes uint64, color func(string) string) string {
			return color(arrow) + " " + s.Bold(groupDigits(int(pkts))) + s.Dim(" "+verb+" (") +
				formatBytes(float64(bytes)) + s.Dim(", ") + formatCount(perSec(pkts)) + s.Dim(" pkt/s)")
		}
		line := dir("↑", "sent", t.TxPackets, t.TxBytes, s.Cyan) + sep + dir("↓", "recv", t.RxPackets, t.RxBytes, s.Green)
		if st.Interface != "" {
			line += s.Dim(" on ") + st.Interface
		}
		row("packets", line)
	}
	return b.String()
}
