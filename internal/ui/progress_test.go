package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestProgressRender(t *testing.T) {
	p := &Progress{style: Plain(), total: 300, done: 100, found: 2}
	got := p.render(4*time.Second, 120)
	want := "⠋ scanning " + strings.Repeat("━", 13) + strings.Repeat("─", 27) +
		"  33%  100/300 • 2 found • 25/s • 0:04 • eta 0:08"
	if got != want {
		t.Fatalf("render:\n got %q\nwant %q", got, want)
	}
	p.done = 50
	if got := p.bar(50, 40, false); got != strings.Repeat("━", 6)+"╸"+strings.Repeat("─", 33) {
		t.Fatalf("half-cell bar: %q", got)
	}
	p.done = 300
	got = p.render(time.Hour+2*time.Second, 120)
	if !strings.HasPrefix(got, "✓ scanning "+strings.Repeat("━", 40)) ||
		!strings.HasSuffix(got, "100%  300/300 • 2 found • 0.1/s • 1:00:02") {
		t.Fatalf("finished render: %q", got)
	}
}

func TestProgressRenderFitsNarrowTerminal(t *testing.T) {
	p := &Progress{style: Plain(), total: 70000, done: 35000, found: 1200, frame: 3}
	for _, cols := range []int{120, 80, 60, 40, 24} {
		got := p.render(10*time.Second, cols)
		if w := visibleWidth(got); w >= cols {
			t.Errorf("cols %d: width %d overflows: %q", cols, w, got)
		}
		if !strings.Contains(got, " 50%") {
			t.Errorf("cols %d: percent dropped: %q", cols, got)
		}
	}
	if got := p.render(10*time.Second, 40); strings.Contains(got, "eta") {
		t.Errorf("narrow render keeps low-priority segments: %q", got)
	}
}

func TestProgressSmoothedRate(t *testing.T) {
	p := &Progress{total: 1000}
	p.done = 100
	p.sampleLocked(time.Second)
	if p.rate != 100 {
		t.Fatalf("first sample rate = %v, want 100", p.rate)
	}
	p.done = 100 // stalled for a second
	p.sampleLocked(2 * time.Second)
	if p.rate <= 0 || p.rate >= 100 {
		t.Fatalf("stalled rate = %v, want it to decay below 100", p.rate)
	}
}

func TestGroupDigits(t *testing.T) {
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 65535: "65,535", 1234567: "1,234,567"} {
		if got := groupDigits(n); got != want {
			t.Errorf("groupDigits(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestProgressDisabledOffTerminal(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, 10, true, Plain())
	if p.Enabled() {
		t.Fatal("progress must stay off when the writer is not a terminal")
	}
	p.Step(true)
	if w := p.Wrap(&buf); w != &buf {
		t.Fatal("a disabled bar must not wrap the output")
	}
	p.Done()
	if buf.Len() != 0 {
		t.Fatalf("disabled bar wrote %q", buf.String())
	}
}
