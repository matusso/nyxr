package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestProgressRender(t *testing.T) {
	p := &Progress{style: Plain(), total: 300, done: 100, found: 2}
	got := p.render(4 * time.Second)
	want := strings.Repeat("█", 10) + strings.Repeat("░", 20) + "  33%  100/300  2 found  0:04 eta 0:08"
	if got != want {
		t.Fatalf("render:\n got %q\nwant %q", got, want)
	}
	p.done = 300
	if got := p.render(time.Hour + 2*time.Second); !strings.HasSuffix(got, "100%  300/300  2 found  1:00:02") {
		t.Fatalf("finished render: %q", got)
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
