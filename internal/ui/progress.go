package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Progress draws a one-line progress bar on a terminal, normally stderr,
// while results stream to the output writer. Writes through the writer
// returned by Wrap clear the bar first and redraw it afterwards, so result
// lines and the bar never interleave on a shared terminal. A disabled Progress
// is inert: every method is a no-op and Wrap returns its argument.
type Progress struct {
	mu      sync.Mutex
	w       io.Writer
	style   *Styler
	total   int
	done    int
	found   int
	start   time.Time
	drawn   bool
	stopped bool
	stop    chan struct{}
	ticker  sync.WaitGroup
}

const (
	barWidth     = 30
	progressTick = 100 * time.Millisecond
)

// NewProgress returns a bar for total tasks drawn on w. The bar is shown only
// when enabled is set, total is positive, w is an interactive terminal and
// TERM is not "dumb"; otherwise it is disabled. style colors the bar.
func NewProgress(w io.Writer, total int, enabled bool, style *Styler) *Progress {
	if !enabled || total <= 0 || !isTerminal(w) || os.Getenv("TERM") == "dumb" {
		return &Progress{}
	}
	if style == nil {
		style = Plain()
	}
	p := &Progress{w: w, style: style, total: total, start: time.Now(), stop: make(chan struct{})}
	p.ticker.Add(1)
	go p.run()
	return p
}

// Enabled reports whether the bar is drawn.
func (p *Progress) Enabled() bool { return p != nil && p.w != nil }

func (p *Progress) run() {
	defer p.ticker.Done()
	t := time.NewTicker(progressTick)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			p.mu.Lock()
			p.drawLocked()
			p.mu.Unlock()
		case <-p.stop:
			return
		}
	}
}

// Step records one finished task; found marks a positive result (an open
// port or a responsive host). The bar redraws on its next tick.
func (p *Progress) Step(found bool) {
	if !p.Enabled() {
		return
	}
	p.mu.Lock()
	p.done++
	if found {
		p.found++
	}
	p.mu.Unlock()
}

// Wrap returns a writer that keeps out's lines clear of the bar. When out is
// not a terminal the bar cannot collide with it, so out is returned as is.
func (p *Progress) Wrap(out io.Writer) io.Writer {
	if !p.Enabled() || !isTerminal(out) {
		return out
	}
	return progressWriter{p: p, w: out}
}

// Done stops the bar and erases it. It is safe to call more than once.
func (p *Progress) Done() {
	if !p.Enabled() {
		return
	}
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	p.clearLocked()
	p.mu.Unlock()
	close(p.stop)
	p.ticker.Wait()
}

type progressWriter struct {
	p *Progress
	w io.Writer
}

func (pw progressWriter) Write(b []byte) (int, error) {
	pw.p.mu.Lock()
	defer pw.p.mu.Unlock()
	pw.p.clearLocked()
	n, err := pw.w.Write(b)
	pw.p.drawLocked()
	return n, err
}

func (p *Progress) clearLocked() {
	if p.drawn {
		fmt.Fprint(p.w, "\r\x1b[K")
		p.drawn = false
	}
}

func (p *Progress) drawLocked() {
	if p.stopped {
		return
	}
	fmt.Fprint(p.w, "\r"+p.render(time.Since(p.start))+"\x1b[K")
	p.drawn = true
}

// render formats the bar line, e.g.
// "██████████░░░░░░░░░░░░░░░░░░░░  33%  100/300  2 found  0:04 eta 0:08".
func (p *Progress) render(elapsed time.Duration) string {
	done := min(p.done, p.total)
	filled := done * barWidth / p.total
	pct := done * 100 / p.total
	s := p.style
	var b strings.Builder
	b.WriteString(s.Cyan(strings.Repeat("█", filled)))
	b.WriteString(s.Dim(strings.Repeat("░", barWidth-filled)))
	fmt.Fprintf(&b, " %s", s.Bold(fmt.Sprintf("%3d%%", pct)))
	b.WriteString(s.Dim(fmt.Sprintf("  %d/%d", done, p.total)))
	if p.found > 0 {
		b.WriteString("  " + s.Green(fmt.Sprintf("%d found", p.found)))
	}
	b.WriteString(s.Dim("  " + clock(elapsed)))
	if done > 0 && done < p.total {
		eta := time.Duration(float64(elapsed) * float64(p.total-done) / float64(done))
		b.WriteString(s.Dim(" eta " + clock(eta)))
	}
	return b.String()
}

// clock formats d as m:ss, or h:mm:ss from an hour up.
func clock(d time.Duration) string {
	sec := int(d.Round(time.Second) / time.Second)
	h, m, ss := sec/3600, sec/60%60, sec%60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, ss)
	}
	return fmt.Sprintf("%d:%02d", m, ss)
}
