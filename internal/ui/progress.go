package ui

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// Progress draws a one-line, rich-style progress bar on a terminal, normally
// stderr, while results stream to the output writer:
//
//	⠹ scanning ━━━━━━━━━━━╸━━━━━━━━━━━━━━━━━━  33%  100/300 • 2 found • 25/s • 0:04 • eta 0:08
//
// Writes through the writer returned by Wrap clear the bar first and redraw it
// afterwards, so result lines and the bar never interleave on a shared
// terminal. A disabled Progress is inert: every method is a no-op and Wrap
// returns its argument.
type Progress struct {
	mu        sync.Mutex
	w         io.Writer
	style     *Styler
	truecolor bool
	width     func() int
	total     int
	done      int
	found     int
	frame     int
	rate      float64 // smoothed tasks per second
	lastDone  int
	lastTick  time.Duration
	start     time.Time
	drawn     bool
	stopped   bool
	stop      chan struct{}
	ticker    sync.WaitGroup
}

const (
	progressTick  = 100 * time.Millisecond
	progressLabel = "scanning"
	minBarWidth   = 10
	maxBarWidth   = 40
	defaultCols   = 80
	// rateWindow is the time constant of the exponential rate average: long
	// enough to ride out bursts, short enough to follow a changed rate limit.
	rateWindow = 3 * time.Second
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Gradient endpoints for the filled part of the bar on truecolor terminals.
var (
	gradientFrom = [3]int{0x00, 0xd7, 0xff} // cyan
	gradientTo   = [3]int{0xaf, 0x5f, 0xff} // violet
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
	p := &Progress{
		w:         w,
		style:     style,
		truecolor: style.Enabled() && truecolorTerminal(),
		width:     terminalWidth(w),
		total:     total,
		start:     time.Now(),
		stop:      make(chan struct{}),
	}
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
			p.frame++
			p.sampleLocked(time.Since(p.start))
			p.drawLocked()
			p.mu.Unlock()
		case <-p.stop:
			return
		}
	}
}

// sampleLocked folds the tasks finished since the last tick into the smoothed
// rate, so the speed and ETA follow the current pace rather than the average
// since the start.
func (p *Progress) sampleLocked(elapsed time.Duration) {
	dt := elapsed - p.lastTick
	if dt <= 0 {
		return
	}
	inst := float64(p.done-p.lastDone) / dt.Seconds()
	if p.lastTick == 0 {
		p.rate = inst
	} else {
		alpha := dt.Seconds() / (rateWindow.Seconds() + dt.Seconds())
		p.rate += alpha * (inst - p.rate)
	}
	p.lastDone, p.lastTick = p.done, elapsed
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
	cols := defaultCols
	if p.width != nil {
		cols = p.width()
	}
	fmt.Fprint(p.w, "\r"+p.render(time.Since(p.start), cols)+"\x1b[K")
	p.drawn = true
}

// render formats the bar line to fit cols terminal columns. Segments are
// dropped from the right as the terminal narrows, and the bar itself shrinks
// between minBarWidth and maxBarWidth cells.
func (p *Progress) render(elapsed time.Duration, cols int) string {
	s := p.style
	done := min(p.done, p.total)
	finished := done == p.total
	pct := done * 100 / p.total

	icon := s.Cyan(spinnerFrames[p.frame%len(spinnerFrames)])
	if finished {
		icon = s.Green("✓")
	}
	head := icon + " " + s.Bold(progressLabel) + " "
	headWidth := 2 + len(progressLabel) + 1

	pctText := fmt.Sprintf("%3d%%", pct)
	pctCell := " " + s.Bold(pctText)
	if finished {
		pctCell = " " + s.Green(pctText)
	}
	pctWidth := 1 + len(pctText)

	// Info segments, in the order they are given up when space runs out.
	type segment struct{ text, colored string }
	count := groupDigits(done) + "/" + groupDigits(p.total)
	segs := []segment{{count, s.Bold(groupDigits(done)) + s.Dim("/"+groupDigits(p.total))}}
	if p.found > 0 {
		t := groupDigits(p.found) + " found"
		segs = append(segs, segment{t, s.Green(t)})
	}
	if r := p.speed(elapsed); r > 0 {
		t := formatRate(r)
		segs = append(segs, segment{t, s.Magenta(t)})
	}
	segs = append(segs, segment{clock(elapsed), s.Yellow(clock(elapsed))})
	if eta, ok := p.eta(elapsed); ok {
		t := "eta " + clock(eta)
		segs = append(segs, segment{t, s.Cyan(t)})
	}

	const sep = " • "
	infoWidth := func(n int) int {
		w := 0
		for i, sg := range segs[:n] {
			if i > 0 {
				w += len(sep) - 2 // the bullet is one column
			}
			w += visibleWidth(sg.text)
		}
		if n > 0 {
			w += 2 // gap before the first segment
		}
		return w
	}

	// Keep as many info segments as fit beside a minimum-width bar.
	n := len(segs)
	for n > 0 && headWidth+minBarWidth+pctWidth+infoWidth(n) > cols-1 {
		n--
	}
	showHead := headWidth+minBarWidth+pctWidth+infoWidth(n) <= cols-1
	avail := cols - 1 - pctWidth - infoWidth(n)
	if showHead {
		avail -= headWidth
	}
	barW := max(min(avail, maxBarWidth), 1)

	var b strings.Builder
	if showHead {
		b.WriteString(head)
	}
	b.WriteString(p.bar(done, barW, finished))
	b.WriteString(pctCell)
	for i, sg := range segs[:n] {
		if i == 0 {
			b.WriteString("  ")
		} else {
			b.WriteString(s.Dim(sep))
		}
		b.WriteString(sg.colored)
	}
	return b.String()
}

// bar draws width cells at half-cell resolution: "━" for full cells, "╸" for
// a trailing half cell and a dimmed "━" track for the rest, like rich's bar.
// Filled cells shade along a gradient on truecolor terminals.
func (p *Progress) bar(done, width int, finished bool) string {
	halves := done * width * 2 / p.total
	full, half := halves/2, halves%2
	s := p.style
	var b strings.Builder
	switch {
	case finished:
		b.WriteString(s.Green(strings.Repeat("━", width)))
		return b.String()
	case p.truecolor:
		for i := range full {
			b.WriteString(rgb(gradientAt(i, width), "━"))
		}
		if half == 1 {
			b.WriteString(rgb(gradientAt(full, width), "╸"))
		}
	default:
		b.WriteString(s.Cyan(strings.Repeat("━", full)))
		if half == 1 {
			b.WriteString(s.Cyan("╸"))
		}
	}
	rest := width - full - half
	if rest > 0 {
		track := strings.Repeat("━", rest)
		if half == 0 && full > 0 {
			track = "╺" + strings.Repeat("━", rest-1)
		}
		if s.Enabled() {
			b.WriteString(s.paint("38;5;238", track))
		} else {
			// Without color the track cannot be dimmed, so draw it light.
			b.WriteString(strings.Repeat("─", rest))
		}
	}
	return b.String()
}

// speed is the smoothed task rate, falling back to the overall average until
// the first tick has sampled one.
func (p *Progress) speed(elapsed time.Duration) float64 {
	if p.rate > 0 {
		return p.rate
	}
	if elapsed > 0 && p.done > 0 {
		return float64(p.done) / elapsed.Seconds()
	}
	return 0
}

func (p *Progress) eta(elapsed time.Duration) (time.Duration, bool) {
	left := p.total - min(p.done, p.total)
	if left == 0 || p.done == 0 {
		return 0, false
	}
	r := p.speed(elapsed)
	if r <= 0 {
		return 0, false
	}
	return time.Duration(float64(left) / r * float64(time.Second)), true
}

func gradientAt(i, width int) [3]int {
	if width <= 1 {
		return gradientFrom
	}
	var c [3]int
	for k := range c {
		c[k] = gradientFrom[k] + (gradientTo[k]-gradientFrom[k])*i/(width-1)
	}
	return c
}

func rgb(c [3]int, text string) string {
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm%s%s", c[0], c[1], c[2], text, reset)
}

// truecolorTerminal reports whether the terminal advertises 24-bit color.
func truecolorTerminal() bool {
	switch strings.ToLower(os.Getenv("COLORTERM")) {
	case "truecolor", "24bit":
		return true
	}
	return false
}

// terminalWidth returns a function reporting w's current column count, so
// the bar follows window resizes.
func terminalWidth(w io.Writer) func() int {
	f, ok := w.(interface{ Fd() uintptr })
	return func() int {
		if ok {
			if cols, _, err := term.GetSize(int(f.Fd())); err == nil && cols > 0 {
				return cols
			}
		}
		if cols, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && cols > 0 {
			return cols
		}
		return defaultCols
	}
}

// formatRate prints tasks per second with a k/M suffix for fast scans.
func formatRate(r float64) string {
	switch {
	case r >= 1e6:
		return fmt.Sprintf("%.1fM/s", r/1e6)
	case r >= 1e3:
		return fmt.Sprintf("%.1fk/s", r/1e3)
	case r >= 10:
		return fmt.Sprintf("%.0f/s", r)
	default:
		return fmt.Sprintf("%.1f/s", r)
	}
}

// groupDigits writes n with thousands separators, e.g. 65,535.
func groupDigits(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	lead := len(s) % 3
	if lead > 0 {
		b.WriteString(s[:lead])
	}
	for i := lead; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
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
