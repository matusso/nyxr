// Package ui renders nyxr's terminal output. The same rendering code serves
// terminals, pipes and tests: a Styler emits ANSI SGR escapes when the writer
// is an interactive terminal, and returns text unchanged otherwise, so piped
// or captured output stays plain and parseable.
package ui

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/mattn/go-isatty"
)

// Styler wraps text in ANSI color codes. A disabled Styler is a transparent
// pass-through, so callers write one formatting path for both modes.
type Styler struct{ on bool }

// New decides whether to color output written to w. Color is disabled when the
// caller passes disabled (the --no-color flag), when the NO_COLOR environment
// variable is present with any value (https://no-color.org), or when w is not
// a terminal (a pipe, file or test buffer).
func New(w io.Writer, disabled bool) *Styler {
	return &Styler{on: colorEnabled(w, disabled)}
}

// Plain returns a Styler that never emits color.
func Plain() *Styler { return &Styler{on: false} }

func colorEnabled(w io.Writer, disabled bool) bool {
	if disabled {
		return false
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	f, ok := w.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	fd := f.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

// Enabled reports whether this Styler emits color.
func (s *Styler) Enabled() bool { return s != nil && s.on }

const reset = "\x1b[0m"

func (s *Styler) paint(code, text string) string {
	if !s.Enabled() || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + reset
}

// Base styles.
func (s *Styler) Bold(t string) string     { return s.paint("1", t) }
func (s *Styler) Dim(t string) string      { return s.paint("2", t) }
func (s *Styler) Red(t string) string      { return s.paint("31", t) }
func (s *Styler) Green(t string) string    { return s.paint("32", t) }
func (s *Styler) Yellow(t string) string   { return s.paint("33", t) }
func (s *Styler) Blue(t string) string     { return s.paint("34", t) }
func (s *Styler) Magenta(t string) string  { return s.paint("35", t) }
func (s *Styler) Cyan(t string) string     { return s.paint("36", t) }
func (s *Styler) Gray(t string) string     { return s.paint("90", t) }
func (s *Styler) BoldCyan(t string) string { return s.paint("1;36", t) }

// Header styles a table header row.
func (s *Styler) Header(t string) string { return s.paint("1;4", t) }

// Key styles a left-hand label in a key/value listing (plans, summaries).
func (s *Styler) Key(t string) string { return s.paint("36", t) }

// pad right-aligns the padding after colored content, measuring the padding
// against the plain-text width so ANSI escapes do not throw columns off.
func pad(colored string, plainWidth, width int) string {
	if plainWidth >= width {
		return colored
	}
	return colored + strings.Repeat(" ", width-plainWidth)
}

func padLeft(colored string, plainWidth, width int) string {
	if plainWidth >= width {
		return colored
	}
	return strings.Repeat(" ", width-plainWidth) + colored
}

// stateGlyph is the leading mark for a discovery state.
func stateGlyph(state string) string {
	switch state {
	case "open", "responsive", "up", "identified":
		return "●"
	case "open|filtered", "filtered", "unfiltered":
		return "◐"
	case "closed", "down":
		return "○"
	default:
		return "·"
	}
}

func (s *Styler) stateColor(state, text string) string {
	switch state {
	case "open", "responsive", "up", "identified":
		return s.Green(text)
	case "open|filtered", "filtered", "unfiltered":
		return s.Yellow(text)
	case "closed", "down":
		return s.Red(text)
	case "unknown":
		return s.Dim(text)
	default:
		return text
	}
}

// StateText colors a discovery state word (open, closed, filtered, ...).
func (s *Styler) StateText(state string) string { return s.stateColor(state, state) }

// Confidence colors a percentage by how strong the claim is.
func (s *Styler) Confidence(c int) string {
	txt := strconv.Itoa(c) + "%"
	switch {
	case c >= 80:
		return s.Green(txt)
	case c >= 50:
		return s.Yellow(txt)
	case c > 0:
		return s.Red(txt)
	default:
		return s.Dim(txt)
	}
}

// Column widths shared by every scanner line so they align in a column.
const (
	addrWidth  = 21 // 255.255.255.255:65535
	transWidth = 5
	stateWidth = 14
	confWidth  = 4 // "100%"
)

func portSuffix(port uint16) string {
	if port == 0 {
		return ""
	}
	return ":" + strconv.Itoa(int(port))
}

// Discovery renders one host, port or research result line, without a trailing
// newline. In plain mode it reproduces nyxr's original fixed-width layout so
// scripts and stored output are unchanged.
func (s *Styler) Discovery(target string, port uint16, transport, state string, confidence int, reason string) string {
	portStr := portSuffix(port)
	if !s.Enabled() {
		return fmt.Sprintf("%s%s %-5s %-14s %3d%% %s", target, portStr, transport, state, confidence, reason)
	}
	addrPlain := target + portStr
	addr := s.Bold(target) + s.Cyan(portStr)
	var b strings.Builder
	b.WriteString(s.stateColor(state, stateGlyph(state)))
	b.WriteByte(' ')
	b.WriteString(pad(addr, len(addrPlain), addrWidth))
	b.WriteByte(' ')
	b.WriteString(pad(s.Dim(transport), len(transport), transWidth))
	b.WriteByte(' ')
	b.WriteString(pad(s.stateColor(state, state), len(state), stateWidth))
	b.WriteByte(' ')
	b.WriteString(padLeft(s.Confidence(confidence), len(strconv.Itoa(confidence))+1, confWidth))
	b.WriteByte(' ')
	b.WriteString(s.Dim(reason))
	return b.String()
}

// ServiceHead renders the left, fixed-width part of a service line (through the
// confidence column). The caller appends the variable detail list. In plain
// mode it matches the original "svc <name>" layout.
func (s *Styler) ServiceHead(target string, port uint16, transport, name string, confidence int) string {
	portStr := portSuffix(port)
	label := "svc " + name
	if !s.Enabled() {
		return fmt.Sprintf("%s%s %-5s %-14s %3d%%", target, portStr, transport, label, confidence)
	}
	addrPlain := target + portStr
	addr := s.Bold(target) + s.Cyan(portStr)
	labelColored := s.Dim("svc ") + s.BoldCyan(name)
	var b strings.Builder
	b.WriteString(s.Cyan("◆"))
	b.WriteByte(' ')
	b.WriteString(pad(addr, len(addrPlain), addrWidth))
	b.WriteByte(' ')
	b.WriteString(pad(s.Dim(transport), len(transport), transWidth))
	b.WriteByte(' ')
	b.WriteString(pad(labelColored, len(label), stateWidth))
	b.WriteByte(' ')
	b.WriteString(padLeft(s.Confidence(confidence), len(strconv.Itoa(confidence))+1, confWidth))
	return b.String()
}

// Detail dims one service detail (banner, TLS summary, page title).
func (s *Styler) Detail(text string) string { return s.Dim(text) }

// JoinDetails joins service details with a separator that matches the mode:
// " | " in plain output, a dimmed middot in color.
func (s *Styler) JoinDetails(details []string) string {
	if !s.Enabled() {
		return strings.Join(details, " | ")
	}
	colored := make([]string, len(details))
	for i, d := range details {
		colored[i] = s.Dim(d)
	}
	return strings.Join(colored, s.Dim(" · "))
}

// Device renders a device-classification line without a trailing newline.
func (s *Styler) Device(target, class string, confidence, signals int) string {
	if !s.Enabled() {
		return fmt.Sprintf("%s device %-20s %3d%% %d signals", target, class, confidence, signals)
	}
	var b strings.Builder
	b.WriteString(s.Magenta("⬢"))
	b.WriteByte(' ')
	b.WriteString(pad(s.Bold(target), len(target), addrWidth))
	b.WriteByte(' ')
	b.WriteString(s.Dim("device"))
	b.WriteByte(' ')
	b.WriteString(pad(s.paint("1;35", class), len(class), 20))
	b.WriteByte(' ')
	b.WriteString(padLeft(s.Confidence(confidence), len(strconv.Itoa(confidence))+1, confWidth))
	b.WriteByte(' ')
	b.WriteString(s.Dim(strconv.Itoa(signals) + " signals"))
	return b.String()
}

// Evidence renders a packet-evidence line without a trailing newline.
func (s *Styler) Evidence(target string, port uint16, transport string, count int, capture, ids string, truncated bool) string {
	portStr := portSuffix(port)
	more := ""
	if truncated {
		more = " (index truncated)"
	}
	if !s.Enabled() {
		return fmt.Sprintf("%s%s %-5s evidence       %d packets in %s: %s%s", target, portStr, transport, count, capture, ids, more)
	}
	addr := s.Bold(target) + s.Cyan(portStr)
	addrPlain := target + portStr
	var b strings.Builder
	b.WriteString(s.Gray("▸"))
	b.WriteByte(' ')
	b.WriteString(pad(addr, len(addrPlain), addrWidth))
	b.WriteByte(' ')
	b.WriteString(pad(s.Dim(transport), len(transport), transWidth))
	b.WriteByte(' ')
	b.WriteString(s.Dim("evidence"))
	b.WriteByte(' ')
	b.WriteString(s.Cyan(strconv.Itoa(count)))
	b.WriteString(s.Dim(" packets in " + capture + ": "))
	b.WriteString(s.Dim(ids))
	if more != "" {
		b.WriteString(s.Yellow(more))
	}
	return b.String()
}

// ScanSummary renders the closing scan summary line without a trailing newline.
func (s *Styler) ScanSummary(id, status string, observations, services int, tail string) string {
	if !s.Enabled() {
		line := fmt.Sprintf("scan %s %s: %d observations, %d services identified", id, status, observations, services)
		return line + tail
	}
	glyph, colored := s.statusMark(status)
	var b strings.Builder
	b.WriteString(glyph)
	b.WriteByte(' ')
	b.WriteString(s.Dim("scan "))
	b.WriteString(s.Dim(id))
	b.WriteByte(' ')
	b.WriteString(colored)
	b.WriteString(s.Dim(": "))
	b.WriteString(s.Bold(strconv.Itoa(observations)))
	b.WriteString(s.Dim(" observations, "))
	b.WriteString(s.Bold(strconv.Itoa(services)))
	b.WriteString(s.Dim(" services identified"))
	if tail != "" {
		b.WriteString(s.Dim(tail))
	}
	return b.String()
}

// visibleWidth counts rune columns, skipping ANSI SGR escapes so colored and
// plain cells measure the same.
func visibleWidth(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			i += 2
			for i < len(s) && s[i] != 'm' {
				i++
			}
			if i < len(s) {
				i++ // consume the terminating 'm'
			}
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		n++
	}
	return n
}

// Table writes rows in left-aligned columns separated by two spaces, measuring
// visible width so ANSI color never disturbs the layout. It replaces
// text/tabwriter, which counts escape bytes and would misalign colored cells.
// The first row is treated as the header. Cells are written as given; color
// them before calling.
func (s *Styler) Table(out io.Writer, rows [][]string) error {
	if len(rows) == 0 {
		return nil
	}
	cols := 0
	for _, r := range rows {
		if len(r) > cols {
			cols = len(r)
		}
	}
	width := make([]int, cols)
	for _, r := range rows {
		for c, cell := range r {
			if w := visibleWidth(cell); w > width[c] {
				width[c] = w
			}
		}
	}
	for _, r := range rows {
		var b strings.Builder
		for c := 0; c < cols; c++ {
			cell := ""
			if c < len(r) {
				cell = r[c]
			}
			b.WriteString(cell)
			if c < cols-1 {
				b.WriteString(strings.Repeat(" ", width[c]-visibleWidth(cell)+2))
			}
		}
		if _, err := fmt.Fprintln(out, strings.TrimRight(b.String(), " ")); err != nil {
			return err
		}
	}
	return nil
}

func (s *Styler) statusMark(status string) (glyph, colored string) {
	switch status {
	case "completed":
		return s.Green("✓"), s.Green(status)
	case "failed":
		return s.Red("✗"), s.Red(status)
	case "running":
		return s.Yellow("…"), s.Yellow(status)
	default:
		return s.Dim("•"), s.Dim(status)
	}
}
