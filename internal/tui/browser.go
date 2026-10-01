// Package tui is nyxr's interactive packet browser: a packet list, a
// layer-by-layer breakdown of the selected packet with a note on what each
// field means, and a hex dump that highlights the bytes of the selected field.
//
// Browser is a pure model (Update for keys, View for a frame of lines) so it
// can be tested without a terminal; Run drives it on a real one.
package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/matusso/nyxr/internal/capture"
	"github.com/matusso/nyxr/internal/dissect"
)

type pane int

const (
	paneList pane = iota
	paneDetail
)

// dline is one row of the detail tree: a layer header (field < 0) or a field.
type dline struct{ layer, field int }

// Browser holds the browsing state for one capture.
type Browser struct {
	name  string
	recs  []capture.Record
	rows  []dissect.Summary
	color bool

	view    []int // indexes into rows that pass the filter
	sel     int   // position in view
	top     int   // first visible list row
	focus   pane
	showHex bool
	help    bool
	quit    bool
	filter  string
	input   *string // filter being edited; nil otherwise

	pkt       int // row index of the dissected packet; -1 when none
	packet    dissect.Packet
	lines     []dline
	collapsed map[string]bool // by layer name, so folding sticks while browsing
	cursor    int
	dtop      int
	hexTop    int

	hasDir     bool
	srcW, dstW int
	numW       int
	listRows   int // visible list rows in the last frame, for paging
	detailRows int
}

// New summarizes every record up front so the list and filter are instant.
func New(name string, recs []capture.Record, color bool) *Browser {
	b := &Browser{name: name, recs: recs, color: color, showHex: true, pkt: -1,
		collapsed: map[string]bool{"Frame": true}}
	var first time.Time
	if len(recs) > 0 {
		first = recs[0].Timestamp
	}
	b.rows = make([]dissect.Summary, len(recs))
	b.srcW, b.dstW = len("Source"), len("Destination")
	for i, r := range recs {
		s := dissect.Summarize(r, i+1, first)
		b.rows[i] = s
		b.srcW = max(b.srcW, min(len(s.Source), 39))
		b.dstW = max(b.dstW, min(len(s.Destination), 39))
		if r.Direction != capture.DirectionUnknown {
			b.hasDir = true
		}
	}
	b.numW = max(3, len(strconv.Itoa(len(recs))))
	b.applyFilter("")
	return b
}

// Done reports whether the user asked to quit.
func (b *Browser) Done() bool { return b.quit }

func (b *Browser) applyFilter(f string) {
	keep := -1
	if b.sel < len(b.view) {
		keep = b.view[b.sel]
	}
	b.filter = strings.TrimSpace(f)
	terms := strings.Fields(strings.ToLower(b.filter))
	b.view = b.view[:0]
	for i, r := range b.rows {
		if matches(r.SearchText(), terms) {
			b.view = append(b.view, i)
		}
	}
	b.sel = 0
	for i, idx := range b.view {
		if idx >= keep {
			b.sel = i
			break
		}
	}
	if len(b.view) == 0 {
		b.focus = paneList
	}
}

// matches requires every term; a term starting with "!" must be absent.
func matches(text string, terms []string) bool {
	for _, t := range terms {
		if neg, ok := strings.CutPrefix(t, "!"); ok {
			if neg != "" && strings.Contains(text, neg) {
				return false
			}
			continue
		}
		if !strings.Contains(text, t) {
			return false
		}
	}
	return true
}

func (b *Browser) current() int {
	if b.sel < 0 || b.sel >= len(b.view) {
		return -1
	}
	return b.view[b.sel]
}

// loadDetail dissects the selected packet, keeping the cursor on the same
// layer and field so stepping through packets compares like with like.
func (b *Browser) loadDetail() {
	idx := b.current()
	if idx == b.pkt {
		return
	}
	var wantLayer, wantField string
	if b.pkt >= 0 && b.cursor < len(b.lines) {
		d := b.lines[b.cursor]
		wantLayer = b.packet.Layers[d.layer].Name
		if d.field >= 0 {
			wantField = b.packet.Layers[d.layer].Fields[d.field].Name
		}
	}
	b.pkt = idx
	if idx < 0 {
		b.packet, b.lines = dissect.Packet{}, nil
		return
	}
	var first time.Time
	if len(b.recs) > 0 {
		first = b.recs[0].Timestamp
	}
	b.packet = dissect.Dissect(b.recs[idx], idx+1, first)
	b.rebuildLines()
	b.cursor = 0
	for i, d := range b.lines {
		l := b.packet.Layers[d.layer]
		if l.Name != wantLayer {
			continue
		}
		if d.field < 0 {
			b.cursor = i
			if wantField == "" {
				break
			}
		} else if l.Fields[d.field].Name == wantField {
			b.cursor = i
			break
		}
	}
}

func (b *Browser) rebuildLines() {
	b.lines = b.lines[:0]
	for li, l := range b.packet.Layers {
		b.lines = append(b.lines, dline{li, -1})
		if b.collapsed[l.Name] {
			continue
		}
		for fi := range l.Fields {
			b.lines = append(b.lines, dline{li, fi})
		}
	}
	b.cursor = clamp(b.cursor, 0, len(b.lines)-1)
}

func (b *Browser) setCollapsed(layer int, on bool) {
	name := b.packet.Layers[layer].Name
	if b.collapsed[name] == on {
		return
	}
	b.collapsed[name] = on
	b.rebuildLines()
	b.cursor = b.headerOf(layer)
}

func (b *Browser) headerOf(layer int) int {
	for i, d := range b.lines {
		if d.layer == layer && d.field < 0 {
			return i
		}
	}
	return b.cursor
}

func clamp(v, lo, hi int) int {
	if v > hi {
		v = hi
	}
	if v < lo {
		v = lo
	}
	return v
}

// Update applies one key press.
func (b *Browser) Update(k Key) {
	if b.input != nil {
		b.editFilter(k)
		return
	}
	if b.help {
		b.help = false
		if k.Code == KeyCtrlC {
			b.quit = true
		}
		return
	}
	switch {
	case k.Code == KeyCtrlC || k.Is('q'):
		b.quit = true
	case k.Is('?'):
		b.help = true
	case k.Is('/'):
		s := b.filter
		b.input = &s
	case k.Code == KeyTab || k.Code == KeyBackTab:
		if b.focus == paneList && b.current() >= 0 {
			b.focus = paneDetail
		} else {
			b.focus = paneList
		}
	case k.Code == KeyEsc:
		if b.focus == paneDetail {
			b.focus = paneList
		} else if b.filter != "" {
			b.applyFilter("")
		}
	case k.Is('x'):
		b.showHex = !b.showHex
	case k.Is('n'):
		b.moveSel(1)
	case k.Is('p'):
		b.moveSel(-1)
	case k.Is('e'), k.Is('c'):
		b.loadDetail()
		for _, l := range b.packet.Layers {
			b.collapsed[l.Name] = k.Is('c')
		}
		b.rebuildLines()
	case b.focus == paneList:
		b.listKey(k)
	default:
		b.detailKey(k)
	}
}

func (b *Browser) moveSel(delta int) {
	b.sel = clamp(b.sel+delta, 0, len(b.view)-1)
}

func page(rows int) int { return max(1, rows-1) }

func (b *Browser) listKey(k Key) {
	switch {
	case k.Code == KeyUp || k.Is('k'):
		b.moveSel(-1)
	case k.Code == KeyDown || k.Is('j'):
		b.moveSel(1)
	case k.Code == KeyPgUp || k.Code == KeyCtrlB:
		b.moveSel(-page(b.listRows))
	case k.Code == KeyPgDn || k.Code == KeyCtrlF || k.Is(' '):
		b.moveSel(page(b.listRows))
	case k.Code == KeyCtrlU:
		b.moveSel(-max(1, b.listRows/2))
	case k.Code == KeyCtrlD:
		b.moveSel(max(1, b.listRows/2))
	case k.Code == KeyHome || k.Is('g'):
		b.sel = 0
	case k.Code == KeyEnd || k.Is('G'):
		b.sel = max(0, len(b.view)-1)
	case k.Code == KeyEnter || k.Code == KeyRight || k.Is('l'):
		if b.current() >= 0 {
			b.focus = paneDetail
		}
	}
}

func (b *Browser) detailKey(k Key) {
	b.loadDetail()
	if len(b.lines) == 0 {
		return
	}
	d := b.lines[b.cursor]
	move := func(delta int) { b.cursor = clamp(b.cursor+delta, 0, len(b.lines)-1) }
	switch {
	case k.Code == KeyUp || k.Is('k'):
		move(-1)
	case k.Code == KeyDown || k.Is('j'):
		move(1)
	case k.Code == KeyPgUp || k.Code == KeyCtrlB:
		move(-page(b.detailRows))
	case k.Code == KeyPgDn || k.Code == KeyCtrlF:
		move(page(b.detailRows))
	case k.Code == KeyCtrlU:
		move(-max(1, b.detailRows/2))
	case k.Code == KeyCtrlD:
		move(max(1, b.detailRows/2))
	case k.Code == KeyHome || k.Is('g'):
		b.cursor = 0
	case k.Code == KeyEnd || k.Is('G'):
		b.cursor = len(b.lines) - 1
	case k.Code == KeyEnter || k.Is(' '):
		b.setCollapsed(d.layer, !b.collapsed[b.packet.Layers[d.layer].Name])
	case k.Code == KeyLeft || k.Is('h'):
		// On a field: jump to its layer. On an open layer: fold it. On a
		// folded layer: go to the previous layer.
		switch {
		case d.field >= 0:
			b.cursor = b.headerOf(d.layer)
		case !b.collapsed[b.packet.Layers[d.layer].Name]:
			b.setCollapsed(d.layer, true)
		case d.layer > 0:
			b.cursor = b.headerOf(d.layer - 1)
		}
	case k.Code == KeyRight || k.Is('l'):
		if d.field < 0 {
			b.setCollapsed(d.layer, false)
		}
	}
}

func (b *Browser) editFilter(k Key) {
	s := *b.input
	switch k.Code {
	case KeyEnter:
		b.input = nil
		b.applyFilter(s)
		return
	case KeyEsc, KeyCtrlC:
		b.input = nil
		return
	case KeyBackspace:
		if s != "" {
			_, n := utf8.DecodeLastRuneInString(s)
			s = s[:len(s)-n]
		}
	case KeyCtrlU:
		s = ""
	case KeyRune:
		s += string(k.Rune)
	}
	b.input = &s
}

// View renders a full frame of exactly height lines, each width columns wide.
func (b *Browser) View(width, height int) []string {
	if width < 20 || height < 8 {
		return []string{b.line(width, false, span{text: "terminal too small"})}
	}
	if b.help {
		return b.helpView(width, height)
	}
	b.loadDetail()
	avail := height - 2 // title bar and footer
	hexH := 0
	if b.showHex && b.pkt >= 0 {
		hexH = min((len(b.recs[b.pkt].Data)+15)/16, max(3, avail/4)) + 1
	}
	listH := max(4, (avail-hexH)*2/5)
	detailH := avail - hexH - listH - 1
	if detailH < 2 {
		hexH = 0
		detailH = avail - listH - 1
	}
	out := make([]string, 0, height)
	out = append(out, b.titleBar(width))
	out = append(out, b.listView(width, listH)...)
	out = append(out, b.detailView(width, detailH)...)
	if hexH > 0 {
		out = append(out, b.hexView(width, hexH)...)
	}
	out = append(out, b.footer(width))
	return out
}

func (b *Browser) titleBar(w int) string {
	spans := []span{{text: " nyxr ", sgr: "1;97;44", attr: "1"}, {text: " " + b.name + " ", sgr: "1"}}
	count := fmt.Sprintf("%d packets", len(b.rows))
	if b.filter != "" {
		count = fmt.Sprintf("%d of %d packets", len(b.view), len(b.rows))
	}
	spans = append(spans, span{text: count, sgr: "2"})
	if b.filter != "" {
		spans = append(spans, span{text: "  filter: ", sgr: "2"}, span{text: b.filter, sgr: "33"})
	}
	return b.line(w, false, spans...)
}

func protoColor(p string) string {
	switch p {
	case "TCP":
		return "36"
	case "UDP":
		return "34"
	case "ICMP", "ICMPv6":
		return "35"
	case "ARP":
		return "33"
	case "DNS":
		return "32"
	}
	return ""
}

func toneColor(t dissect.Tone) string {
	switch t {
	case dissect.ToneOpen:
		return "32"
	case dissect.ToneClosed, dissect.ToneError:
		return "31"
	case dissect.ToneFilter:
		return "33"
	}
	return ""
}

func pad(s string, n int) string {
	if r := utf8.RuneCountInString(s); r < n {
		return s + strings.Repeat(" ", n-r)
	}
	return truncate(s, n)
}

func padLeft(s string, n int) string {
	if r := utf8.RuneCountInString(s); r < n {
		return strings.Repeat(" ", n-r) + s
	}
	return s
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	if n <= 1 {
		return string([]rune(s)[:max(n, 0)])
	}
	return string([]rune(s)[:n-1]) + "…"
}

func (b *Browser) listView(w, h int) []string {
	rows := h - 1
	b.listRows = rows
	if b.sel < b.top {
		b.top = b.sel
	}
	if b.sel >= b.top+rows {
		b.top = b.sel - rows + 1
	}
	b.top = clamp(b.top, 0, max(0, len(b.view)-rows))
	header := []span{{text: padLeft("No.", b.numW) + "  " + padLeft("Time", 11) + " "}}
	if b.hasDir {
		header = append(header, span{text: "  "})
	}
	header = append(header, span{text: pad("Source", b.srcW) + "  " + pad("Destination", b.dstW) + "  " + pad("Proto", 8) + " " + padLeft("Len", 5) + "  Info"})
	for i := range header {
		header[i].sgr, header[i].attr = "1;4", "1"
	}
	out := []string{b.line(w, false, header...)}
	for i := 0; i < rows; i++ {
		pos := b.top + i
		if pos >= len(b.view) {
			if i == 0 && len(b.view) == 0 {
				msg := "no packets in this capture"
				if b.filter != "" {
					msg = "no packets match the filter (Esc clears it)"
				}
				out = append(out, b.line(w, false, span{text: "  " + msg, sgr: "2"}))
				continue
			}
			out = append(out, b.line(w, false))
			continue
		}
		r := b.rows[b.view[pos]]
		sel := pos == b.sel
		spans := []span{
			{text: padLeft(strconv.Itoa(r.Number), b.numW) + "  ", sgr: "90"},
			{text: padLeft(fmt.Sprintf("%.6f", r.Elapsed.Seconds()), 11) + " ", sgr: "2"},
		}
		if b.hasDir {
			dir, c := " ", ""
			switch r.Direction {
			case capture.DirectionTX:
				dir, c = "↑", "36"
			case capture.DirectionRX:
				dir, c = "↓", "32"
			}
			spans = append(spans, span{text: dir + " ", sgr: c})
		}
		spans = append(spans,
			span{text: pad(r.Source, b.srcW) + "  "},
			span{text: pad(r.Destination, b.dstW) + "  "},
			span{text: pad(r.Protocol, 8) + " ", sgr: protoColor(r.Protocol)},
			span{text: padLeft(strconv.Itoa(r.Length), 5) + "  ", sgr: "2"},
			span{text: r.Info, sgr: toneColor(r.Tone)},
		)
		out = append(out, b.line(w, sel, spans...))
	}
	return out
}

func (b *Browser) separator(w int, title string, focused bool) string {
	sgr := "2"
	if focused {
		sgr = "1;36"
	}
	t := "── " + title + " "
	return b.line(w, false, span{text: t, sgr: sgr}, span{text: strings.Repeat("─", max(0, w-utf8.RuneCountInString(t))), sgr: "2"})
}

func (b *Browser) detailView(w, h int) []string {
	title := "Packet"
	if b.pkt >= 0 {
		title = fmt.Sprintf("Packet %d · %s", b.rows[b.pkt].Number, b.rows[b.pkt].Protocol)
	}
	out := []string{b.separator(w, title, b.focus == paneDetail)}
	rows := h
	b.detailRows = rows
	if b.cursor < b.dtop {
		b.dtop = b.cursor
	}
	if b.cursor >= b.dtop+rows {
		b.dtop = b.cursor - rows + 1
	}
	b.dtop = clamp(b.dtop, 0, max(0, len(b.lines)-rows))
	for i := 0; i < rows; i++ {
		pos := b.dtop + i
		if pos >= len(b.lines) {
			out = append(out, b.line(w, false))
			continue
		}
		out = append(out, b.detailLine(w, pos))
	}
	return out
}

func (b *Browser) detailLine(w, pos int) string {
	d := b.lines[pos]
	l := b.packet.Layers[d.layer]
	sel := pos == b.cursor && b.focus == paneDetail
	if d.field < 0 {
		mark := "▾ "
		if b.collapsed[l.Name] {
			mark = "▸ "
		}
		return b.line(w, sel, span{text: mark, sgr: "2"}, span{text: l.Name, sgr: "1;36", attr: "1"}, span{text: "  " + l.Summary, sgr: "2"})
	}
	nameW := 0
	for _, f := range l.Fields {
		nameW = max(nameW, utf8.RuneCountInString(f.Name)+2*f.Indent)
	}
	f := l.Fields[d.field]
	indent := strings.Repeat("  ", f.Indent)
	spans := []span{
		{text: "    " + indent},
		{text: pad(f.Name, nameW-2*f.Indent) + "  ", sgr: "36"},
		{text: f.Value, sgr: "1", attr: ""},
	}
	if f.Note != "" {
		spans = append(spans, span{text: "  " + f.Note, sgr: "90"})
	}
	return b.line(w, sel, spans...)
}

// highlight returns the byte ranges of the selected layer and field.
func (b *Browser) highlight() (lo, hi, flo, fhi int) {
	if b.focus != paneDetail || b.cursor >= len(b.lines) {
		return -1, -1, -1, -1
	}
	d := b.lines[b.cursor]
	l := b.packet.Layers[d.layer]
	lo, hi, flo, fhi = l.Offset, l.Offset+l.Length, -1, -1
	if l.Name == "Frame" {
		lo, hi = -1, -1
	}
	if d.field >= 0 {
		f := l.Fields[d.field]
		if f.Length > 0 {
			flo, fhi = f.Offset, f.Offset+f.Length
		}
	}
	return
}

func (b *Browser) hexView(w, h int) []string {
	data := b.recs[b.pkt].Data
	out := []string{b.separator(w, fmt.Sprintf("Bytes · %d", len(data)), false)}
	rows := h - 1
	total := (len(data) + 15) / 16
	lo, hi, flo, fhi := b.highlight()
	anchor := flo
	if anchor < 0 {
		anchor = lo
	}
	if anchor >= 0 {
		line := anchor / 16
		if line < b.hexTop || line >= b.hexTop+rows {
			b.hexTop = line
		}
	}
	b.hexTop = clamp(b.hexTop, 0, max(0, total-rows))
	for i := 0; i < rows; i++ {
		row := b.hexTop + i
		if row >= total {
			out = append(out, b.line(w, false))
			continue
		}
		spans := []span{{text: fmt.Sprintf("%04x  ", row*16), sgr: "90"}}
		var ascii []span
		for j := 0; j < 16; j++ {
			at := row*16 + j
			sep := " "
			if j == 7 {
				sep = "  "
			}
			if at >= len(data) {
				spans = append(spans, span{text: "  " + sep})
				continue
			}
			s := span{}
			switch {
			case at >= flo && at < fhi:
				s.sgr, s.attr = "30;43", "7"
			case at >= lo && at < hi:
				s.sgr, s.attr = "36", "4"
			}
			c := data[at]
			hexS := s
			hexS.text = fmt.Sprintf("%02x", c)
			spans = append(spans, hexS, span{text: sep})
			ch := "."
			if c >= 0x20 && c < 0x7f {
				ch = string(rune(c))
			}
			s.text = ch
			if s.sgr == "" {
				s.sgr = "2"
			}
			ascii = append(ascii, s)
		}
		spans = append(spans, span{text: " "})
		out = append(out, b.line(w, false, append(spans, ascii...)...))
	}
	return out
}

func (b *Browser) footer(w int) string {
	if b.input != nil {
		return b.line(w, false, span{text: "/", sgr: "1;33", attr: "1"}, span{text: *b.input}, span{text: "█", sgr: "33"},
			span{text: "   Enter apply · Esc cancel · words must all match, !word excludes", sgr: "90"})
	}
	if b.focus == paneDetail && b.cursor < len(b.lines) {
		d := b.lines[b.cursor]
		if d.field >= 0 {
			if f := b.packet.Layers[d.layer].Fields[d.field]; f.Note != "" {
				return b.line(w, false, span{text: " " + f.Name + ": ", sgr: "1;36", attr: "1"}, span{text: f.Note})
			}
		}
	}
	keys := []string{"↑↓", "move", "Tab", "pane", "Enter", "fold", "/", "filter", "n/p", "next/prev", "x", "hex", "?", "help", "q", "quit"}
	var spans []span
	for i := 0; i < len(keys); i += 2 {
		spans = append(spans, span{text: " " + keys[i], sgr: "1;33", attr: "1"}, span{text: " " + keys[i+1] + " ", sgr: "2"})
	}
	return b.line(w, false, spans...)
}

func (b *Browser) helpView(w, h int) []string {
	type entry struct{ k, v string }
	entries := []entry{
		{"", "Keys"},
		{"↑ ↓  j k", "move in the focused pane"},
		{"PgUp PgDn  ^B ^F", "page up / down (^U ^D half a page)"},
		{"Home End  g G", "first / last"},
		{"Tab  Enter", "switch between packet list and packet details"},
		{"Enter  Space", "fold or unfold a layer (details)"},
		{"← →  h l", "fold / unfold, or jump to the layer header"},
		{"e  c", "expand / collapse every layer"},
		{"n  p", "next / previous packet from either pane"},
		{"/", "filter: words must all match (ip, port, protocol, flag); !word excludes"},
		{"Esc", "back to the list, then clear the filter"},
		{"x", "show or hide the hex dump"},
		{"q  ^C", "quit"},
		{"", ""},
		{"", "Colors"},
		{"green", "the reply shows something open or alive: SYN-ACK, echo reply, DNS answer"},
		{"red", "closed or broken: RST, ICMP port unreachable, malformed frame"},
		{"yellow", "filtered: ICMP unreachable from a firewall or router"},
		{"↑ ↓", "sent / received by the scanner (nyxr pcapng captures)"},
		{"hex", "underline = selected layer's bytes, highlight = selected field's bytes"},
		{"", ""},
		{"", "Press any key to return."},
	}
	out := []string{b.titleBar(w)}
	for _, e := range entries {
		if len(out) >= h {
			break
		}
		if e.k == "" {
			out = append(out, b.line(w, false, span{text: "  " + e.v, sgr: "1;36", attr: "1"}))
			continue
		}
		out = append(out, b.line(w, false, span{text: "    " + pad(e.k, 18), sgr: "1;33", attr: "1"}, span{text: e.v}))
	}
	for len(out) < h {
		out = append(out, b.line(w, false))
	}
	return out
}

// span is a run of text with color (sgr) and a monochrome attribute (attr)
// used when color is off, so selection and highlights still show under
// --no-color.
type span struct{ text, sgr, attr string }

// line renders spans into exactly w columns. Packet bytes, names and comments
// come from the capture, so control characters are replaced before they can
// reach the terminal.
func (b *Browser) line(w int, selected bool, spans ...span) string {
	var out strings.Builder
	left := w
	for _, s := range spans {
		if left <= 0 {
			break
		}
		text := truncate(sanitize(s.text), left)
		left -= utf8.RuneCountInString(text)
		code := s.attr
		if b.color {
			code = s.sgr
		}
		if selected {
			code = joinCodes(code, "7")
		}
		if code != "" {
			out.WriteString("\x1b[" + code + "m" + text + "\x1b[0m")
		} else {
			out.WriteString(text)
		}
	}
	if left > 0 {
		fill := strings.Repeat(" ", left)
		if selected {
			fill = "\x1b[7m" + fill + "\x1b[0m"
		}
		out.WriteString(fill)
	}
	return out.String()
}

func joinCodes(a, b string) string {
	if a == "" {
		return b
	}
	return a + ";" + b
}

func sanitize(s string) string {
	clean := true
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == utf8.RuneError {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var out strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == utf8.RuneError {
			r = '.'
		}
		out.WriteRune(r)
	}
	return out.String()
}
