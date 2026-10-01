package tui

import (
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/matusso/nyxr/internal/capture"
)

func fixture(t *testing.T) []capture.Record {
	t.Helper()
	f, err := os.Open("../../tests/pcaps/phase0.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := capture.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var recs []capture.Record
	for {
		rec, err := r.NextRecord()
		if errors.Is(err, io.EOF) {
			return recs
		}
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rec)
	}
}

var ansi = regexp.MustCompile("\x1b\\[[0-9;]*m")

func screen(b *Browser) string {
	return ansi.ReplaceAllString(strings.Join(b.View(100, 40), "\n"), "")
}

func press(b *Browser, keys ...Key) {
	for _, k := range keys {
		b.Update(k)
	}
}

func r(c rune) Key { return Key{Code: KeyRune, Rune: c} }

func TestViewFillsTheScreen(t *testing.T) {
	b := New("phase0.pcap", fixture(t), true)
	lines := b.View(100, 40)
	if len(lines) != 40 {
		t.Fatalf("got %d lines, want 40", len(lines))
	}
	for i, l := range lines {
		if w := utf8.RuneCountInString(ansi.ReplaceAllString(l, "")); w != 100 {
			t.Fatalf("line %d is %d columns: %q", i, w, l)
		}
	}
	s := screen(b)
	for _, want := range []string{"phase0.pcap", "10 packets", "443 → 50000 [SYN,ACK]", "Packet 1 · TCP", "▾ IPv4", "TTL", "Bytes · 60", "0000  02 00"} {
		if !strings.Contains(s, want) {
			t.Fatalf("screen missing %q:\n%s", want, s)
		}
	}
}

func TestFilterAndNavigation(t *testing.T) {
	b := New("phase0.pcap", fixture(t), false)
	press(b, r('/'))
	for _, c := range "icmp !icmpv6" {
		press(b, r(c))
	}
	press(b, Key{Code: KeyEnter})
	if len(b.view) != 2 {
		t.Fatalf("filter kept %d packets, want 2 ICMPv4", len(b.view))
	}
	if s := screen(b); !strings.Contains(s, "2 of 10 packets") || !strings.Contains(s, "echo request") {
		t.Fatalf("filtered screen:\n%s", s)
	}
	press(b, Key{Code: KeyEnd})
	if b.rows[b.current()].Number != 8 {
		t.Fatalf("End selected packet %d", b.rows[b.current()].Number)
	}
	press(b, Key{Code: KeyEsc})
	if b.filter != "" || len(b.view) != 10 || b.rows[b.current()].Number != 8 {
		t.Fatalf("Esc should clear the filter and keep packet 8 selected: filter %q, %d rows", b.filter, len(b.view))
	}
}

func TestDetailFoldingAndHighlight(t *testing.T) {
	b := New("phase0.pcap", fixture(t), false)
	press(b, Key{Code: KeyTab})
	if b.focus != paneDetail {
		t.Fatal("Tab should focus details")
	}
	// Frame starts folded; the cursor walks Frame, Ethernet, its fields...
	press(b, Key{Code: KeyDown}, Key{Code: KeyDown})
	d := b.lines[b.cursor]
	if b.packet.Layers[d.layer].Name != "Ethernet" || b.packet.Layers[d.layer].Fields[d.field].Name != "Destination" {
		t.Fatalf("cursor on %+v", d)
	}
	if lo, hi, flo, fhi := b.highlight(); lo != 0 || hi != 14 || flo != 0 || fhi != 6 {
		t.Fatalf("highlight %d-%d field %d-%d", lo, hi, flo, fhi)
	}
	if s := screen(b); !strings.Contains(s, "Destination: receiver's NIC") {
		t.Fatalf("footer should explain the field:\n%s", s)
	}
	press(b, Key{Code: KeyLeft}) // to the Ethernet header
	press(b, Key{Code: KeyEnter})
	if !b.collapsed["Ethernet"] || !strings.Contains(screen(b), "▸ Ethernet") {
		t.Fatal("Enter should fold Ethernet")
	}
	press(b, r('n')) // folding sticks on the next packet
	if b.rows[b.current()].Number != 2 || !strings.Contains(screen(b), "▸ Ethernet") {
		t.Fatal("next packet should keep Ethernet folded")
	}
	press(b, r('e'))
	if b.collapsed["Ethernet"] || b.collapsed["Frame"] {
		t.Fatal("e should expand all layers")
	}
}

func TestNoColorKeepsSelectionVisible(t *testing.T) {
	b := New("phase0.pcap", fixture(t), false)
	out := strings.Join(b.View(100, 40), "\n")
	codes := map[string]bool{}
	for _, m := range ansi.FindAllString(out, -1) {
		codes[m] = true
	}
	for c := range codes {
		if c != "\x1b[0m" && c != "\x1b[1m" && c != "\x1b[7m" && c != "\x1b[1;7m" && c != "\x1b[4m" {
			t.Fatalf("no-color view emitted %q", c)
		}
	}
	if !codes["\x1b[7m"] {
		t.Fatal("selected row should be reverse video")
	}
}

func TestHelpAndQuit(t *testing.T) {
	b := New("phase0.pcap", fixture(t), false)
	press(b, r('?'))
	if !strings.Contains(screen(b), "Keys") {
		t.Fatal("help not shown")
	}
	press(b, r('j'))
	if b.help || b.Done() {
		t.Fatal("any key should close help without acting")
	}
	press(b, r('q'))
	if !b.Done() {
		t.Fatal("q should quit")
	}
}

func TestEmptyCapture(t *testing.T) {
	b := New("empty.pcap", nil, false)
	press(b, Key{Code: KeyTab}, Key{Code: KeyDown}, r('n'), Key{Code: KeyEnter}, r('e'))
	if s := screen(b); !strings.Contains(s, "no packets in this capture") {
		t.Fatalf("empty screen:\n%s", s)
	}
}

func TestSanitizeStripsTerminalControls(t *testing.T) {
	b := New("x", nil, false)
	got := b.line(30, false, span{text: "evil\x1b]0;title\x07\x9b2J"})
	if strings.ContainsAny(got, "\x1b\x07") || strings.ContainsRune(got, 0x9b) {
		t.Fatalf("control bytes leaked: %q", got)
	}
}

func TestParseKeys(t *testing.T) {
	got := ParseKeys([]byte("j\x1b[A\x1b[6~\x1bOH\x1b[Z\r\t\x7f\x03é\x1b"))
	want := []Key{r('j'), {Code: KeyUp}, {Code: KeyPgDn}, {Code: KeyHome}, {Code: KeyBackTab}, {Code: KeyEnter},
		{Code: KeyTab}, {Code: KeyBackspace}, {Code: KeyCtrlC}, r('é'), {Code: KeyEsc}}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("key %d: got %+v want %+v", i, got[i], want[i])
		}
	}
}
