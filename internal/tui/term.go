package tui

import (
	"errors"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

// KeyCode identifies a non-printable key; printable keys are KeyRune.
type KeyCode int

const (
	KeyRune KeyCode = iota
	KeyUp
	KeyDown
	KeyLeft
	KeyRight
	KeyPgUp
	KeyPgDn
	KeyHome
	KeyEnd
	KeyEnter
	KeyEsc
	KeyTab
	KeyBackTab
	KeyBackspace
	KeyCtrlB
	KeyCtrlC
	KeyCtrlD
	KeyCtrlF
	KeyCtrlU
	KeyCtrlL
)

// Key is one decoded key press.
type Key struct {
	Code KeyCode
	Rune rune
}

// Is reports whether k is the printable rune r.
func (k Key) Is(r rune) bool { return k.Code == KeyRune && k.Rune == r }

// ParseKeys decodes one read from a raw-mode terminal. A lone ESC is the
// Escape key; ESC [ and ESC O start cursor and paging sequences.
func ParseKeys(b []byte) []Key {
	var keys []Key
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == 0x1b:
			if i+1 < len(b) && (b[i+1] == '[' || b[i+1] == 'O') {
				j := i + 2
				for j < len(b) && (b[j] < 0x40 || b[j] > 0x7e) {
					j++
				}
				if j >= len(b) {
					return append(keys, Key{Code: KeyEsc})
				}
				if k, ok := csiKey(string(b[i+2:j]), b[j]); ok {
					keys = append(keys, k)
				}
				i = j + 1
				continue
			}
			keys = append(keys, Key{Code: KeyEsc})
			i++
			continue
		case c == '\r' || c == '\n':
			keys = append(keys, Key{Code: KeyEnter})
		case c == '\t':
			keys = append(keys, Key{Code: KeyTab})
		case c == 0x7f || c == 0x08:
			keys = append(keys, Key{Code: KeyBackspace})
		case c < 0x20:
			if code, ok := map[byte]KeyCode{0x02: KeyCtrlB, 0x03: KeyCtrlC, 0x04: KeyCtrlD, 0x06: KeyCtrlF, 0x0c: KeyCtrlL, 0x15: KeyCtrlU}[c]; ok {
				keys = append(keys, Key{Code: code})
			}
		default:
			r, n := utf8.DecodeRune(b[i:])
			keys = append(keys, Key{Code: KeyRune, Rune: r})
			i += n
			continue
		}
		i++
	}
	return keys
}

func csiKey(params string, final byte) (Key, bool) {
	switch final {
	case 'A':
		return Key{Code: KeyUp}, true
	case 'B':
		return Key{Code: KeyDown}, true
	case 'C':
		return Key{Code: KeyRight}, true
	case 'D':
		return Key{Code: KeyLeft}, true
	case 'H':
		return Key{Code: KeyHome}, true
	case 'F':
		return Key{Code: KeyEnd}, true
	case 'Z':
		return Key{Code: KeyBackTab}, true
	case '~':
		p, _, _ := strings.Cut(params, ";")
		switch p {
		case "1", "7":
			return Key{Code: KeyHome}, true
		case "4", "8":
			return Key{Code: KeyEnd}, true
		case "5":
			return Key{Code: KeyPgUp}, true
		case "6":
			return Key{Code: KeyPgDn}, true
		}
	}
	return Key{}, false
}

// Run shows b full screen on the terminal attached to in and out until the
// user quits. The terminal is restored on return.
func Run(in, out *os.File, b *Browser) error {
	inFd, outFd := int(in.Fd()), int(out.Fd())
	if !term.IsTerminal(inFd) || !term.IsTerminal(outFd) {
		return errors.New("the packet browser needs an interactive terminal (drop --tui to print a summary)")
	}
	state, err := term.MakeRaw(inFd)
	if err != nil {
		return err
	}
	defer term.Restore(inFd, state)
	out.WriteString("\x1b[?1049h\x1b[?25l") // alternate screen, hide cursor
	defer out.WriteString("\x1b[?25h\x1b[?1049l")

	input := make(chan []byte, 16)
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := in.Read(buf)
			if err != nil {
				close(input)
				return
			}
			input <- append([]byte(nil), buf[:n]...)
		}
	}()
	// Polling the size keeps resize handling portable (no SIGWINCH on Windows).
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	w, h, dirty := 0, 0, true
	for {
		if nw, nh, err := term.GetSize(outFd); err == nil && (nw != w || nh != h) {
			w, h, dirty = nw, nh, true
		}
		if dirty {
			if _, err := out.WriteString(frame(b.View(w, h))); err != nil {
				return err
			}
			dirty = false
		}
		select {
		case data, ok := <-input:
			if !ok {
				return nil
			}
			for _, k := range ParseKeys(data) {
				if k.Code == KeyCtrlL {
					w = 0 // force a full redraw
				}
				b.Update(k)
			}
			if b.Done() {
				return nil
			}
			dirty = true
		case <-tick.C:
		}
	}
}

func frame(lines []string) string {
	var s strings.Builder
	s.WriteString("\x1b[H")
	for i, l := range lines {
		s.WriteString(l)
		s.WriteString("\x1b[K")
		if i < len(lines)-1 {
			s.WriteString("\r\n")
		}
	}
	s.WriteString("\x1b[J")
	return s.String()
}
