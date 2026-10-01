package nmapdb

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// maxFieldLen bounds a substituted version field so a hostile response cannot
// inflate an observation.
const maxFieldLen = 256

// applyTemplate resolves an Nmap version template against a regex submatch.
// It supports $0..$9 group references, $$ for a literal $, and the common
// helpers $P(n), $SUBST(n,"from","to") and $I(n,"<"|">"). Anything it does not
// recognize is emitted literally. The result is trimmed to printable bytes.
func applyTemplate(tmpl string, sub [][]byte) string {
	if tmpl == "" {
		return ""
	}
	if !strings.ContainsRune(tmpl, '$') {
		return clean(tmpl)
	}
	var b strings.Builder
	for i := 0; i < len(tmpl); {
		if tmpl[i] != '$' || i+1 >= len(tmpl) {
			b.WriteByte(tmpl[i])
			i++
			continue
		}
		next := tmpl[i+1]
		switch {
		case next == '$':
			b.WriteByte('$')
			i += 2
		case next >= '0' && next <= '9':
			b.WriteString(group(sub, int(next-'0')))
			i += 2
		case strings.HasPrefix(tmpl[i+1:], "P("):
			args, end, ok := readCall(tmpl, i+2)
			if !ok {
				b.WriteByte('$')
				i++
				continue
			}
			if n, err := strconv.Atoi(strings.TrimSpace(args)); err == nil {
				b.WriteString(group(sub, n))
			}
			i = end
		case strings.HasPrefix(tmpl[i+1:], "SUBST("):
			args, end, ok := readCall(tmpl, i+6)
			if !ok {
				b.WriteByte('$')
				i++
				continue
			}
			b.WriteString(subst(args, sub))
			i = end
		case strings.HasPrefix(tmpl[i+1:], "I("):
			args, end, ok := readCall(tmpl, i+2)
			if !ok {
				b.WriteByte('$')
				i++
				continue
			}
			b.WriteString(integer(args, sub))
			i = end
		default:
			b.WriteByte('$')
			i++
		}
	}
	return clean(b.String())
}

func applyAll(tmpls []string, sub [][]byte) []string {
	if len(tmpls) == 0 {
		return nil
	}
	out := make([]string, 0, len(tmpls))
	for _, t := range tmpls {
		if v := applyTemplate(t, sub); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// readCall returns the text between the parenthesis at s[open] and its match,
// plus the index just past the closing parenthesis. open points at '('.
func readCall(s string, open int) (string, int, bool) {
	if open >= len(s) || s[open] != '(' {
		return "", 0, false
	}
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[open+1 : i], i + 1, true
			}
		}
	}
	return "", 0, false
}

func group(sub [][]byte, n int) string {
	if n < 0 || n >= len(sub) {
		return ""
	}
	return string(sub[n])
}

// subst implements $SUBST(n,"from","to").
func subst(args string, sub [][]byte) string {
	n, rest, ok := strings.Cut(args, ",")
	if !ok {
		return ""
	}
	idx, err := strconv.Atoi(strings.TrimSpace(n))
	if err != nil {
		return ""
	}
	from, to, ok := splitQuotedPair(rest)
	if !ok {
		return group(sub, idx)
	}
	return strings.ReplaceAll(group(sub, idx), from, to)
}

// integer implements $I(n,"<") / $I(n,">") reading the group as an unsigned int.
func integer(args string, sub [][]byte) string {
	n, endian, ok := strings.Cut(args, ",")
	if !ok {
		return ""
	}
	idx, err := strconv.Atoi(strings.TrimSpace(n))
	if err != nil {
		return ""
	}
	raw := []byte(group(sub, idx))
	if len(raw) == 0 || len(raw) > 8 {
		return ""
	}
	buf := make([]byte, 8)
	if strings.Contains(endian, "<") {
		copy(buf, raw)
		return strconv.FormatUint(binary.LittleEndian.Uint64(buf), 10)
	}
	copy(buf[8-len(raw):], raw)
	return strconv.FormatUint(binary.BigEndian.Uint64(buf), 10)
}

// splitQuotedPair parses `"a","b"` into a and b.
func splitQuotedPair(s string) (string, string, bool) {
	s = strings.TrimSpace(s)
	a, rest, ok := readQuoted(s)
	if !ok {
		return "", "", false
	}
	rest = strings.TrimSpace(rest)
	rest = strings.TrimPrefix(rest, ",")
	b, _, ok := readQuoted(strings.TrimSpace(rest))
	if !ok {
		return "", "", false
	}
	return a, b, true
}

func readQuoted(s string) (string, string, bool) {
	if len(s) == 0 || s[0] != '"' {
		return "", s, false
	}
	for i := 1; i < len(s); i++ {
		if s[i] == '"' {
			return s[1:i], s[i+1:], true
		}
	}
	return "", s, false
}

// clean keeps printable ASCII and bounds the length so version fields stay
// readable and cannot be inflated by a hostile response.
func clean(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < maxFieldLen; i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		} else if c == '\t' {
			b.WriteByte(' ')
		}
	}
	return strings.TrimSpace(b.String())
}
