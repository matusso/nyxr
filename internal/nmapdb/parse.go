package nmapdb

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// maxFile bounds the database we will read. The real nmap-service-probes file
// is a few megabytes; this leaves generous headroom without allowing a huge
// untrusted file to exhaust memory.
const maxFile = 16 << 20

// LoadFile reads and compiles an nmap-service-probes file from disk.
func LoadFile(path string) (*Database, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f, path)
}

// Parse compiles an nmap-service-probes stream. The source is recorded as
// provenance. Unparsable directives and patterns RE2 cannot compile are
// counted and noted rather than failing the whole import.
func Parse(r io.Reader, source string) (*Database, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxFile {
		return nil, fmt.Errorf("nmap-service-probes file exceeds %d bytes", maxFile)
	}
	sum := sha256.Sum256(raw)
	db := &Database{Source: source, SHA256: hex.EncodeToString(sum[:])}

	var current *Probe
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keyword, rest, _ := strings.Cut(line, " ")
		switch keyword {
		case "Probe":
			p, ok := db.parseProbe(rest, lineNo)
			if !ok {
				continue
			}
			db.Probes = append(db.Probes, p)
			current = p
			if p.Name == "NULL" && db.null == nil {
				db.null = p
			}
		case "match", "softmatch":
			if current == nil {
				db.note("line %d: %s before any Probe", lineNo, keyword)
				continue
			}
			rule, ok := db.parseMatch(rest, keyword == "softmatch", lineNo)
			if !ok {
				continue
			}
			current.Matches = append(current.Matches, rule)
			db.TotalMatch++
			if rule.Soft {
				db.SoftMatch++
			}
			if rule.re != nil {
				db.Usable++
			} else {
				db.Skipped++
				db.note("line %d: skipped %s pattern for %q: %s", lineNo, keyword, rule.Service, rule.skip)
			}
		case "ports", "sslports":
			if current == nil {
				continue
			}
			ranges := parsePorts(rest)
			if keyword == "ports" {
				current.Ports = append(current.Ports, ranges...)
			} else {
				current.SSLPorts = append(current.SSLPorts, ranges...)
			}
		case "rarity":
			if current != nil {
				current.Rarity, _ = strconv.Atoi(strings.TrimSpace(rest))
			}
		case "fallback":
			if current != nil {
				for _, name := range strings.Split(rest, ",") {
					if name = strings.TrimSpace(name); name != "" {
						current.Fallback = append(current.Fallback, name)
					}
				}
			}
		case "Exclude":
			db.Exclude = append(db.Exclude, parseExclude(rest)...)
		case "totalwaittime", "tcpwrappedms":
			// Timing hints; recorded implicitly by being accepted, not used yet.
		default:
			db.note("line %d: unknown directive %q", lineNo, keyword)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(db.Probes) == 0 {
		return nil, errors.New("no Probe directives found; is this an nmap-service-probes file?")
	}
	return db, nil
}

// parseProbe reads "TCP NULL q||" style probe headers.
func (d *Database) parseProbe(rest string, lineNo int) (*Probe, bool) {
	proto, after, ok := strings.Cut(strings.TrimLeft(rest, " \t"), " ")
	if !ok || (proto != "TCP" && proto != "UDP") {
		d.note("line %d: unsupported Probe protocol", lineNo)
		return nil, false
	}
	name, spec, ok := strings.Cut(strings.TrimLeft(after, " \t"), " ")
	if !ok || name == "" {
		d.note("line %d: Probe missing name or payload", lineNo)
		return nil, false
	}
	spec = strings.TrimLeft(spec, " \t")
	if len(spec) < 2 || spec[0] != 'q' {
		d.note("line %d: Probe payload must be q<delim>...<delim>", lineNo)
		return nil, false
	}
	delim := spec[1]
	end := strings.IndexByte(spec[2:], delim)
	if end < 0 {
		d.note("line %d: unterminated Probe payload", lineNo)
		return nil, false
	}
	payload, err := decodeEscapes(spec[2 : 2+end])
	if err != nil {
		d.note("line %d: %v", lineNo, err)
		return nil, false
	}
	return &Probe{Proto: proto, Name: name, Payload: payload, Line: lineNo}, true
}

// parseMatch reads a match/softmatch body: "<service> m<delim><pattern><delim>[flags] [versioninfo]".
func (d *Database) parseMatch(rest string, soft bool, lineNo int) (*Rule, bool) {
	service, after, ok := strings.Cut(strings.TrimLeft(rest, " \t"), " ")
	if !ok || service == "" {
		d.note("line %d: match missing service and pattern", lineNo)
		return nil, false
	}
	after = strings.TrimLeft(after, " \t")
	if len(after) < 2 || after[0] != 'm' {
		d.note("line %d: match pattern must be m<delim>...<delim>", lineNo)
		return nil, false
	}
	delim := after[1]
	end := strings.IndexByte(after[2:], delim)
	if end < 0 {
		d.note("line %d: unterminated match pattern for %q", lineNo, service)
		return nil, false
	}
	pattern := after[2 : 2+end]
	tail := after[2+end+1:]
	flags := ""
	i := 0
	for i < len(tail) && tail[i] != ' ' && tail[i] != '\t' {
		flags += string(tail[i])
		i++
	}
	rule := &Rule{Service: service, Soft: soft, Line: lineNo, pattern: pattern, flags: flags}
	rule.Version = parseVersion(strings.TrimLeft(tail[i:], " \t"))
	re, err := compilePattern(pattern, flags)
	if err != nil {
		rule.skip = compileError(err)
	} else {
		rule.re = re
	}
	return rule, true
}

// compilePattern translates the supported Nmap flags (i, s) into an RE2 mode
// prefix and compiles the pattern. Unsupported PCRE constructs make RE2 return
// an error, which the caller records as a skip reason.
func compilePattern(pattern, flags string) (*regexp.Regexp, error) {
	mode := ""
	if strings.ContainsRune(flags, 'i') {
		mode += "i"
	}
	if strings.ContainsRune(flags, 's') {
		mode += "s"
	}
	expr := pattern
	if mode != "" {
		expr = "(?" + mode + ")" + pattern
	}
	return regexp.Compile(expr)
}

func compileError(err error) string {
	s := err.Error()
	const prefix = "error parsing regexp: "
	if strings.HasPrefix(s, prefix) {
		s = s[len(prefix):]
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// parseVersion reads the p/…/ v/…/ i/…/ h/…/ o/…/ d/…/ cpe:/…/ token stream.
// Each token's delimiter is the character after the field key.
func parseVersion(s string) Version {
	var v Version
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		var key string
		switch {
		case strings.HasPrefix(s[i:], "cpe:"):
			key = "cpe"
			i += 4
		default:
			key = s[i : i+1]
			i++
		}
		if i >= len(s) {
			break
		}
		delim := s[i]
		i++
		end := strings.IndexByte(s[i:], delim)
		if end < 0 {
			break
		}
		val := s[i : i+end]
		i += end + 1
		if key == "cpe" {
			// Skip the optional trailing part flag (e.g. the "a" in cpe:/…/a).
			for i < len(s) && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			v.CPE = append(v.CPE, "cpe:"+string(delim)+val)
			continue
		}
		switch key {
		case "p":
			v.Product = val
		case "v":
			v.VersionStr = val
		case "i":
			v.Info = val
		case "h":
			v.Hostname = val
		case "o":
			v.OS = val
		case "d":
			v.Device = val
		}
	}
	return v
}

func parsePorts(s string) []PortRange {
	var out []PortRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			l, err1 := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
			h, err2 := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
			if err1 == nil && err2 == nil && l <= h {
				out = append(out, PortRange{Lo: uint16(l), Hi: uint16(h)})
			}
			continue
		}
		if p, err := strconv.ParseUint(part, 10, 16); err == nil {
			out = append(out, PortRange{Lo: uint16(p), Hi: uint16(p)})
		}
	}
	return out
}

// parseExclude reads "T:9100-9107" or "U:53" style exclusion entries.
func parseExclude(s string) []PortRange {
	var out []PortRange
	for _, part := range strings.Fields(s) {
		udp := false
		if proto, portList, ok := strings.Cut(part, ":"); ok {
			udp = strings.EqualFold(proto, "U")
			part = portList
		}
		for _, pr := range parsePorts(part) {
			pr.UDP = udp
			out = append(out, pr)
		}
	}
	return out
}

// decodeEscapes turns an Nmap probe q|…| body into raw bytes. It handles the
// C-style escapes Nmap uses; an unknown \x sequence is a literal char.
func decodeEscapes(s string) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(s) {
			return nil, errors.New("probe payload ends with a backslash")
		}
		switch s[i] {
		case '0':
			out = append(out, 0)
		case 'a':
			out = append(out, '\a')
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'v':
			out = append(out, '\v')
		case '\\':
			out = append(out, '\\')
		case 'x':
			if i+2 >= len(s) {
				return nil, errors.New("truncated \\x escape in probe payload")
			}
			b, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid \\x escape: %w", err)
			}
			out = append(out, byte(b))
			i += 2
		default:
			out = append(out, s[i])
		}
	}
	return out, nil
}
