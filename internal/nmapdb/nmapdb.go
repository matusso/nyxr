// Package nmapdb imports user-supplied nmap-service-probes files into nyxr's
// own match model at runtime. It never bundles Nmap's probe data: the database
// is read from a path the operator provides, its provenance (source path and
// SHA-256) is recorded, and the importer reports how much of the file it could
// use. This keeps the license boundary that docs/architecture/design.md §7
// requires — the Nmap Project's data is not redistributed inside a nyxr
// binary.
//
// Only a safe, self-contained subset is used at scan time. Match patterns are
// compiled with Go's RE2 engine; any pattern that relies on PCRE features RE2
// does not support (backreferences, lookaround, possessive quantifiers) is
// skipped with a recorded reason rather than failing the whole import. The
// service engine currently applies only the NULL probe's rules, against the
// banner a server sends on connect, so importing a database sends no new
// traffic. Sending the imported active probes is a later slice.
package nmapdb

import (
	"fmt"
	"regexp"
)

// LicenseNotice is printed whenever a database is imported. The data file is
// the Nmap Project's; nyxr reads it at the operator's direction and does not
// redistribute it.
const LicenseNotice = "nmap-service-probes data is licensed by the Nmap Project (Nmap Public Source License). " +
	"nyxr imports it at runtime from the file you supply and does not bundle or redistribute it; " +
	"ensure your use complies with that license."

// Database is a parsed, compiled nmap-service-probes file plus the provenance
// and statistics the importer collected.
type Database struct {
	Source  string // path the database was read from
	SHA256  string // hex digest of the raw file bytes
	Probes  []*Probe
	Exclude []PortRange // Exclude directive ranges, if any

	// Statistics gathered while parsing, surfaced by the import command.
	TotalMatch int      // match/softmatch lines seen
	SoftMatch  int      // of those, softmatch lines
	Usable     int      // rules whose pattern compiled and is usable
	Skipped    int      // rules whose pattern RE2 could not compile
	Warnings   []string // bounded list of parse/compile warnings

	null *Probe // the "NULL" probe, matched against a connect banner
}

// Probe is one nmap Probe directive with its match rules and metadata.
type Probe struct {
	Proto    string // "TCP" or "UDP"
	Name     string
	Payload  []byte
	Rarity   int
	Ports    []PortRange
	SSLPorts []PortRange
	Fallback []string
	Matches  []*Rule
	Line     int
}

// Rule is one match or softmatch line.
type Rule struct {
	Service string
	Soft    bool
	Line    int
	Version Version // product/version templates
	pattern string  // original Nmap pattern (kept for provenance)
	flags   string  // Nmap flags applied (subset of i, s)
	re      *regexp.Regexp
	skip    string // non-empty when the rule could not be compiled
}

// Version holds the version-info templates of a match line. Each field may
// contain $1..$9 capture references that Apply resolves against a response.
type Version struct {
	Product, VersionStr, Info, Hostname, OS, Device string
	CPE                                             []string
}

// Result is a successful service identification.
type Result struct {
	Service  string
	Product  string
	Version  string
	Info     string
	Hostname string
	OS       string
	Device   string
	CPE      []string
	Probe    string // the probe whose rules matched
	Soft     bool   // a softmatch (lower confidence) rather than a hard match
	Line     int    // source line of the matching rule
}

// PortRange is an inclusive port span from a ports/sslports/Exclude directive.
type PortRange struct {
	Lo, Hi uint16
	UDP    bool // only meaningful for Exclude ranges
}

// Contains reports whether port is inside the range.
func (r PortRange) Contains(port uint16) bool { return port >= r.Lo && port <= r.Hi }

// MatchBanner classifies the bytes a server sent on connect. Nmap's NULL probe
// holds the rules that apply to an unsolicited banner, so those are the only
// rules used here — no probe payload is sent. A hard match wins; otherwise the
// first softmatch is returned with Soft set, mirroring Nmap's precedence.
func (d *Database) MatchBanner(data []byte) (Result, bool) {
	if d == nil || d.null == nil || len(data) == 0 {
		return Result{}, false
	}
	var soft *Rule
	var softSub [][]byte
	for _, r := range d.null.Matches {
		if r.re == nil {
			continue
		}
		sub := r.re.FindSubmatch(data)
		if sub == nil {
			continue
		}
		if !r.Soft {
			return r.result(d.null.Name, sub), true
		}
		if soft == nil {
			soft, softSub = r, sub
		}
	}
	if soft != nil {
		return soft.result(d.null.Name, softSub), true
	}
	return Result{}, false
}

// NullRules reports how many usable rules the NULL probe contributes; it lets
// callers warn when a database has nothing to match a banner against.
func (d *Database) NullRules() int {
	if d == nil || d.null == nil {
		return 0
	}
	n := 0
	for _, r := range d.null.Matches {
		if r.re != nil {
			n++
		}
	}
	return n
}

func (r *Rule) result(probe string, sub [][]byte) Result {
	return Result{
		Service:  r.Service,
		Product:  applyTemplate(r.Version.Product, sub),
		Version:  applyTemplate(r.Version.VersionStr, sub),
		Info:     applyTemplate(r.Version.Info, sub),
		Hostname: applyTemplate(r.Version.Hostname, sub),
		OS:       applyTemplate(r.Version.OS, sub),
		Device:   applyTemplate(r.Version.Device, sub),
		CPE:      applyAll(r.Version.CPE, sub),
		Probe:    probe,
		Soft:     r.Soft,
		Line:     r.Line,
	}
}

func (d *Database) note(format string, args ...any) {
	if len(d.Warnings) < 64 {
		d.Warnings = append(d.Warnings, fmt.Sprintf(format, args...))
	}
}
