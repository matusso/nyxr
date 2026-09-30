package nmapdb

import (
	"strings"
	"testing"
)

// FuzzParse feeds hostile input to the importer and to the banner matcher. An
// nmap-service-probes file is untrusted operator input; parsing and matching
// must never panic, and a compiled pattern must never be run against a nil
// regexp.
func FuzzParse(f *testing.F) {
	f.Add(sample)
	f.Add("Probe TCP NULL q||\nmatch x m|(|\n")
	f.Add("Probe TCP NULL q|\\x|\n")
	f.Add("match ftp m|^220| p/$/\n")
	f.Add("Probe UDP X q|\\xzz|\nsoftmatch y m=.=\n")
	f.Fuzz(func(t *testing.T, in string) {
		db, err := Parse(strings.NewReader(in), "fuzz")
		if err != nil {
			return
		}
		// Exercise the match path with several banners, including the input.
		for _, banner := range []string{in, "220 ready", "SSH-2.0-x", ""} {
			if res, ok := db.MatchBanner([]byte(banner)); ok {
				_ = res.Service + res.Product + res.Version
			}
		}
		_ = db.NullRules()
	})
}
