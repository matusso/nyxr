package service

import (
	"bytes"
	"strings"

	"github.com/matusso/nyxr/internal/observe"
)

// A 220 code alone is shared by several protocols. Require an explicit FTP
// token in the server greeting before claiming FTP from a passive banner.
func matchFTPBanner(o *observe.Observation, banner []byte) bool {
	if bytes.IndexByte(banner, 0) >= 0 {
		return false
	}
	first, _, _ := strings.Cut(string(banner), "\n")
	first = strings.TrimSuffix(first, "\r")
	if len(first) > 512 || (!strings.HasPrefix(first, "220 ") && !strings.HasPrefix(first, "220-")) {
		return false
	}
	for _, field := range strings.Fields(first[4:]) {
		if strings.EqualFold(field, "FTP") {
			o.Service, o.Confidence, o.Reason = "ftp", 95, "FTP service greeting"
			o.Probe, o.Fingerprint = ProbeBanner, observe.FingerprintMatched
			return true
		}
	}
	return false
}
