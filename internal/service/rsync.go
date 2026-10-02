package service

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/matusso/nyxr/internal/observe"
)

func matchRsyncBanner(o *observe.Observation, banner []byte) bool {
	if bytes.IndexByte(banner, 0) >= 0 {
		return false
	}
	first, _, _ := strings.Cut(string(banner), "\n")
	first = strings.TrimSuffix(first, "\r")
	if len(first) > 512 || !strings.HasPrefix(first, "@RSYNCD: ") {
		return false
	}
	fields := strings.Fields(first[len("@RSYNCD: "):])
	if len(fields) == 0 {
		return false
	}
	major, minor, ok := strings.Cut(fields[0], ".")
	if !ok {
		return false
	}
	if _, err := strconv.ParseUint(major, 10, 16); err != nil {
		return false
	}
	if _, err := strconv.ParseUint(minor, 10, 16); err != nil {
		return false
	}
	o.Service, o.Confidence, o.Reason = "rsync", 100, "rsync daemon protocol greeting"
	o.Probe, o.Fingerprint = ProbeBanner, observe.FingerprintMatched
	o.Attributes = map[string]string{"rsync.protocol_version": fields[0]}
	if len(fields) > 1 {
		o.Attributes["rsync.hashes"] = strings.Join(fields[1:], " ")
	}
	return true
}
