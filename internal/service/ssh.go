package service

import (
	"bytes"
	"strings"

	"github.com/matusso/nyxr/internal/observe"
)

// matchSSH recognizes an RFC 4253 identification string. Servers may send
// other lines first, so each line of the banner is checked.
func matchSSH(o *observe.Observation, banner []byte) bool {
	for _, line := range bytes.Split(banner, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if !bytes.HasPrefix(line, []byte("SSH-")) || len(line) > 255 {
			continue
		}
		rest := string(line[4:])
		proto, software, ok := strings.Cut(rest, "-")
		if !ok || software == "" || (proto != "2.0" && proto != "1.99" && proto != "1.5") {
			continue
		}
		software, comment, _ := strings.Cut(software, " ")
		o.Service, o.Confidence, o.Fingerprint = "ssh", 100, observe.FingerprintMatched
		o.Reason = "SSH identification string"
		o.Probe = ProbeSSH
		o.Attributes = map[string]string{"ssh.protocol": proto, "ssh.software": software}
		if comment != "" {
			o.Attributes["ssh.comment"] = comment
		}
		o.Product, o.Version = splitSoftware(software, "_")
		return true
	}
	return false
}

// splitSoftware turns "OpenSSH_9.6p1" or "nginx/1.25.3" into product and
// version. A token without a separator followed by a digit is product only.
func splitSoftware(s, sep string) (product, version string) {
	product, version, ok := strings.Cut(s, sep)
	if !ok || version == "" || version[0] < '0' || version[0] > '9' {
		return s, ""
	}
	return product, version
}
