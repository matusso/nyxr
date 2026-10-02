package service

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/matusso/nyxr/internal/observe"
)

// matchMailBanner identifies server-first mail protocols from their wire
// greetings. A bare 220, +OK, or * OK is ambiguous, so each match requires a
// protocol-specific marker. The original response remains in Evidence.
func matchMailBanner(o *observe.Observation, banner []byte) bool {
	if len(banner) == 0 || bytes.IndexByte(banner, 0) >= 0 {
		return false
	}
	lines := strings.Split(string(banner), "\n")
	first := strings.TrimSuffix(lines[0], "\r")
	if len(first) > 512 {
		return false
	}
	if strings.HasPrefix(first, "* OK ") {
		capabilities := ""
		upper := strings.ToUpper(first)
		if at := strings.Index(upper, "[CAPABILITY "); at >= 0 {
			if end := strings.IndexByte(first[at:], ']'); end >= 0 {
				capabilities = first[at+len("[CAPABILITY ") : at+end]
			}
		}
		var imapCapability bool
		for _, capability := range strings.Fields(capabilities) {
			if strings.EqualFold(capability, "IMAP4rev1") || strings.EqualFold(capability, "IMAP4rev2") {
				imapCapability = true
				break
			}
		}
		dovecot := strings.Contains(strings.ToLower(first), "dovecot")
		if imapCapability || dovecot {
			o.Service, o.Confidence, o.Reason = "imap", 95, "IMAP server greeting"
			o.Probe, o.Fingerprint = ProbeBanner, observe.FingerprintMatched
			if dovecot {
				o.Product = "Dovecot"
			}
			if capabilities != "" {
				o.Attributes = map[string]string{"imap.capabilities": capabilities}
			}
			return true
		}
	}

	if strings.HasPrefix(first, "220 ") || strings.HasPrefix(first, "220-") {
		fields := strings.Fields(first[4:])
		for _, field := range fields {
			if strings.EqualFold(field, "ESMTP") || strings.EqualFold(field, "SMTP") {
				o.Service, o.Confidence, o.Reason = "smtp", 95, "SMTP greeting identifies the protocol"
				o.Probe, o.Fingerprint = ProbeBanner, observe.FingerprintMatched
				if len(fields) > 0 && !strings.EqualFold(fields[0], "ESMTP") && !strings.EqualFold(fields[0], "SMTP") {
					o.Attributes = map[string]string{"smtp.hostname": fields[0]}
				}
				return true
			}
		}
	}

	if strings.HasPrefix(first, "+OK ") {
		lower := strings.ToLower(first[4:])
		if strings.Contains(lower, "dovecot") || strings.Contains(lower, "pop3") {
			o.Service, o.Confidence, o.Reason = "pop3", 95, "POP3 greeting identifies the protocol"
			o.Probe, o.Fingerprint = ProbeBanner, observe.FingerprintMatched
			if strings.Contains(lower, "dovecot") {
				o.Product = "Dovecot"
			}
			return true
		}
	}

	return matchSieveGreeting(o, lines)
}

func matchSieveGreeting(o *observe.Observation, lines []string) bool {
	attrs := map[string]string{}
	var implementation, extensions string
	var terminated, version bool
	for _, raw := range lines {
		line := strings.TrimSuffix(raw, "\r")
		if line == "OK" || strings.HasPrefix(line, "OK ") {
			terminated = true
			break
		}
		if line == "STARTTLS" {
			attrs["sieve.starttls"] = "true"
			continue
		}
		key, value, ok := strings.Cut(line, " ")
		if !ok || len(line) > 2048 {
			continue
		}
		key = strings.Trim(key, "\"")
		decoded, err := strconv.Unquote(value)
		if err != nil {
			continue
		}
		switch key {
		case "IMPLEMENTATION":
			implementation = decoded
			attrs["sieve.implementation"] = decoded
		case "SIEVE":
			extensions = decoded
			attrs["sieve.extensions"] = decoded
		case "SASL":
			attrs["sieve.sasl"] = decoded
		case "VERSION":
			version = decoded != ""
			attrs["sieve.protocol_version"] = decoded
		case "NOTIFY":
			attrs["sieve.notify"] = decoded
		}
	}
	if !terminated || extensions == "" || (implementation == "" && !version) {
		return false
	}
	o.Service, o.Confidence, o.Reason = "sieve", 100, "ManageSieve capability greeting"
	o.Probe, o.Fingerprint, o.Attributes = ProbeBanner, observe.FingerprintMatched, attrs
	if strings.HasPrefix(strings.ToLower(implementation), "dovecot pigeonhole") {
		o.Product = "Dovecot Pigeonhole"
	}
	return true
}
