package service

import (
	"strconv"
	"strings"

	"github.com/matusso/nyxr/internal/observe"
)

// Telnet commands from RFC 854.
const (
	telnetSE   = 0xf0
	telnetSB   = 0xfa
	telnetWILL = 0xfb
	telnetWONT = 0xfc
	telnetDO   = 0xfd
	telnetDONT = 0xfe
	telnetIAC  = 0xff
)

var telnetVerbs = map[byte]string{telnetWILL: "WILL", telnetWONT: "WONT", telnetDO: "DO", telnetDONT: "DONT"}

// Option names from the IANA Telnet option registry, limited to the ones
// servers commonly negotiate in a greeting.
var telnetOptions = map[byte]string{
	0: "BINARY", 1: "ECHO", 3: "SGA", 5: "STATUS", 6: "TIMING-MARK",
	24: "TTYPE", 31: "NAWS", 32: "TSPEED", 33: "LFLOW", 34: "LINEMODE",
	35: "XDISPLOC", 36: "OLD-ENVIRON", 37: "AUTHENTICATION", 38: "ENCRYPT",
	39: "NEW-ENVIRON", 42: "CHARSET", 44: "COM-PORT", 70: "MSSP",
	85: "COMPRESS", 86: "COMPRESS2", 91: "MXP", 93: "ZMP", 201: "GMCP",
}

// A Telnet server usually opens with option negotiation before any text.
// Claim Telnet only when the banner starts with IAC and every command in it
// parses as a well-formed RFC 854 sequence with at least one negotiation.
func matchTelnetBanner(o *observe.Observation, banner []byte) bool {
	if len(banner) < 3 || banner[0] != telnetIAC {
		return false
	}
	var negotiated []string
	var text []byte
	for i := 0; i < len(banner); {
		c := banner[i]
		if c != telnetIAC {
			text = append(text, c)
			i++
			continue
		}
		if i+1 >= len(banner) {
			break // a truncated read may split a command
		}
		cmd := banner[i+1]
		switch {
		case cmd == telnetIAC: // escaped 0xff data byte
			text = append(text, c)
			i += 2
		case telnetVerbs[cmd] != "":
			if i+2 >= len(banner) {
				i = len(banner)
				continue
			}
			negotiated = append(negotiated, telnetVerbs[cmd]+" "+telnetOptionName(banner[i+2]))
			i += 3
		case cmd == telnetSB:
			end := subnegotiationEnd(banner[i+2:])
			if end < 0 {
				// Tolerate a read cut off mid-subnegotiation only after
				// the banner has already proven itself.
				if len(negotiated) == 0 {
					return false
				}
				i = len(banner)
				continue
			}
			negotiated = append(negotiated, "SB "+telnetOptionName(banner[i+2]))
			i += 2 + end
		case cmd >= telnetSE && cmd < telnetSB: // SE, NOP, DM, BRK, IP, AO, AYT, EC, EL, GA
			i += 2
		default:
			return false
		}
	}
	if len(negotiated) == 0 {
		return false
	}
	o.Service, o.Confidence, o.Reason = "telnet", 95, "Telnet option negotiation"
	o.Probe, o.Fingerprint = ProbeBanner, observe.FingerprintMatched
	o.Attributes = map[string]string{"telnet.negotiation": strings.Join(negotiated, ", ")}
	if prompt := printable(text, 256); prompt != "" {
		o.Attributes["telnet.prompt"] = prompt
	}
	return true
}

// subnegotiationEnd returns the length through IAC SE, or -1 when the
// subnegotiation is not terminated within b.
func subnegotiationEnd(b []byte) int {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == telnetIAC {
			if b[i+1] == telnetSE {
				return i + 2
			}
			i++ // skip IAC IAC and other escaped bytes
		}
	}
	return -1
}

func telnetOptionName(opt byte) string {
	if name, ok := telnetOptions[opt]; ok {
		return name
	}
	return strconv.Itoa(int(opt))
}
