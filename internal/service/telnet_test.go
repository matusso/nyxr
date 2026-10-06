package service

import (
	"context"
	"net"
	"testing"

	"github.com/matusso/nyxr/internal/observe"
)

func TestTelnetNegotiationIdentified(t *testing.T) {
	greeting := []byte("\xff\xfd\x1flogin: ")
	target := serve(t, func(c net.Conn) { _, _ = c.Write(greeting) })
	o := testEngine(t).Interrogate(context.Background(), target)
	if o.Service != "telnet" || o.Confidence != 95 || o.Fingerprint != observe.FingerprintMatched || o.Probe != ProbeBanner {
		t.Fatalf("unexpected Telnet identity: %+v", o)
	}
	if o.Attributes["telnet.negotiation"] != "DO NAWS" || o.Attributes["telnet.prompt"] != "login:" {
		t.Fatalf("unexpected Telnet attributes: %+v", o.Attributes)
	}
	if len(o.Evidence) != 1 || o.Evidence[0].Matched != ProbeBanner || string(o.Evidence[0].Response) != string(greeting) {
		t.Fatalf("Telnet greeting must remain in evidence: %+v", o.Evidence)
	}
}

func TestTelnetMatcherParsesCommands(t *testing.T) {
	var o observe.Observation
	banner := "\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03\xff\xfa\x18\x01\xff\xf0\xff\xf9"
	if !matchTelnetBanner(&o, []byte(banner)) {
		t.Fatal("BusyBox-style negotiation was not classified")
	}
	if got := o.Attributes["telnet.negotiation"]; got != "DO ECHO, DO NAWS, WILL ECHO, WILL SGA, SB TTYPE" {
		t.Fatalf("negotiation = %q", got)
	}
	if _, ok := o.Attributes["telnet.prompt"]; ok {
		t.Fatalf("negotiation-only greeting has no prompt: %+v", o.Attributes)
	}
}

func TestTelnetMatcherRejectsNonTelnet(t *testing.T) {
	for _, banner := range []string{
		"login: ",              // no negotiation
		"\xff\xf1\xf1",         // NOP only
		"\xff\x10\x01",         // not a Telnet command
		"\xff\xfa\x18\x01",     // unterminated subnegotiation
		"220 \xff\xfd\x1f FTP", // IAC not leading
	} {
		var o observe.Observation
		if matchTelnetBanner(&o, []byte(banner)) {
			t.Errorf("non-Telnet banner was classified: %q -> %+v", banner, o)
		}
	}
}
