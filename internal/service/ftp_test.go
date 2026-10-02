package service

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/matusso/nyxr/internal/observe"
)

func TestFTPGreetingIdentified(t *testing.T) {
	target := serve(t, func(c net.Conn) { _, _ = io.WriteString(c, "220 FTP\r\n") })
	o := testEngine(t).Interrogate(context.Background(), target)
	if o.Service != "ftp" || o.Confidence != 95 || o.Fingerprint != observe.FingerprintMatched || o.Probe != ProbeBanner {
		t.Fatalf("unexpected FTP identity: %+v", o)
	}
	if len(o.Evidence) != 1 || o.Evidence[0].Matched != ProbeBanner || string(o.Evidence[0].Response) != "220 FTP\r\n" {
		t.Fatalf("FTP greeting must remain in evidence: %+v", o.Evidence)
	}
}

func TestFTPMatcherRequiresExplicitToken(t *testing.T) {
	for _, banner := range []string{"220 ready\r\n", "220 SFTP ready\r\n", "220 ProFTPD 1.3.5 ready\r\n"} {
		var o observe.Observation
		if matchFTPBanner(&o, []byte(banner)) {
			t.Errorf("ambiguous greeting was classified: %q -> %+v", banner, o)
		}
	}
}
