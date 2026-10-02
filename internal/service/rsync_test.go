package service

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/observe"
)

func TestRsyncGreetingIdentified(t *testing.T) {
	banner := "@RSYNCD: 32.0 sha512 sha256 sha1 md5 md4\n" +
		"Welcome to Wheel.sk (supported by ZeroOne Solutions s.r.o.) Gentoo/Slackware/Raspbian rsync mirror\n\n" +
		"Server Name: rsync1.sk.gentoo.org\n             mirror.wheel.sk\n" +
		"IP address : 92.60.51.128\n\n" +
		"Full mirror @ http://gentoo.wheel.sk/\n              http://mirror.wheel.sk/\n\n" +
		"Server admin : Michal Brngal (mirror@wheel.sk)\n"
	target := serve(t, func(c net.Conn) { _, _ = io.WriteString(c, banner) })
	o := testEngine(t).Interrogate(context.Background(), target)
	if o.Service != "rsync" || o.Confidence != 100 || o.Fingerprint != observe.FingerprintMatched ||
		o.Attributes["rsync.protocol_version"] != "32.0" || o.Attributes["rsync.hashes"] != "sha512 sha256 sha1 md5 md4" {
		t.Fatalf("unexpected rsync identity: %+v", o)
	}
	if len(o.Evidence) != 1 || o.Evidence[0].Matched != ProbeBanner || string(o.Evidence[0].Response) != banner {
		t.Fatalf("rsync greeting and MOTD should remain in evidence: %+v", o.Evidence)
	}
}

func TestRsyncMatcherRejectsMalformedVersion(t *testing.T) {
	for _, banner := range []string{"@RSYNCD: hello\n", "@RSYNCD: 32.x\n", "Welcome to an rsync mirror\n"} {
		var o observe.Observation
		if matchRsyncBanner(&o, []byte(banner)) {
			t.Errorf("malformed greeting was classified: %q -> %+v", strings.TrimSpace(banner), o)
		}
	}
}
