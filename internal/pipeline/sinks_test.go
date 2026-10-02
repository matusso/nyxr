package pipeline

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/observe"
)

func TestTextSinkShowsBinaryBannerAsHex(t *testing.T) {
	banner := []byte{0x17, 0x1c, 0x15, 0x5b, 0xee, 0x75, 0xfd, 0x45, 0xa1, 0x10, 0x09, 0xee, 0x36, 0x1b}
	var out bytes.Buffer
	o := observe.Observation{Kind: observe.KindService, Target: netip.MustParseAddr("92.60.48.48"),
		Transport: "tcp", Port: 444, Fingerprint: observe.FingerprintUnknown,
		Reason:   "unrecognized banner retained as evidence",
		Evidence: []observe.Evidence{{Probe: "banner", Layer: "tcp", Response: banner}}}
	if err := NewTextSink(&out).Observation(o); err != nil {
		t.Fatal(err)
	}
	want := "  00000000: 171c 155b ee75 fd45 a110 09ee 361b       ...[.u.E....6.\n"
	if !strings.Contains(out.String(), want) || strings.Contains(out.String(), "banner \"...") {
		t.Fatalf("binary banner needs a grouped hex and ASCII dump:\n%s", out.String())
	}
	o.Fingerprint, o.Service = observe.FingerprintMatched, "binaryproto"
	out.Reset()
	if err := NewTextSink(&out).Observation(o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), want) {
		t.Fatalf("identified binary service still needs its dump:\n%s", out.String())
	}
}

func TestTextSinkShowsReadableUnknownBannerAsText(t *testing.T) {
	var out bytes.Buffer
	o := observe.Observation{Kind: observe.KindService, Target: netip.MustParseAddr("192.0.2.1"),
		Transport: "tcp", Port: 1234, Fingerprint: observe.FingerprintUnknown,
		Reason:   "unrecognized banner retained as evidence",
		Evidence: []observe.Evidence{{Probe: "banner", Layer: "tcp", Response: []byte("Welcome\r\n")}}}
	if err := NewTextSink(&out).Observation(o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `banner "Welcome\r\n"`) || strings.Contains(out.String(), "00000000:") {
		t.Fatalf("readable banner should stay on the summary line:\n%s", out.String())
	}
}
