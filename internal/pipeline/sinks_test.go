package pipeline

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/observe"
)

func TestTextSinkShowsOnlyFirstReceivedBanner(t *testing.T) {
	banner := []byte{0x01, 0x94, 0x3e, 0x68, 0x83, 0x72, 0x94, 0xdf, 0xee, 0xd6, 0xe7, 0x1b, 0x8e, 0x7a}
	var out bytes.Buffer
	o := observe.Observation{Kind: observe.KindService, Target: netip.MustParseAddr("92.60.48.55"),
		Transport: "tcp", Port: 444, Fingerprint: observe.FingerprintUnknown,
		Reason: "unrecognized banner retained as evidence",
		Evidence: []observe.Evidence{
			{Probe: "banner", Layer: "tcp", Response: banner},
			{Probe: "http", Layer: "tcp", Request: []byte("GET / HTTP/1.1\r\n"), Response: []byte{0xe1, 0x0d, 0x6b, 0x4e}},
		}}
	if err := NewTextSink(&out).Observation(o); err != nil {
		t.Fatal(err)
	}
	want := "binary banner [14 bytes] (01 94 3e 68 83 72 94 df ee d6 e7 1b 8e 7a)"
	if !strings.Contains(out.String(), want) || strings.Count(out.String(), "\n") != 1 ||
		strings.Contains(out.String(), "http") || strings.Contains(out.String(), "sent") ||
		strings.Contains(out.String(), "unrecognized banner retained") {
		t.Fatalf("unknown service should show one received preview inline:\n%s", out.String())
	}
}

func TestTextSinkLimitsPreviewAndHidesDetectedBanner(t *testing.T) {
	var out bytes.Buffer
	banner := []byte("SSH-2.0-mod_sftp\r\n\x00\x00\x02\xb4\x07\x14")
	o := observe.Observation{Kind: observe.KindService, Target: netip.MustParseAddr("192.0.2.3"),
		Transport: "tcp", Port: 2222, Fingerprint: observe.FingerprintUnknown,
		Reason:   "unrecognized banner retained as evidence",
		Evidence: []observe.Evidence{{Probe: "banner", Layer: "tcp", Response: banner}}}
	if err := NewTextSink(&out).Observation(o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "binary banner [24 bytes] (53 53 48 2d 32 2e 30 2d 6d 6f 64 5f 73 66 74 70 …)") ||
		strings.Count(out.String(), "\n") != 1 || strings.Contains(out.String(), "00 00 02 b4") {
		t.Fatalf("preview should stop after the first 16 received bytes:\n%s", out.String())
	}
	o.Service, o.Fingerprint, o.Reason = "ssh", observe.FingerprintMatched, "SSH identification string"
	out.Reset()
	if err := NewTextSink(&out).Observation(o); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "banner") || strings.Contains(out.String(), "53 53 48") {
		t.Fatalf("detected SSH should not print banner bytes:\n%s", out.String())
	}
}

func TestTextSinkUsesReceivedProbeWhenNoBanner(t *testing.T) {
	var out bytes.Buffer
	o := observe.Observation{Kind: observe.KindService, Target: netip.MustParseAddr("192.0.2.2"),
		Transport: "tcp", Port: 9999, Fingerprint: observe.FingerprintUnknown,
		Reason: "no probe matched", Evidence: []observe.Evidence{{Probe: "http", Layer: "tcp",
			Request: []byte("GET /\r\n"), Response: []byte{0x00, 0xff}}}}
	if err := NewTextSink(&out).Observation(o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "http response [2 bytes] (00 ff)") ||
		strings.Contains(out.String(), "47 45 54") || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("only received bytes should appear inline:\n%s", out.String())
	}
}
