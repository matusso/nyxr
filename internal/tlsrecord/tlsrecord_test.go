package tlsrecord

import (
	"strings"
	"testing"
)

func TestDecodeAlert(t *testing.T) {
	got := Decode([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x78})
	want := []struct{ bytes, value string }{
		{"15", "alert"}, {"03 03", "TLS 1.2"}, {"00 02", "len 2"}, {"02", "fatal"}, {"78", "no_application_protocol"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d fields, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Bytes != w.bytes || got[i].Value != w.value || got[i].Note == "" {
			t.Errorf("field %d = %+v, want %s %s", i, got[i], w.bytes, w.value)
		}
	}
	if got[4].Offset != 6 || !strings.Contains(got[4].Note, "120") {
		t.Errorf("description should sit at offset 6 and cite its decimal code: %+v", got[4])
	}
}

func TestDecodeHandshakeAndTruncation(t *testing.T) {
	// A server_hello header cut short after the handshake length.
	got := Decode([]byte{0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03})
	if len(got) != 5 || got[3].Value != "server_hello" || got[4].Value != "len 86" {
		t.Fatalf("handshake header not explained: %+v", got)
	}
}

func TestDecodeRejectsNonTLS(t *testing.T) {
	for _, data := range [][]byte{
		[]byte("HTTP/1.1 400 Bad Request\r\n"),
		{0x15, 0x03},                         // shorter than a header
		{0x15, 0x02, 0x00, 0x00, 0x02, 0, 0}, // not a 3.x version
		{0x19, 0x03, 0x03, 0x00, 0x02, 0, 0}, // unknown content type
		{0x17, 0x03, 0x03, 0xff, 0xff},       // longer than any record
	} {
		if got := Decode(data); got != nil {
			t.Errorf("Decode(% x) = %+v, want nil", data, got)
		}
	}
}

func TestDecodeMultipleRecords(t *testing.T) {
	got := Decode([]byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00})
	if len(got) != 9 || got[3].Value != "change_cipher_spec" || got[4].Offset != 6 || got[8].Value != "close_notify" {
		t.Fatalf("second record not explained at its offset: %+v", got)
	}
}
