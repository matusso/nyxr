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

// serverHello builds one handshake record carrying a ServerHello.
func serverHello(version, suite uint16, random [32]byte, exts ...[]byte) []byte {
	body := []byte{byte(version >> 8), byte(version)}
	body = append(body, random[:]...)
	body = append(body, 0, byte(suite>>8), byte(suite), 0) // empty session ID, suite, null compression
	var ext []byte
	for _, e := range exts {
		ext = append(ext, e...)
	}
	if len(exts) > 0 {
		body = append(body, byte(len(ext)>>8), byte(len(ext)))
		body = append(body, ext...)
	}
	hs := append([]byte{2, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{22, 3, 3, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func TestParseServerHello(t *testing.T) {
	renegotiation := []byte{0xff, 0x01, 0, 1, 0}
	tls12 := serverHello(0x0303, 0xc02f, [32]byte{1}, renegotiation, []byte{0, 0x17, 0, 0})
	h, ok := ParseServerHello(append(tls12, 0x16, 3, 3, 0, 4, 11, 0, 0, 0))
	if !ok || h.Version != 0x0303 || h.CipherSuite != 0xc02f || len(h.Extensions) != 2 || h.Extensions[0] != 0xff01 || h.Extensions[1] != 0x17 || h.HelloRetry {
		t.Fatalf("TLS 1.2 ServerHello = %+v %v", h, ok)
	}
	tls13 := serverHello(0x0303, 0x1301, [32]byte{2}, []byte{0, 43, 0, 2, 3, 4}, []byte{0, 51, 0, 2, 0, 29})
	if h, ok := ParseServerHello(tls13); !ok || h.Version != 0x0304 || h.CipherSuite != 0x1301 || len(h.Extensions) != 2 {
		t.Fatalf("supported_versions must select TLS 1.3: %+v %v", h, ok)
	}
	if h, ok := ParseServerHello(serverHello(0x0303, 0x1301, helloRetryRandom)); !ok || !h.HelloRetry {
		t.Fatalf("HelloRetryRequest not marked: %+v %v", h, ok)
	}
	// A ServerHello split over two records is reassembled.
	split := append(append([]byte{}, tls12[:5]...), tls12[5:20]...)
	split[3], split[4] = 0, 15
	rest := tls12[20:]
	split = append(split, 22, 3, 3, byte(len(rest)>>8), byte(len(rest)))
	split = append(split, rest...)
	if h, ok := ParseServerHello(split); !ok || h.CipherSuite != 0xc02f {
		t.Fatalf("split ServerHello = %+v %v", h, ok)
	}
	for name, data := range map[string][]byte{
		"truncated":  tls12[:len(tls12)-3],
		"alert":      {21, 3, 3, 0, 2, 2, 40},
		"plaintext":  []byte("HTTP/1.1 400 Bad Request\r\n\r\n"),
		"bad length": serverHello(0x0303, 0xc02f, [32]byte{}, []byte{0, 0x17, 0, 9}),
		"empty":      nil,
	} {
		if h, ok := ParseServerHello(data); ok {
			t.Errorf("%s parsed as %+v", name, h)
		}
	}
	if AlertName(112) != "unrecognized_name" || AlertName(250) != "alert 250" {
		t.Fatal("alert names")
	}
}

func FuzzParseServerHello(f *testing.F) {
	f.Add(serverHello(0x0303, 0x1301, [32]byte{}, []byte{0, 43, 0, 2, 3, 4}))
	f.Add([]byte{21, 3, 3, 0, 2, 2, 40})
	f.Fuzz(func(t *testing.T, data []byte) {
		if h, ok := ParseServerHello(data); ok && len(h.Extensions) > 64 {
			t.Fatalf("unbounded extensions: %d", len(h.Extensions))
		}
	})
}
