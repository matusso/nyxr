package service

import (
	"testing"

	"github.com/matusso/nyxr/internal/observe"
)

// FuzzResponseParsers feeds hostile server responses to every matcher. They
// must never panic, and a match must always name a service.
func FuzzResponseParsers(f *testing.F) {
	for _, seed := range []string{
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n",
		"HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n\r\n<title>x</title>",
		"HTTP/1.0 301\r\nLocation:",
		"\x12\x34\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03\xc0\x0c\x00\x10\x00\x03\x00\x00\x00\x00\x00\x02\x01x",
		"\xc0\xc0\xc0",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var o observe.Observation
		if matchSSH(&o, data) && o.Service != "ssh" {
			t.Fatal("SSH match without service")
		}
		o = observe.Observation{}
		if parseHTTP(&o, data) && o.Service != "http" {
			t.Fatal("HTTP match without service")
		}
		if len(data) >= 2 {
			_, _, _ = parseDNSResponse(data, uint16(data[0])<<8|uint16(data[1]))
		}
	})
}
