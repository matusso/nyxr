package service

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

const maxHTTPRead = 16 << 10

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// probeHTTP sends one GET / and parses the response head. conn is an
// established TLS connection, or nil to dial plain TCP.
func (e *Engine) probeHTTP(ctx context.Context, t Target, conn net.Conn, layer string, o *observe.Observation) (observe.Evidence, bool) {
	timeout := e.timeout(ProbeHTTP)
	ev := observe.Evidence{Probe: ProbeHTTP, Layer: layer, Started: time.Now().UTC()}
	if conn == nil {
		var err error
		conn, err = e.dial(ctx, t, timeout)
		if err != nil {
			ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
			return ev, false
		}
		defer conn.Close()
	}
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	host := t.Addr.String()
	if t.Port != 80 && t.Port != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(int(t.Port)))
	} else if t.Addr.Is6() {
		host = "[" + host + "]"
	}
	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n", host, e.cfg.UserAgent)
	if _, err := rc.Write([]byte(request)); err != nil {
		e.finish(&ev, rc, err)
		return ev, false
	}
	// The retained response may be shorter than what is parsed.
	data, err := readHTTP(rc)
	e.finish(&ev, rc, err)
	if !parseHTTP(o, data) {
		return ev, false
	}
	ev.Matched = ProbeHTTP
	if ev.Error == "timeout" {
		ev.Error = "" // keep-alive servers may ignore Connection: close
	}
	return ev, true
}

// readHTTP reads until the connection closes, the deadline passes, or the
// response head plus some body has arrived.
func readHTTP(c net.Conn) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for len(buf) < maxHTTPRead {
		n, err := c.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if err != nil {
			return buf, err
		}
		if head := bytes.Index(buf, []byte("\r\n\r\n")); head >= 0 && (len(buf)-head > 2048 || bytes.Contains(bytes.ToLower(buf), []byte("</title>"))) {
			return buf, nil
		}
	}
	return buf, nil
}

// parseHTTP fills service fields from an HTTP/1.x response.
func parseHTTP(o *observe.Observation, data []byte) bool {
	if !bytes.HasPrefix(data, []byte("HTTP/1.")) {
		return false
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
	attrs := map[string]string{}
	if err != nil {
		// A status line without a parsable head is still HTTP.
		line, _, _ := bytes.Cut(data, []byte("\r\n"))
		attrs["http.status_line"] = printable(line, 200)
	} else {
		_ = resp.Body.Close()
		attrs["http.status"] = strconv.Itoa(resp.StatusCode)
		for header, key := range map[string]string{
			"Server": "http.server", "Content-Type": "http.content_type", "Location": "http.location",
			"X-Powered-By": "http.powered_by", "WWW-Authenticate": "http.www_authenticate",
		} {
			if v := resp.Header.Get(header); v != "" {
				attrs[key] = printable([]byte(v), 200)
			}
		}
	}
	if m := titlePattern.FindSubmatch(data); m != nil {
		if title := printable(m[1], 200); title != "" {
			attrs["http.title"] = title
		}
	}
	if o.Attributes == nil {
		o.Attributes = map[string]string{}
	}
	for k, v := range attrs {
		o.Attributes[k] = v
	}
	o.Service, o.Confidence, o.Probe = "http", 100, ProbeHTTP
	o.Reason = "HTTP/1.x response to GET /"
	if server := attrs["http.server"]; server != "" {
		token, _, _ := strings.Cut(server, " ")
		o.Product, o.Version = splitSoftware(token, "/")
		o.Reason += "; product from Server header"
	}
	return true
}
