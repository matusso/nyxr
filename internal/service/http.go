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
	ev, _, matched := e.probeHTTPExchange(ctx, t, conn, layer, "/", o)
	return ev, matched
}

func (e *Engine) probeHTTPExchange(ctx context.Context, t Target, conn net.Conn, layer, path string, o *observe.Observation) (observe.Evidence, []byte, bool) {
	timeout := e.timeout(ProbeHTTP)
	ev := observe.Evidence{Probe: ProbeHTTP, Layer: layer, Started: time.Now().UTC()}
	if conn == nil {
		var err error
		conn, err = e.dial(ctx, t, timeout)
		if err != nil {
			ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
			return ev, nil, false
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
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, host, e.cfg.UserAgent)
	if _, err := rc.Write([]byte(request)); err != nil {
		e.finish(&ev, rc, err)
		return ev, nil, false
	}
	// The retained response may be shorter than what is parsed.
	data, err := readHTTP(rc, path != "/")
	e.finish(&ev, rc, err)
	if plaintextToTLSError(data) {
		return ev, nil, false
	}
	if !parseHTTPReply(o, data, "GET "+path) {
		return ev, nil, false
	}
	ev.Matched = ProbeHTTP
	// An HTTP response can also carry a stronger database identity. Reuse
	// these bytes instead of scheduling a duplicate GET for the DB matcher.
	if e.enabled[ProbeDatabase] && matchHTTPDatabase(data, o) {
		ev.Matched = ProbeDatabase
	}
	if ev.Error == "timeout" {
		ev.Error = "" // keep-alive servers may ignore Connection: close
	}
	return ev, data, true
}

// readHTTP reads until the connection closes, the deadline passes, or the
// response head plus some body has arrived.
func readHTTP(c net.Conn, complete bool) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for len(buf) < maxHTTPRead {
		n, err := c.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if err != nil {
			return buf, err
		}
		if head := bytes.Index(buf, []byte("\r\n\r\n")); !complete && head >= 0 && (len(buf)-head > 2048 || bytes.Contains(bytes.ToLower(buf), []byte("</title>"))) {
			return buf, nil
		}
	}
	return buf, nil
}

// parseHTTP fills service fields from an HTTP/1.x response to GET /.
func parseHTTP(o *observe.Observation, data []byte) bool {
	return parseHTTPReply(o, data, "GET /")
}

// parseHTTPReply fills service fields from an HTTP/1.x response to request.
func parseHTTPReply(o *observe.Observation, data []byte, request string) bool {
	if !bytes.HasPrefix(data, []byte("HTTP/1.")) {
		return false
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
	attrs := map[string]string{}
	if err != nil {
		return false // a prefix alone is not protocol grammar
	} else {
		_ = resp.Body.Close()
		attrs["http.status"] = strconv.Itoa(resp.StatusCode)
		for header, key := range map[string]string{
			"Server": "http.server", "Content-Type": "http.content_type", "Location": "http.location",
			"X-Powered-By": "http.powered_by", "WWW-Authenticate": "http.www_authenticate",
			"X-Amz-Request-Id": "http.amz_request_id", "X-Amz-Bucket-Region": "http.amz_bucket_region",
		} {
			if v := resp.Header.Get(header); v != "" {
				attrs[key] = printable([]byte(v), 200)
			}
		}
		// MinIO, Ceph RADOS Gateway, SeaweedFS and other S3-compatible object
		// stores answer with an Amazon S3 request id (and an S3 Server token).
		if resp.Header.Get("X-Amz-Request-Id") != "" || strings.HasPrefix(resp.Header.Get("Server"), "MinIO") ||
			strings.HasPrefix(resp.Header.Get("Server"), "AmazonS3") {
			attrs["http.object_storage"] = "s3-compatible"
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
	o.Reason = "HTTP/1.x response to " + request
	if server := attrs["http.server"]; server != "" {
		token, _, _ := strings.Cut(server, " ")
		o.Product, o.Version = splitSoftware(token, "/")
		o.Reason += "; product from Server header"
	}
	return true
}
