package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// probeHTTP2 uses the negotiated TLS connection for one stream. Frame count,
// frame size, decoded headers, body and total wire input all have limits; a
// peer cannot extend the probe indefinitely with SETTINGS or CONTINUATION.
func (e *Engine) probeHTTP2(ctx context.Context, t Target, conn net.Conn, o *observe.Observation) (ev observe.Evidence, matched bool) {
	ev, _, matched = e.probeHTTP2Exchange(ctx, t, conn, "/", o)
	return ev, matched
}

func (e *Engine) probeHTTP2Exchange(ctx context.Context, t Target, conn net.Conn, path string, o *observe.Observation) (ev observe.Evidence, data []byte, matched bool) {
	ev = observe.Evidence{Probe: "http2", Layer: "tls", Started: time.Now().UTC()}
	rc := e.record(conn)
	stop := deadline(ctx, rc, e.timeout(ProbeHTTP))
	defer stop()
	var exchangeErr error
	defer func() { e.finish(&ev, rc, exchangeErr) }()
	f := http2.NewFramer(rc, io.LimitReader(rc, 64<<10))
	f.SetMaxReadFrameSize(16 << 10)
	f.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	f.ReadMetaHeaders.SetMaxStringLength(maxHTTPRead)
	f.MaxHeaderListSize = maxHTTPRead
	if _, exchangeErr = io.WriteString(rc, http2.ClientPreface); exchangeErr != nil {
		return ev, nil, false
	}
	exchangeErr = f.WriteSettings(
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: maxHTTPRead},
	)
	if exchangeErr != nil {
		return ev, nil, false
	}
	host := t.Addr.String()
	if t.Port != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(int(t.Port)))
	} else if t.Addr.Is6() {
		host = "[" + host + "]"
	}
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: host}, {Name: ":path", Value: path},
		{Name: "user-agent", Value: e.cfg.UserAgent}, {Name: "accept", Value: "*/*"},
	} {
		if exchangeErr = encoder.WriteField(field); exchangeErr != nil {
			return ev, nil, false
		}
	}
	exchangeErr = f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndStream: true, EndHeaders: true})
	if exchangeErr != nil {
		return ev, nil, false
	}
	var head, body bytes.Buffer
	status := ""
	for frames := 0; frames < 64; frames++ {
		frame, err := f.ReadFrame()
		if err != nil {
			exchangeErr = err
			break
		}
		ended := false
		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			if !frame.IsAck() {
				exchangeErr = f.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !frame.IsAck() {
				exchangeErr = f.WritePing(true, frame.Data)
			}
		case *http2.MetaHeadersFrame:
			if frame.StreamID != 1 || frame.Truncated {
				exchangeErr = errors.New("invalid HTTP/2 response headers")
				break
			}
			if status == "" {
				for _, field := range frame.Fields {
					if field.Name == ":status" {
						status = field.Value
					} else if !strings.HasPrefix(field.Name, ":") {
						fmt.Fprintf(&head, "%s: %s\r\n", field.Name, field.Value)
					}
				}
				code, err := strconv.Atoi(status)
				if err != nil || len(status) != 3 || code < 100 || code > 599 {
					exchangeErr = errors.New("invalid HTTP/2 status")
					break
				}
				if code < 200 { // informational headers precede the final response
					status = ""
					head.Reset()
				}
			}
			ended = frame.StreamEnded()
		case *http2.DataFrame:
			if frame.StreamID != 1 || status == "" {
				exchangeErr = errors.New("HTTP/2 DATA before response headers")
				break
			}
			data := frame.Data()
			body.Write(data[:min(len(data), maxHTTPRead-body.Len())])
			ended = frame.StreamEnded() || body.Len() >= maxHTTPRead
		case *http2.RSTStreamFrame:
			exchangeErr = fmt.Errorf("HTTP/2 stream reset: %s", frame.ErrCode)
		case *http2.GoAwayFrame:
			exchangeErr = fmt.Errorf("HTTP/2 GOAWAY: %s", frame.ErrCode)
		}
		if exchangeErr != nil || ended {
			break
		}
	}
	if status == "" {
		return ev, nil, false
	}
	// Reuse the HTTP identity parser without pretending the retained binary
	// frames are HTTP/1 bytes. The synthetic head is never stored as evidence.
	data = []byte("HTTP/1.1 " + status + " response\r\n" + head.String() + "\r\n" + body.String())
	if !parseHTTPReply(o, data, "GET "+path) {
		return ev, nil, false
	}
	o.Reason = strings.Replace(o.Reason, "HTTP/1.x response", "HTTP/2 response", 1)
	o.Attributes["http.version"] = "HTTP/2"
	ev.Matched = ProbeHTTP
	if e.enabled[ProbeDatabase] && matchHTTPDatabase(data, o) {
		ev.Matched = ProbeDatabase
	}
	return ev, data, true
}
