package service

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// Port hints order the active probes. They never claim a service by
// themselves: an identity always comes from a matched response.
var (
	tlsPorts = portSet(261, 443, 448, 465, 563, 585, 614, 636, 853, 989, 990, 992, 993, 994, 995,
		2083, 2087, 2096, 2376, 2484, 3269, 4443, 5061, 5986, 6443, 6697, 7443, 8443, 8883, 9443, 10250)
	httpPorts = portSet(80, 81, 591, 2375, 3000, 3128, 5000, 5601, 5985, 7001, 7080, 8000, 8008, 8080,
		8081, 8088, 8180, 8888, 9000, 9090, 9200, 10000)
	dnsPorts = portSet(53)
)

func portSet(ports ...uint16) map[uint16]bool {
	m := make(map[uint16]bool, len(ports))
	for _, p := range ports {
		m[p] = true
	}
	return m
}

// plan returns the active probes for a port that sent no banner.
func (e *Engine) plan(port uint16) []string {
	var order []string
	switch {
	case dnsPorts[port]:
		order = []string{ProbeDNS}
	case tlsPorts[port]:
		order = []string{ProbeTLS, ProbeHTTP}
	case httpPorts[port]:
		order = []string{ProbeHTTP, ProbeTLS}
	default:
		order = e.cfg.Fallback
	}
	out := make([]string, 0, len(order))
	for _, p := range order {
		if e.enabled[p] {
			out = append(out, p)
		}
	}
	return out
}

// Interrogate identifies the service on one open port. The result is always
// a service observation: unrecognized or absent responses are reported as an
// unknown fingerprint with every exchange retained as evidence.
func (e *Engine) Interrogate(ctx context.Context, t Target) observe.Observation {
	o := observe.Observation{
		Kind: observe.KindService, Timestamp: time.Now().UTC(), Target: t.Addr, Transport: "tcp", Port: t.Port,
		State: "open", Fingerprint: observe.FingerprintUnknown,
	}
	if e.enabled[ProbeBanner] || e.enabled[ProbeSSH] {
		ev, banner := e.probeBanner(ctx, t)
		o.Evidence = append(o.Evidence, ev)
		o.ProbesAttempted = append(o.ProbesAttempted, ProbeBanner)
		if ev.Error != "" && len(banner) == 0 && !isTimeout(ev.Error) {
			o.State, o.Reason, o.Probe = "error", "banner connection failed: "+ev.Error, ProbeBanner
			return o
		}
		if len(banner) > 0 {
			o.Probe = ProbeBanner
			if e.enabled[ProbeSSH] && matchSSH(&o, banner) {
				o.Evidence[len(o.Evidence)-1].Matched = ProbeSSH
				return o
			}
			o.Attributes = map[string]string{"banner": printable(banner, 256)}
			o.Reason = "unrecognized banner retained as evidence"
			return o
		}
	}
	for _, p := range e.plan(t.Port) {
		if ctx.Err() != nil {
			break
		}
		o.ProbesAttempted = append(o.ProbesAttempted, p)
		var matched bool
		switch p {
		case ProbeTLS:
			matched = e.probeTLS(ctx, t, &o)
		case ProbeHTTP:
			var ev observe.Evidence
			ev, matched = e.probeHTTP(ctx, t, nil, "tcp", &o)
			o.Evidence = append(o.Evidence, ev)
		case ProbeDNS:
			matched = e.probeDNS(ctx, t, &o)
		}
		if matched {
			o.Fingerprint = observe.FingerprintMatched
			return o
		}
	}
	if o.Reason == "" {
		o.Reason = "no probe matched"
		for _, ev := range o.Evidence {
			if len(ev.Response) > 0 {
				o.Reason = "unrecognized response retained as evidence"
				break
			}
		}
		if len(o.Evidence) == 0 {
			o.Reason = "no enabled probe applies to this port"
		}
	}
	return o
}

// probeBanner connects and waits for the server to speak first.
func (e *Engine) probeBanner(ctx context.Context, t Target) (observe.Evidence, []byte) {
	timeout := e.timeout(ProbeBanner)
	ev := observe.Evidence{Probe: ProbeBanner, Layer: "tcp", Started: time.Now().UTC()}
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = err.Error(), time.Since(ev.Started)
		return ev, nil
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	data, err := readSome(rc, e.cfg.MaxEvidence, 200*time.Millisecond)
	e.finish(&ev, rc, err)
	return ev, data
}

// recordingConn keeps a bounded copy of both directions of an exchange.
type recordingConn struct {
	net.Conn
	max       int
	sent      []byte
	recv      []byte
	truncated bool
}

func (e *Engine) record(c net.Conn) *recordingConn {
	return &recordingConn{Conn: c, max: e.cfg.MaxEvidence}
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.recv, c.truncated = keep(c.recv, p[:n], c.max, c.truncated)
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.sent, _ = keep(c.sent, p[:n], c.max, false)
	return n, err
}

func keep(dst, src []byte, max int, truncated bool) ([]byte, bool) {
	room := max - len(dst)
	if room <= 0 {
		return dst, truncated || len(src) > 0
	}
	if len(src) > room {
		return append(dst, src[:room]...), true
	}
	return append(dst, src...), truncated
}

// finish copies the recorded exchange into ev. A read timeout after data
// arrived is the normal end of a passive read, not an error.
func (e *Engine) finish(ev *observe.Evidence, rc *recordingConn, err error) {
	ev.Duration = time.Since(ev.Started)
	ev.Request = append([]byte(nil), rc.sent...)
	ev.Response = append([]byte(nil), rc.recv...)
	ev.Truncated = rc.truncated
	if err != nil && !errors.Is(err, io.EOF) && !(len(rc.recv) > 0 && errors.Is(err, os.ErrDeadlineExceeded)) {
		ev.Error = errorText(err)
	}
}

// deadline applies the probe budget and aborts blocking I/O on cancel.
func deadline(ctx context.Context, c net.Conn, timeout time.Duration) func() bool {
	d := time.Now().Add(timeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(d) {
		d = cd
	}
	_ = c.SetDeadline(d)
	return context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
}

// readSome reads until EOF, the connection deadline, max bytes, or a quiet
// gap after the first data arrived.
func readSome(c net.Conn, max int, quiet time.Duration) ([]byte, error) {
	buf := make([]byte, 0, min(max, 4096))
	chunk := make([]byte, 2048)
	for len(buf) < max {
		n, err := c.Read(chunk[:min(len(chunk), max-len(buf))])
		buf = append(buf, chunk[:n]...)
		if err != nil {
			return buf, err
		}
		if n > 0 {
			shorter := time.Now().Add(quiet)
			_ = c.SetReadDeadline(shorter)
		}
	}
	return buf, nil
}

func errorText(err error) string {
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	return err.Error()
}

func isTimeout(text string) bool { return text == "timeout" }

// printable renders bytes for a short attribute; the raw bytes stay in evidence.
func printable(b []byte, max int) string {
	var s strings.Builder
	for _, c := range b {
		if s.Len() >= max {
			break
		}
		switch {
		case c == '\r' || c == '\n' || c == '\t':
			s.WriteByte(' ')
		case c >= 0x20 && c < 0x7f:
			s.WriteByte(c)
		default:
			s.WriteByte('.')
		}
	}
	return strings.TrimSpace(s.String())
}
