package service

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/tlsrecord"
)

// Port hints influence priors and active-probe eligibility. They never
// claim a service by themselves: an identity comes from a matched response.
var (
	tlsPorts = portSet(261, 443, 448, 465, 563, 585, 614, 636, 853, 989, 990, 992, 993, 994, 995,
		2083, 2087, 2096, 2376, 2484, 3269, 4443, 5061, 5986, 6443, 6697, 7443, 8443, 8883, 9443, 10250)
	httpPorts = portSet(80, 81, 591, 2375, 3000, 3128, 5000, 5601, 5985, 7001, 7080, 8000, 8008, 8080,
		8081, 8088, 8180, 8888, 9000, 9090, 9200, 10000)
	dnsPorts        = portSet(53)
	socksPorts      = portSet(1080)
	modbusPorts     = portSet(502)
	ethernetIPPorts = portSet(44818)
	// Windows-propagated services. SMB answers on the NetBIOS session port
	// (139) and the direct-TCP port (445); RDP on 3389; the DCE/RPC endpoint
	// mapper on 135.
	smbPorts   = portSet(139, 445)
	rdpPorts   = portSet(3389)
	msrpcPorts = portSet(135)
	// Directory and file-system services. LDAPS (636, 3269) is reached through
	// the TLS probe instead; the LDAP probe speaks plaintext on 389 and the
	// Global Catalog port 3268. NFS answers on 2049 and the ONC RPC portmapper
	// on 111.
	ldapPorts     = portSet(389, 3268)
	kerberosPorts = portSet(88)
	nfsPorts      = portSet(111, 2049)
)

func portSet(ports ...uint16) map[uint16]bool {
	m := make(map[uint16]bool, len(ports))
	for _, p := range ports {
		m[p] = true
	}
	return m
}

// Interrogate identifies the service on one open port. The result is always
// a service observation: unrecognized or absent responses are reported as an
// unknown fingerprint with every exchange retained as evidence.
func (e *Engine) Interrogate(ctx context.Context, t Target) (o observe.Observation) {
	o = observe.Observation{
		Kind: observe.KindService, Timestamp: time.Now().UTC(), Target: t.Addr, Transport: "tcp", Port: t.Port,
		State: "open", Fingerprint: observe.FingerprintUnknown,
	}
	transport := t.Transport
	if transport == "" {
		transport = "tcp"
	}
	planner := newProbePlannerFor(e, t.Port, transport)
	defer func() {
		o.ServiceHypotheses = planner.probabilities()
		if ctx.Err() != nil {
			o.ProbeStopReason = "canceled"
		}
	}()
	if transport == "udp" {
		o.Transport = "udp"
		if t.State != "" {
			o.State = t.State
		}
	} else if e.enabled[ProbeBanner] || e.enabled[ProbeSSH] || e.enabled[ProbeNmap] || e.enabled[ProbeDatabase] {
		before := planner.probabilities()
		ev, banner, connected := e.probeBanner(ctx, t)
		o.Evidence = append(o.Evidence, ev)
		o.ProbesAttempted = append(o.ProbesAttempted, ProbeBanner)
		if !connected {
			o.State, o.Reason, o.Probe = "error", "banner connection failed: "+ev.Error, ProbeBanner
			o.ProbeStopReason = "connection failed"
			planner.recordUpdate(&o, ProbeBanner, "inconclusive", 0, before, "")
			return o
		}
		if len(banner) > 0 {
			o.Probe = ProbeBanner
			matched := e.matchBanner(&o, banner)
			if matched == "" && e.enabled[ProbeHTTP] && !plaintextToTLSError(banner) && parseHTTP(&o, banner) {
				matched = ProbeHTTP
			}
			if matched != "" {
				o.Evidence[0].Matched = matched
				if matched == ProbeDatabase || matched == ProbeSSH || matched == ProbeHTTP {
					planner.confirmPassive(matched)
				} else {
					planner.confirmNamed(o.Service, float64(o.Confidence)/100)
				}
				planner.recordUpdate(&o, ProbeBanner, "matched", 0, before, matched)
				if matched == ProbeSSH && ctx.Err() == nil {
					o.ProbesAttempted = append(o.ProbesAttempted, probeSSHHostKey)
					o.Evidence = append(o.Evidence, e.probeSSHHostKey(ctx, t, &o))
				}
				o.Fingerprint, o.ProbeStopReason = observe.FingerprintMatched, "identified"
				return o
			}
			o.Attributes = map[string]string{"banner": printable(banner, 256)}
			o.Reason = "unrecognized banner retained as evidence"
			planner.observeBanner(banner, e)
			planner.recordUpdate(&o, ProbeBanner, "unmatched", 0, before, responseHint(banner))
		} else {
			planner.recordUpdate(&o, ProbeBanner, "inconclusive", 0, before, "")
		}
	}
	for ctx.Err() == nil {
		name, gain, score := planner.next()
		if name == "" {
			o.ProbeStopReason = "candidates exhausted"
			break
		}
		if !e.probeBudget(&o) {
			break
		}
		if gain < 0.0001 {
			o.ProbeStopReason = "insufficient information gain"
			break
		}
		before := planner.probabilities()
		o.ProbeDecisions = append(o.ProbeDecisions, observe.ProbeDecision{
			Probe: name, InformationGain: gain, Score: score, Hypotheses: before,
		})
		o.ProbesAttempted = append(o.ProbesAttempted, name)
		start := len(o.Evidence)
		matched := e.executeProbe(ctx, t, name, planner.redisHint, &o)
		// A service may speak first on an active connection too. Reuse that
		// greeting instead of sending an unrelated follow-up to it.
		if !matched && transport == "tcp" {
			for i := start; i < len(o.Evidence); i++ {
				if family := e.matchBanner(&o, o.Evidence[i].Response); family != "" {
					o.Evidence[i].Matched = family
					planner.confirmNamed(o.Service, float64(o.Confidence)/100)
					matched = true
					break
				}
			}
		}
		planner.observeExchange(&o, name, matched, start, before, e)
		if matched {
			if strings.HasPrefix(name, "dsl/") || transport == "udp" {
				o.Confidence = planner.confidence(name)
			}
			if (name == ProbeHTTP && o.Probe == ProbeDatabase) ||
				(name == ProbeTLS && strings.HasPrefix(o.Probe, ProbeTLS+"+") && o.Probe != ProbeTLS+"+"+ProbeHTTP) {
				planner.confirmNamed(o.Service, float64(o.Confidence)/100)
				// Include the named inference in this step's after snapshot.
				o.ProbeUpdates[len(o.ProbeUpdates)-1].After = planner.probabilities()
			}
			o.State, o.Fingerprint, o.ProbeStopReason = "open", observe.FingerprintMatched, "identified"
			e.validateProduct(ctx, t, &o)
			return o
		}
		if o.ProbeStopReason == "probe budget exhausted" {
			break
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

// matchBanner runs the enabled server-first matchers over a greeting, from
// the most to the least specific, and returns the probe credited with the
// match, or "" when none applies.
func (e *Engine) matchBanner(o *observe.Observation, banner []byte) string {
	switch {
	case e.enabled[ProbeDatabase] && matchDatabaseBanner(o, banner):
		return ProbeDatabase
	case e.enabled[ProbeSSH] && matchSSH(o, banner):
		return ProbeSSH
	case e.enabled[ProbeBanner] && (matchMailBanner(o, banner) || matchRsyncBanner(o, banner) || matchFTPBanner(o, banner) || matchTelnetBanner(o, banner) || matchCephBanner(o, banner)):
		return ProbeBanner
	case e.nmapBanner(o, banner):
		return ProbeNmap
	}
	return ""
}

// probeBanner connects and waits for the server to speak first.
func (e *Engine) probeBanner(ctx context.Context, t Target) (observe.Evidence, []byte, bool) {
	timeout := e.timeout(ProbeBanner)
	if e.enabled[ProbeDatabase] && !e.enabled[ProbeSSH] && timeout > 350*time.Millisecond {
		timeout = 350 * time.Millisecond
	}
	ev := observe.Evidence{Probe: ProbeBanner, Layer: "tcp", Started: time.Now().UTC()}
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = err.Error(), time.Since(ev.Started)
		return ev, nil, false
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	data, err := readSome(rc, e.cfg.MaxEvidence, 200*time.Millisecond)
	e.finish(&ev, rc, err)
	return ev, data, true
}

// recordingConn keeps a bounded copy of both directions of an exchange.
type recordingConn struct {
	net.Conn
	max        int
	bufferMu   sync.Mutex
	sent       []byte
	recv       []byte
	truncated  bool
	deadlineMu sync.Mutex
	readLimit  time.Time
}

func (c *recordingConn) SetDeadline(d time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readLimit = d
	return c.Conn.SetDeadline(d)
}

// Quiet-gap reads must not extend the exchange's original deadline, including
// a deadline shortened by cancellation from another goroutine.
func (c *recordingConn) SetReadDeadline(d time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if !c.readLimit.IsZero() && d.After(c.readLimit) {
		d = c.readLimit
	}
	return c.Conn.SetReadDeadline(d)
}

func (e *Engine) record(c net.Conn) *recordingConn {
	return &recordingConn{Conn: c, max: e.cfg.MaxEvidence}
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.bufferMu.Lock()
	c.recv, c.truncated = keep(c.recv, p[:n], c.max, c.truncated)
	c.bufferMu.Unlock()
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.bufferMu.Lock()
	c.sent, _ = keep(c.sent, p[:n], c.max, false)
	c.bufferMu.Unlock()
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
	rc.bufferMu.Lock()
	ev.Request = append([]byte(nil), rc.sent...)
	ev.Response = append([]byte(nil), rc.recv...)
	ev.Truncated = rc.truncated
	rc.bufferMu.Unlock()
	ev.Decoded = tlsrecord.Decode(ev.Response)
	if err != nil && !errors.Is(err, io.EOF) && !(len(ev.Response) > 0 && errors.Is(err, os.ErrDeadlineExceeded)) {
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
