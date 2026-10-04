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
	planner := newProbePlanner(e, t.Port)
	defer func() { o.ServiceHypotheses = planner.probabilities() }()
	if e.enabled[ProbeBanner] || e.enabled[ProbeSSH] || e.enabled[ProbeNmap] || e.enabled[ProbeDatabase] {
		ev, banner := e.probeBanner(ctx, t)
		o.Evidence = append(o.Evidence, ev)
		o.ProbesAttempted = append(o.ProbesAttempted, ProbeBanner)
		if ev.Error != "" && len(banner) == 0 && !isTimeout(ev.Error) {
			o.State, o.Reason, o.Probe = "error", "banner connection failed: "+ev.Error, ProbeBanner
			return o
		}
		if len(banner) > 0 {
			o.Probe = ProbeBanner
			if e.enabled[ProbeDatabase] && matchDatabaseBanner(&o, banner) {
				o.Evidence[len(o.Evidence)-1].Matched = ProbeDatabase
				planner.confirmPassive(ProbeDatabase)
				return o
			}
			if e.enabled[ProbeSSH] && matchSSH(&o, banner) {
				o.Evidence[len(o.Evidence)-1].Matched = ProbeSSH
				planner.confirmPassive(ProbeSSH)
				return o
			}
			if e.enabled[ProbeBanner] && (matchMailBanner(&o, banner) || matchRsyncBanner(&o, banner) || matchFTPBanner(&o, banner) || matchCephBanner(&o, banner)) {
				o.Evidence[len(o.Evidence)-1].Matched = ProbeBanner
				planner.confirmNamed(o.Service, float64(o.Confidence)/100)
				return o
			}
			if e.nmapBanner(&o, banner) {
				o.Evidence[len(o.Evidence)-1].Matched = ProbeNmap
				planner.confirmNamed(o.Service, float64(o.Confidence)/100)
				return o
			}
			o.Attributes = map[string]string{"banner": printable(banner, 256)}
			o.Reason = "unrecognized banner retained as evidence"
			planner.observeBanner(banner, e)
		}
	}
	for {
		if ctx.Err() != nil {
			break
		}
		p, gain, score := planner.next()
		if p == "" {
			break
		}
		o.ProbeDecisions = append(o.ProbeDecisions, observe.ProbeDecision{
			Probe: p, InformationGain: gain, Score: score, Hypotheses: planner.probabilities(),
		})
		o.ProbesAttempted = append(o.ProbesAttempted, p)
		firstEvidence := len(o.Evidence)
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
		case ProbeSOCKS:
			matched = e.probeSOCKS(ctx, t, &o)
		case ProbeModbus:
			matched = e.probeModbus(ctx, t, &o)
		case ProbeEtherNetIP:
			matched = e.probeEtherNetIP(ctx, t, &o)
		case ProbeDatabase:
			matched = e.probeDatabase(ctx, t, &o, planner.redisHint)
		case ProbeSMB:
			matched = e.probeSMB(ctx, t, &o)
		case ProbeRDP:
			matched = e.probeRDP(ctx, t, &o)
		case ProbeMSRPC:
			matched = e.probeMSRPC(ctx, t, &o)
		case ProbeLDAP:
			matched = e.probeLDAP(ctx, t, &o)
		case ProbeKerberos:
			matched = e.probeKerberos(ctx, t, &o)
		case ProbeNFS:
			matched = e.probeNFS(ctx, t, &o)
		}
		if len(o.Evidence) > firstEvidence {
			ev := o.Evidence[firstEvidence]
			if ev.Error != "" && ev.Error != "timeout" && len(ev.Response) == 0 {
				planner.attempted[p] = true // connection failures say nothing about protocol
			} else {
				planner.update(p, matched, ev.Response, e)
			}
		} else {
			planner.attempted[p] = true
		}
		if matched {
			if (p == ProbeHTTP && o.Probe == ProbeDatabase) ||
				(p == ProbeTLS && o.Probe == ProbeTLS+"+"+ProbeDatabase) {
				planner.confirmNamed(o.Service, float64(o.Confidence)/100)
			}
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
	if e.enabled[ProbeDatabase] && !e.enabled[ProbeSSH] && timeout > 350*time.Millisecond {
		timeout = 350 * time.Millisecond
	}
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
	ev.Decoded = tlsrecord.Decode(ev.Response)
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
