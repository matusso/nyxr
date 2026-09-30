package scan

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/matusso/nyxr/internal/probe"
)

type sentProbe struct {
	probe   probe.Probe
	request []byte
	sent    time.Time
}

func matchRecent(recent []sentProbe, response []byte) (sentProbe, bool) {
	for i := len(recent) - 1; i >= 0; i-- {
		if probe.Match(recent[i].probe, recent[i].request, response) {
			return recent[i], true
		}
	}
	return sentProbe{}, false
}

func probeUDPCampaign(ctx context.Context, t task, timeout time.Duration, all []probe.Probe, extraRetries int, secret []byte, limiter *probeLimiter) Observation {
	selected := probe.ForPort(all, t.port)
	o := base(t, selected[0].Name)
	addr := &net.UDPAddr{IP: net.IP(t.target.AsSlice()), Port: int(t.port), Zone: t.target.Zone()}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		o.State, o.Reason = "error", err.Error()
		return o
	}
	defer conn.Close()
	var buf [4096]byte
	var unknownResponse bool
	var attempt uint32
	recent := make([]sentProbe, 0, 32)
	for _, p := range selected {
		probeTimeout := timeout
		if p.Timeout > 0 && p.Timeout < probeTimeout {
			probeTimeout = p.Timeout
		}
		for retry := 0; retry <= p.Retries+extraRetries; retry++ {
			if err := limiter.Wait(ctx); err != nil {
				o.State, o.Reason = "error", err.Error()
				return o
			}
			o.Probe = p.Name
			o.ProbesAttempted = append(o.ProbesAttempted, p.Name)
			attempt++
			request := probe.Prepare(p, probe.Token(secret, t.target.String(), t.port, p.Name, attempt))
			deadline := time.Now().Add(probeTimeout)
			if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
				deadline = d
			}
			if err := conn.SetDeadline(deadline); err != nil {
				o.State, o.Reason = "error", err.Error()
				return o
			}
			start := time.Now()
			if _, err := conn.Write(request); err != nil {
				if isUDPPortUnreachable(err) {
					o.State, o.Confidence, o.Reason = "closed", 95, "ICMP port unreachable"
				} else {
					o.State, o.Reason = "error", err.Error()
				}
				return o
			}
			o.PacketsTX++
			if len(recent) == 32 {
				copy(recent, recent[1:])
				recent = recent[:31]
			}
			recent = append(recent, sentProbe{probe: p, request: request, sent: start})
			// A late response to a previous attempt must not be mistaken for this
			// attempt. Continue reading until a matching token or the deadline.
			for received := 0; received < 16; received++ {
				n, err := conn.Read(buf[:])
				if isUDPPortUnreachable(err) {
					o.State, o.Confidence, o.Reason, o.PacketsRX = "closed", 95, "ICMP port unreachable", o.PacketsRX+1
					return o
				}
				if isTimeout(err) {
					break
				}
				if err != nil {
					o.State, o.Reason = "error", err.Error()
					return o
				}
				o.PacketsRX++
				if n > 128 {
					o.ResponseHex = hex.EncodeToString(buf[:128])
				} else {
					o.ResponseHex = hex.EncodeToString(buf[:n])
				}
				if matched, ok := matchRecent(recent, buf[:n]); ok {
					confidence, reason := 100, "validated "+matched.probe.Matcher+" response"
					if matched.probe.Matcher == "any" {
						confidence, reason = 95, "UDP response received"
					} else {
						o.Service = matched.probe.Matcher
					}
					o.Probe = matched.probe.Name
					o.State, o.Confidence, o.Reason, o.RTT = "open", confidence, reason, time.Since(matched.sent)
					return o
				}
				unknownResponse = true
				o.RTT = time.Since(start)
			}
		}
	}
	if unknownResponse {
		o.State, o.Confidence, o.Reason = "open", 75, "UDP response with unknown fingerprint"
	} else {
		o.State, o.Confidence, o.Reason = "open|filtered", 30, "no UDP or ICMP response"
	}
	return o
}

func isUDPPortUnreachable(err error) bool {
	// Windows reports an ICMP port unreachable as WSAECONNRESET (10054).
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.Errno(10054))
}
