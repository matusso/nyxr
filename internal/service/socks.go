package service

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

func (e *Engine) probeSOCKS(ctx context.Context, t Target, o *observe.Observation) bool {
	if e.probeSOCKS5(ctx, t, o) {
		return true
	}
	return e.probeSOCKS4(ctx, t, o)
}

func (e *Engine) probeSOCKS5(ctx context.Context, t Target, o *observe.Observation) bool {
	ev := observe.Evidence{Probe: ProbeSOCKS, Layer: "tcp", Started: time.Now().UTC()}
	defer func() { o.Evidence = append(o.Evidence, ev) }()
	timeout := e.timeout(ProbeSOCKS)
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		return false
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	defer func() { e.finish(&ev, rc, err) }()
	if _, err = rc.Write([]byte{5, 1, 0}); err != nil {
		return false
	}
	var method [2]byte
	if _, err = io.ReadFull(rc, method[:]); err != nil || method[0] != 5 {
		return false
	}
	o.Service, o.Probe, o.Confidence = "socks5", ProbeSOCKS, 100
	o.Attributes = map[string]string{"socks.udp_associate": "unavailable"}
	o.Reason = "SOCKS5 method negotiation response"
	ev.Matched = ProbeSOCKS
	if method[1] != 0 { // This scanner does not try credentials.
		return true
	}
	// A zero address and port request a relay for the current TCP client's
	// address. The returned BND.PORT is the relay's allocated UDP endpoint.
	if _, err = rc.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return true
	}
	var header [4]byte
	if _, err = io.ReadFull(rc, header[:]); err != nil || header[0] != 5 || header[2] != 0 {
		return true
	}
	addr, port, readErr := readSOCKSAddress(rc, header[3], t)
	err = readErr
	if err != nil {
		return true
	}
	if header[1] != 0 {
		o.Attributes["socks.udp_associate"] = "rejected"
		o.Attributes["socks.udp_reply_code"] = strconv.Itoa(int(header[1]))
		o.Reason = "SOCKS5 UDP ASSOCIATE was rejected"
		return true
	}
	if port == 0 {
		return true
	}
	o.Attributes["socks.udp_associate"] = "accepted"
	o.Attributes["socks.udp_relay_address"] = addr
	o.Attributes["socks.udp_relay_port"] = strconv.Itoa(int(port))
	o.Attributes["socks.udp_relay_transient"] = "true"
	o.Reason = "SOCKS5 UDP ASSOCIATE returned a relay endpoint"
	return true
}

func readSOCKSAddress(r io.Reader, atyp byte, target Target) (string, uint16, error) {
	var size int
	switch atyp {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return "", 0, err
		}
		if length[0] == 0 {
			return "", 0, io.ErrUnexpectedEOF
		}
		size = int(length[0])
	default:
		return "", 0, io.ErrUnexpectedEOF
	}
	data := make([]byte, size+2)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", 0, err
	}
	port := binary.BigEndian.Uint16(data[size:])
	var addr string
	if atyp == 3 {
		addr = printable(data[:size], 255)
	} else {
		ip := net.IP(data[:size])
		if ip.IsUnspecified() {
			addr = target.Addr.String()
		} else {
			addr = ip.String()
		}
	}
	return addr, port, nil
}

func (e *Engine) probeSOCKS4(ctx context.Context, t Target, o *observe.Observation) bool {
	ev := observe.Evidence{Probe: ProbeSOCKS, Layer: "tcp", Started: time.Now().UTC()}
	defer func() { o.Evidence = append(o.Evidence, ev) }()
	timeout := e.timeout(ProbeSOCKS)
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		return false
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	defer func() { e.finish(&ev, rc, err) }()
	// CONNECT to 0.0.0.0:0 is intentionally unusable; a rejection still
	// identifies SOCKS4 without opening an outbound proxy connection.
	if _, err = rc.Write([]byte{4, 1, 0, 0, 0, 0, 0, 0, 0}); err != nil {
		return false
	}
	var reply [8]byte
	if _, err = io.ReadFull(rc, reply[:]); err != nil || reply[0] != 0 || reply[1] < 0x5a || reply[1] > 0x5d {
		return false
	}
	o.Service, o.Probe, o.Confidence = "socks4", ProbeSOCKS, 100
	o.Reason = "SOCKS4 request received a protocol reply"
	o.Attributes = map[string]string{"socks.udp_associate": "unsupported"}
	ev.Matched = ProbeSOCKS
	return true
}
