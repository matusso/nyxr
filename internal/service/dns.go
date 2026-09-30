package service

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// versionBindQuery is a CHAOS-class TXT query for version.bind: a read-only
// query that name servers either answer, refuse or ignore.
func versionBindQuery(id uint16) []byte {
	msg := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(msg[:2], id)
	msg = append(msg, 7)
	msg = append(msg, "version"...)
	msg = append(msg, 4)
	msg = append(msg, "bind"...)
	msg = append(msg, 0, 0, 16, 0, 3) // root, TXT, CH
	framed := make([]byte, 2, 2+len(msg))
	binary.BigEndian.PutUint16(framed, uint16(len(msg)))
	return append(framed, msg...)
}

func (e *Engine) probeDNS(ctx context.Context, t Target, o *observe.Observation) bool {
	timeout := e.timeout(ProbeDNS)
	ev := observe.Evidence{Probe: ProbeDNS, Layer: "tcp", Started: time.Now().UTC()}
	defer func() { o.Evidence = append(o.Evidence, ev) }()
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		return false
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	var idBytes [2]byte
	_, _ = rand.Read(idBytes[:])
	id := binary.BigEndian.Uint16(idBytes[:])
	if _, err := rc.Write(versionBindQuery(id)); err != nil {
		e.finish(&ev, rc, err)
		return false
	}
	var length [2]byte
	if _, err := io.ReadFull(rc, length[:]); err != nil {
		e.finish(&ev, rc, err)
		return false
	}
	msg := make([]byte, binary.BigEndian.Uint16(length[:]))
	_, err = io.ReadFull(rc, msg)
	e.finish(&ev, rc, err)
	if err != nil {
		return false
	}
	rcode, txt, err := parseDNSResponse(msg, id)
	if err != nil {
		ev.Error = err.Error()
		return false
	}
	ev.Matched = ProbeDNS
	o.Service, o.Confidence, o.Probe = "dns", 100, ProbeDNS
	o.Reason = "DNS response with matching transaction ID"
	o.Attributes = map[string]string{"dns.rcode": strconv.Itoa(rcode)}
	if txt != "" {
		o.Attributes["dns.version_bind"] = printable([]byte(txt), 200)
	}
	return true
}

// parseDNSResponse validates the header against the query and returns the
// response code and the first TXT string of the first answer, if any.
func parseDNSResponse(msg []byte, id uint16) (int, string, error) {
	if len(msg) < 12 {
		return 0, "", errors.New("short DNS message")
	}
	if binary.BigEndian.Uint16(msg[:2]) != id || msg[2]&0x80 == 0 {
		return 0, "", errors.New("DNS reply does not match the query")
	}
	rcode := int(msg[3] & 0x0f)
	qd, an := binary.BigEndian.Uint16(msg[4:6]), binary.BigEndian.Uint16(msg[6:8])
	off := 12
	for i := 0; i < int(qd); i++ {
		var err error
		if off, err = skipName(msg, off); err != nil {
			return rcode, "", nil
		}
		off += 4
	}
	if an == 0 || off > len(msg) {
		return rcode, "", nil
	}
	off, err := skipName(msg, off)
	if err != nil || off+10 > len(msg) {
		return rcode, "", nil
	}
	typ := binary.BigEndian.Uint16(msg[off:])
	rdlen := int(binary.BigEndian.Uint16(msg[off+8:]))
	off += 10
	if typ != 16 || off+rdlen > len(msg) || rdlen < 1 {
		return rcode, "", nil
	}
	n := int(msg[off])
	if n+1 > rdlen {
		return rcode, "", nil
	}
	return rcode, string(msg[off+1 : off+1+n]), nil
}

// skipName advances past a possibly compressed domain name.
func skipName(msg []byte, off int) (int, error) {
	for steps := 0; steps < 128; steps++ {
		if off >= len(msg) {
			return 0, errors.New("truncated name")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xc0 == 0xc0:
			if off+2 > len(msg) {
				return 0, errors.New("truncated pointer")
			}
			return off + 2, nil
		case l&0xc0 != 0:
			return 0, errors.New("bad label")
		default:
			off += 1 + l
		}
	}
	return 0, errors.New("name too long")
}
