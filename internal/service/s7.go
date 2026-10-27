package service

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// S7comm identity reads over ISO-on-TCP (RFC 1006, TCP/102). The probe sends
// only a COTP connection request, an S7 Setup Communication and two System
// Status List (SZL) reads: 0x0011 module identification and 0x001C component
// identification. SZL reads are the documented read-only diagnostic service;
// nothing here writes memory, changes the CPU mode or supplies a password.

const s7MaxRecords = 32

// s7Endpoints are the rack/slot pairs tried, in order: S7-300/400 CPUs sit
// in slot 2, S7-1200/1500 in slot 1. Each attempt is one connection.
var s7Endpoints = []struct{ rack, slot byte }{{0, 2}, {0, 1}}

func s7ConnectRequest(rack, slot byte) []byte {
	return []byte{
		3, 0, 0, 22, // TPKT
		17, 0xe0, 0, 0, 0, 1, 0, // COTP CR, class 0
		0xc1, 2, 1, 0, // calling TSAP: PG/PC
		0xc2, 2, 1, rack<<5 | slot, // called TSAP: rack and slot
		0xc0, 1, 10, // TPDU size 1024
	}
}

var s7SetupRequest = []byte{
	3, 0, 0, 25, 2, 0xf0, 0x80, // TPKT, COTP DT
	0x32, 1, 0, 0, 0, 1, 0, 8, 0, 0, // S7 job, PDU ref 1, 8 parameter bytes
	0xf0, 0, 0, 1, 0, 1, 1, 0xe0, // Setup Communication: 1 job each way, PDU 480
}

func s7ReadSZL(ref uint16, id, index uint16) []byte {
	b := []byte{
		3, 0, 0, 33, 2, 0xf0, 0x80,
		0x32, 7, 0, 0, byte(ref >> 8), byte(ref), 0, 8, 0, 8, // userdata, 8 parameter and 8 data bytes
		0, 1, 0x12, 4, 0x11, 0x44, 1, 0, // request, CPU functions, read SZL
		0xff, 9, 0, 4, // data: success, octet string, 4 bytes
		byte(id >> 8), byte(id), byte(index >> 8), byte(index),
	}
	return b
}

// s7PDU is one S7comm message: its ROSCTR, parameters and data.
type s7PDU struct {
	rosctr      byte
	ref         uint16
	errorClass  byte
	errorCode   byte
	param, data []byte
}

func readS7(r net.Conn) (s7PDU, error) {
	body, err := readTPKT(r)
	if err != nil {
		return s7PDU{}, err
	}
	if len(body) < 3 || body[0] != 2 || body[1] != 0xf0 {
		return s7PDU{}, errors.New("not a COTP data TPDU")
	}
	b := body[3:]
	if len(b) < 10 || b[0] != 0x32 {
		return s7PDU{}, errors.New("not an S7comm PDU")
	}
	p := s7PDU{rosctr: b[1], ref: binary.BigEndian.Uint16(b[4:])}
	plen, dlen := int(binary.BigEndian.Uint16(b[6:])), int(binary.BigEndian.Uint16(b[8:]))
	b = b[10:]
	if p.rosctr == 2 || p.rosctr == 3 {
		if len(b) < 2 {
			return s7PDU{}, errors.New("short S7 acknowledgement")
		}
		p.errorClass, p.errorCode = b[0], b[1]
		b = b[2:]
	}
	if plen+dlen != len(b) {
		return s7PDU{}, fmt.Errorf("S7 lengths %d+%d do not match %d bytes", plen, dlen, len(b))
	}
	p.param, p.data = b[:plen], b[plen:]
	return p, nil
}

// probeS7 identifies a Siemens S7 CPU. Each rack/slot attempt is separate
// evidence, so an operator can see exactly which TSAPs were contacted.
func (e *Engine) probeS7(ctx context.Context, t Target, o *observe.Observation) bool {
	for _, ep := range s7Endpoints {
		if ctx.Err() != nil {
			return false
		}
		matched, connected := e.s7Identity(ctx, t, ep.rack, ep.slot, o)
		if matched {
			return true
		}
		if !connected {
			return false // the port did not speak ISO-on-TCP; a second TSAP will not help
		}
	}
	return false
}

// s7Identity runs one connection. connected reports that the peer answered
// the COTP layer, which justifies trying another TSAP.
func (e *Engine) s7Identity(ctx context.Context, t Target, rack, slot byte, o *observe.Observation) (matched, connected bool) {
	ev := observe.Evidence{Probe: ProbeS7, Layer: "tcp", Started: time.Now().UTC()}
	defer func() { o.Evidence = append(o.Evidence, ev) }()
	timeout := e.timeout(ProbeS7)
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		return false, false
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	fail := func(err error) (bool, bool) {
		e.finish(&ev, rc, err)
		return false, connected
	}
	if _, err := rc.Write(s7ConnectRequest(rack, slot)); err != nil {
		return fail(err)
	}
	cc, err := readTPKT(rc)
	if err != nil {
		return fail(err)
	}
	if len(cc) < 2 || int(cc[0]) != len(cc)-1 {
		return fail(errors.New("malformed COTP response"))
	}
	// Any well-formed COTP reply, including a disconnect for an unknown
	// TSAP, shows an ISO-on-TCP peer worth one more rack/slot attempt.
	connected = true
	if cc[1]&0xf0 != 0xd0 {
		return fail(fmt.Errorf("COTP connection refused (TPDU %#02x)", cc[1]))
	}
	if _, err := rc.Write(s7SetupRequest); err != nil {
		return fail(err)
	}
	setup, err := readS7(rc)
	if err != nil {
		return fail(err)
	}
	if setup.rosctr != 3 || setup.errorClass != 0 || setup.errorCode != 0 || len(setup.param) < 8 || setup.param[0] != 0xf0 {
		return fail(fmt.Errorf("S7 setup refused (class %d code %d)", setup.errorClass, setup.errorCode))
	}
	attrs := map[string]string{"s7.rack": fmt.Sprint(rack), "s7.slot": fmt.Sprint(slot),
		"s7.pdu_size": fmt.Sprint(binary.BigEndian.Uint16(setup.param[6:]))}
	var partial []string
	for i, szl := range []uint16{0x0011, 0x001c} {
		if ctx.Err() != nil {
			break
		}
		ref := uint16(2 + i)
		if _, err := rc.Write(s7ReadSZL(ref, szl, 0)); err != nil {
			return fail(err)
		}
		pdu, err := readS7(rc)
		if err != nil {
			return fail(err)
		}
		if pdu.rosctr != 7 || pdu.ref != ref {
			return fail(errors.New("unexpected S7 userdata response"))
		}
		records, more, err := parseSZL(pdu, szl)
		if err != nil {
			// A CPU may refuse one list (for example 0x001C on older
			// firmware); the other list still identifies it.
			partial = append(partial, fmt.Sprintf("SZL %#04x: %v", szl, err))
			continue
		}
		if more {
			partial = append(partial, fmt.Sprintf("SZL %#04x: further fragments not requested", szl))
		}
		applySZL(attrs, szl, records)
	}
	e.finish(&ev, rc, nil)
	if attrs["s7.module"] == "" && attrs["s7.module_type"] == "" && attrs["s7.system_name"] == "" {
		ev.Error = strings.Join(partial, "; ")
		return false, true
	}
	if len(partial) > 0 {
		attrs["s7.partial"] = strings.Join(partial, "; ")
		ev.Completeness = "partial"
	}
	o.Service, o.Attributes = ProbeS7, attrs
	o.Product = attrs["s7.module_type"]
	if o.Product == "" {
		o.Product = attrs["s7.module"]
	}
	o.Version = strings.TrimPrefix(attrs["s7.firmware"], "V")
	o.Confidence, o.Probe = 100, ProbeS7
	o.Reason = "validated S7comm Setup Communication and SZL identity response"
	ev.Matched = ProbeS7
	return true, true
}

// parseSZL validates a read-SZL response and returns its fixed-size records.
// more is true when the CPU announced further fragments.
func parseSZL(p s7PDU, want uint16) (records [][]byte, more bool, err error) {
	// Response parameters: head (3), length, method, type/group, subfunction,
	// sequence, data unit reference, last data unit, error code (2).
	if len(p.param) < 12 || p.param[5] != 0x84 || p.param[6] != 1 {
		return nil, false, errors.New("not a read-SZL response")
	}
	if code := binary.BigEndian.Uint16(p.param[10:]); code != 0 {
		return nil, false, fmt.Errorf("CPU error %#04x", code)
	}
	more = p.param[9] != 0
	d := p.data
	if len(d) < 4 || d[0] != 0xff {
		return nil, false, fmt.Errorf("return code %#02x", firstByte(d))
	}
	n := int(binary.BigEndian.Uint16(d[2:]))
	if n > len(d)-4 || n < 8 {
		return nil, false, errors.New("bad SZL data length")
	}
	d = d[4 : 4+n]
	if binary.BigEndian.Uint16(d) != want {
		return nil, false, errors.New("SZL ID mismatch")
	}
	size, count := int(binary.BigEndian.Uint16(d[4:])), int(binary.BigEndian.Uint16(d[6:]))
	d = d[8:]
	if size < 2 || size > 256 {
		return nil, false, errors.New("bad SZL record size")
	}
	for i := 0; i < count && i < s7MaxRecords; i++ {
		if len(d) < size {
			more = true // the record count exceeds the bytes in this fragment
			break
		}
		records = append(records, d[:size])
		d = d[size:]
	}
	return records, more, nil
}

func firstByte(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

// s7Text trims an SZL text field, which is padded with spaces or NULs.
func s7Text(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return printable(b, 64)
}

// applySZL maps known record indices to attributes. Unknown indices are
// ignored; a field the CPU did not send stays absent rather than guessed.
func applySZL(attrs map[string]string, id uint16, records [][]byte) {
	for _, r := range records {
		index := binary.BigEndian.Uint16(r)
		switch id {
		case 0x0011:
			// Index, 20-byte order number (MLFB), module type, version bytes.
			// Some implementations shorten the record; the version needs all
			// 28 bytes and is left unknown otherwise.
			if len(r) < 22 {
				continue
			}
			switch {
			case index == 1:
				attrs["s7.module"] = s7Text(r[2:22])
			case index == 6:
				attrs["s7.hardware"] = s7Text(r[2:22])
			case index == 7 && len(r) >= 28:
				attrs["s7.firmware"] = fmt.Sprintf("V%d.%d.%d", r[25], r[26], r[27])
			}
		case 0x001c:
			if len(r) < 34 {
				continue
			}
			key := map[uint16]string{1: "s7.system_name", 2: "s7.module_name", 3: "s7.plant_id",
				5: "s7.serial", 7: "s7.module_type", 8: "s7.memory_serial", 11: "s7.location"}[index]
			if value := s7Text(r[2:34]); key != "" && value != "" {
				attrs[key] = value
			}
		}
	}
}
