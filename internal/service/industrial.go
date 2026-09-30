package service

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// These two requests are identity reads only. They contain no register or
// object writes, and each probe opens one bounded TCP connection.
func (e *Engine) probeModbus(ctx context.Context, t Target, o *observe.Observation) bool {
	ev := observe.Evidence{Probe: ProbeModbus, Layer: "tcp", Started: time.Now().UTC()}
	defer func() { o.Evidence = append(o.Evidence, ev) }()
	timeout := e.timeout(ProbeModbus)
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		return false
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	request := []byte{0, 0, 0, 0, 0, 5, 0xff, 0x2b, 0x0e, 0x01, 0x00}
	if _, err = rand.Read(request[:2]); err == nil {
		_, err = rc.Write(request)
	}
	var header [7]byte
	if err == nil {
		_, err = io.ReadFull(rc, header[:])
	}
	if err != nil {
		e.finish(&ev, rc, err)
		return false
	}
	length := int(binary.BigEndian.Uint16(header[4:6]))
	if length < 2 || length > 254 {
		e.finish(&ev, rc, fmt.Errorf("invalid Modbus response length %d", length))
		return false
	}
	pdu := make([]byte, length-1)
	_, err = io.ReadFull(rc, pdu)
	e.finish(&ev, rc, err)
	if err != nil || header[0] != request[0] || header[1] != request[1] || header[2] != 0 || header[3] != 0 || header[6] != request[6] {
		return false
	}
	if len(pdu) < 7 || pdu[0] != 0x2b || pdu[1] != 0x0e || pdu[2] != 0x01 {
		return false
	}
	count := int(pdu[6])
	pos := 7
	attrs := map[string]string{}
	for i := 0; i < count; i++ {
		if len(pdu)-pos < 2 {
			return false
		}
		id, size := pdu[pos], int(pdu[pos+1])
		pos += 2
		if size > len(pdu)-pos {
			return false
		}
		value := printable(pdu[pos:pos+size], 128)
		pos += size
		switch id {
		case 0:
			attrs["modbus.vendor"] = value
		case 1:
			attrs["modbus.product"] = value
		case 2:
			attrs["modbus.revision"] = value
		}
	}
	if pos != len(pdu) {
		return false
	}
	o.Service, o.Product, o.Version = ProbeModbus, attrs["modbus.product"], attrs["modbus.revision"]
	o.Attributes = attrs
	o.Confidence, o.Reason, o.Probe = 100, "validated Modbus Read Device Identification response", ProbeModbus
	ev.Matched = ProbeModbus
	return true
}

func (e *Engine) probeEtherNetIP(ctx context.Context, t Target, o *observe.Observation) bool {
	ev := observe.Evidence{Probe: ProbeEtherNetIP, Layer: "tcp", Started: time.Now().UTC()}
	defer func() { o.Evidence = append(o.Evidence, ev) }()
	timeout := e.timeout(ProbeEtherNetIP)
	conn, err := e.dial(ctx, t, timeout)
	if err != nil {
		ev.Error, ev.Duration = errorText(err), time.Since(ev.Started)
		return false
	}
	defer conn.Close()
	rc := e.record(conn)
	stop := deadline(ctx, rc, timeout)
	defer stop()
	request := make([]byte, 24)
	binary.LittleEndian.PutUint16(request[:2], 0x63) // ListIdentity
	if _, err = rand.Read(request[12:20]); err == nil {
		_, err = rc.Write(request)
	}
	var header [24]byte
	if err == nil {
		_, err = io.ReadFull(rc, header[:])
	}
	if err != nil {
		e.finish(&ev, rc, err)
		return false
	}
	length := int(binary.LittleEndian.Uint16(header[2:4]))
	if length < 4 || length > 4096 {
		e.finish(&ev, rc, fmt.Errorf("invalid EtherNet/IP response length %d", length))
		return false
	}
	body := make([]byte, length)
	_, err = io.ReadFull(rc, body)
	e.finish(&ev, rc, err)
	if err != nil || binary.LittleEndian.Uint16(header[:2]) != 0x63 || binary.LittleEndian.Uint32(header[8:12]) != 0 ||
		string(header[12:20]) != string(request[12:20]) {
		return false
	}
	count := int(binary.LittleEndian.Uint16(body[:2]))
	pos := 2
	for i := 0; i < count; i++ {
		if len(body)-pos < 4 {
			return false
		}
		itemType := binary.LittleEndian.Uint16(body[pos : pos+2])
		itemLength := int(binary.LittleEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if itemLength > len(body)-pos {
			return false
		}
		item := body[pos : pos+itemLength]
		pos += itemLength
		if itemType != 0x0c || len(item) < 34 || int(item[32]) > len(item)-33 {
			continue
		}
		vendor := binary.LittleEndian.Uint16(item[18:20])
		deviceType := binary.LittleEndian.Uint16(item[20:22])
		productCode := binary.LittleEndian.Uint16(item[22:24])
		name := printable(item[33:33+int(item[32])], 128)
		o.Service, o.Product = ProbeEtherNetIP, name
		o.Version = fmt.Sprintf("%d.%d", item[24], item[25])
		o.Attributes = map[string]string{
			"ethernetip.vendor_id":    strconv.Itoa(int(vendor)),
			"ethernetip.device_type":  strconv.Itoa(int(deviceType)),
			"ethernetip.product_code": strconv.Itoa(int(productCode)),
			"ethernetip.serial":       fmt.Sprintf("%08x", binary.LittleEndian.Uint32(item[28:32])),
		}
		o.Confidence, o.Reason, o.Probe = 100, "validated EtherNet/IP ListIdentity response", ProbeEtherNetIP
		ev.Matched = ProbeEtherNetIP
		return true
	}
	return false
}
