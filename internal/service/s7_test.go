package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// s7Sim is an S7-1500-like CPU simulator. It accepts only the messages the
// probe is allowed to send and records every byte it received.
type s7Sim struct {
	slot        byte // accepted slot
	refuse001C  bool // return "object does not exist" for SZL 0x001C
	noFirmware  bool // omit the firmware record of SZL 0x0011
	truncateSZL bool // close in the middle of the first SZL response
	moreData    bool // announce a further fragment for SZL 0x0011
	mu          sync.Mutex
	received    [][]byte // per connection
	violation   string
}

func tpkt(payload []byte) []byte {
	return append([]byte{3, 0, byte((len(payload) + 4) >> 8), byte(len(payload) + 4)}, payload...)
}

func (s *s7Sim) szlResponse(ref, id uint16) []byte {
	var records [][]byte
	size := 28
	switch id {
	case 0x0011:
		mk := func(index uint16, mlfb string, version [3]byte) []byte {
			r := make([]byte, 28)
			binary.BigEndian.PutUint16(r, index)
			copy(r[2:22], mlfb+"                    ")
			r[25], r[26], r[27] = version[0], version[1], version[2]
			return r
		}
		records = append(records, mk(1, "6ES7 516-3AN01-0AB0", [3]byte{}), mk(6, "6ES7 516-3AN01-0AB0", [3]byte{0, 0, 1}))
		if !s.noFirmware {
			records = append(records, mk(7, "", [3]byte{2, 9, 4}))
		}
	case 0x001c:
		size = 34
		for _, f := range []struct {
			index uint16
			text  string
		}{{1, "S71500/ET200MP station_1"}, {2, "PLC_1"}, {5, "S C-X4U421302016"}, {7, "CPU 1516-3 PN/DP"}} {
			text := make([]byte, 32)
			copy(text, f.text)
			records = append(records, append(binary.BigEndian.AppendUint16(nil, f.index), text...))
		}
	}
	data := []byte{0xff, 9, 0, 0}
	data = binary.BigEndian.AppendUint16(data, id)
	data = append(data, 0, 0)
	data = binary.BigEndian.AppendUint16(data, uint16(size))
	data = binary.BigEndian.AppendUint16(data, uint16(len(records)))
	for _, r := range records {
		data = append(data, r...)
	}
	binary.BigEndian.PutUint16(data[2:], uint16(len(data)-4))
	last := byte(0)
	if id == 0x0011 && s.moreData {
		last = 1
	}
	if id == 0x001c && s.refuse001C {
		data = []byte{0x0a, 0, 0, 0} // object does not exist
	}
	param := []byte{0, 1, 0x12, 8, 0x12, 0x84, 1, 1, 0, last, 0, 0}
	header := []byte{0x32, 7, 0, 0, byte(ref >> 8), byte(ref), 0, byte(len(param)), byte(len(data) >> 8), byte(len(data))}
	return tpkt(append(append(append([]byte{2, 0xf0, 0x80}, header...), param...), data...))
}

func (s *s7Sim) fail(reason string) {
	s.mu.Lock()
	s.violation = reason
	s.mu.Unlock()
}

// teeConn lets readTPKT read through a recording tee.
type teeConn struct {
	net.Conn
	r io.Reader
}

func (t teeConn) Read(p []byte) (int, error) { return t.r.Read(p) }

func (s *s7Sim) serve(c net.Conn) {
	var got bytes.Buffer
	var record sync.Once
	recordNow := func() {
		record.Do(func() {
			s.mu.Lock()
			s.received = append(s.received, got.Bytes())
			s.mu.Unlock()
		})
	}
	defer recordNow()
	in := teeConn{c, io.TeeReader(c, &got)}
	read := func() []byte {
		b, err := readTPKT(in)
		if err != nil {
			return nil
		}
		return b
	}
	cr := read()
	if cr == nil {
		return
	}
	if len(cr) != 18 || cr[1] != 0xe0 {
		s.fail("unexpected COTP request")
		return
	}
	if cr[14] != s.slot {
		// Record before refusing: the probe dials the next slot as soon as
		// it sees the disconnect, and connections must be logged in order.
		recordNow()
		_, _ = c.Write(tpkt([]byte{6, 0x80, 0, 1, 0, 0, 0})) // disconnect request
		return
	}
	_, _ = c.Write(tpkt([]byte{17, 0xd0, 0, 1, 0, 1, 0, 0xc1, 2, 1, 0, 0xc2, 2, 1, cr[14], 0xc0, 1, 10}))
	setup := read()
	if len(setup) != 21 || setup[4] != 1 || setup[13] != 0xf0 {
		s.fail("expected Setup Communication")
		return
	}
	_, _ = c.Write(tpkt([]byte{2, 0xf0, 0x80, 0x32, 3, 0, 0, 0, 1, 0, 8, 0, 0, 0, 0, 0xf0, 0, 0, 1, 0, 1, 0, 240}))
	for {
		req := read()
		if req == nil {
			return
		}
		// Only userdata, CPU functions, read SZL (group 4, subfunction 1).
		if len(req) != 29 || req[4] != 7 || req[17] != 0x11 || req[18] != 0x44 || req[19] != 1 {
			s.fail("non-SZL request")
			return
		}
		resp := s.szlResponse(binary.BigEndian.Uint16(req[7:]), binary.BigEndian.Uint16(req[25:]))
		if s.truncateSZL {
			_, _ = c.Write(resp[:len(resp)/2])
			return
		}
		_, _ = c.Write(resp)
	}
}

// checkAudit verifies that each connection's evidence holds exactly the
// bytes the device received.
func checkAudit(t *testing.T, o observe.Observation, mu *sync.Mutex, received *[][]byte) {
	t.Helper()
	// The device side records a connection when it closes, which can be
	// just after the probe returns.
	for deadline := time.Now().Add(time.Second); ; time.Sleep(5 * time.Millisecond) {
		mu.Lock()
		if len(*received) >= len(o.Evidence) || time.Now().After(deadline) {
			break
		}
		mu.Unlock()
	}
	defer mu.Unlock()
	if len(o.Evidence) != len(*received) {
		t.Fatalf("%d evidence entries for %d connections", len(o.Evidence), len(*received))
	}
	for i, ev := range o.Evidence {
		if !bytes.Equal(ev.Request, (*received)[i]) || ev.Truncated {
			t.Fatalf("connection %d: evidence request %x does not match transmitted %x", i, ev.Request, (*received)[i])
		}
	}
}

var s7Target = Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 102}

func TestS7IdentityRead(t *testing.T) {
	sim := &s7Sim{slot: 2}
	o := identityEngine(t, ProbeS7, sim.serve).Interrogate(context.Background(), s7Target)
	if sim.violation != "" {
		t.Fatal(sim.violation)
	}
	if o.Service != ProbeS7 || o.Product != "CPU 1516-3 PN/DP" || o.Version != "2.9.4" || o.Fingerprint != observe.FingerprintMatched || o.Confidence != 100 {
		t.Fatalf("identity: %+v", o)
	}
	want := map[string]string{"s7.module": "6ES7 516-3AN01-0AB0", "s7.hardware": "6ES7 516-3AN01-0AB0", "s7.firmware": "V2.9.4",
		"s7.system_name": "S71500/ET200MP station_1", "s7.module_name": "PLC_1", "s7.serial": "S C-X4U421302016",
		"s7.rack": "0", "s7.slot": "2", "s7.pdu_size": "240"}
	for k, v := range want {
		if o.Attributes[k] != v {
			t.Errorf("%s = %q, want %q", k, o.Attributes[k], v)
		}
	}
	if _, ok := o.Attributes["s7.plant_id"]; ok {
		t.Error("a field the CPU did not send must stay absent")
	}
	checkAudit(t, o, &sim.mu, &sim.received)
	wantRequest := append(append(append(s7ConnectRequest(0, 2), s7SetupRequest...), s7ReadSZL(2, 0x11, 0)...), s7ReadSZL(3, 0x1c, 0)...)
	if !bytes.Equal(o.Evidence[0].Request, wantRequest) || o.Evidence[0].Matched != ProbeS7 {
		t.Fatalf("transmitted bytes are not exactly the documented read-only exchange: %x", o.Evidence[0].Request)
	}
}

func TestS7TriesSecondSlotAfterCOTPRefusal(t *testing.T) {
	sim := &s7Sim{slot: 1}
	o := identityEngine(t, ProbeS7, sim.serve).Interrogate(context.Background(), s7Target)
	if o.Service != ProbeS7 || o.Attributes["s7.slot"] != "1" || len(o.Evidence) != 2 || o.Evidence[0].Matched != "" || o.Evidence[0].Error == "" {
		t.Fatalf("second TSAP: %+v", o)
	}
	checkAudit(t, o, &sim.mu, &sim.received)
}

func TestS7PartialAndUnknownFields(t *testing.T) {
	sim := &s7Sim{slot: 2, refuse001C: true, noFirmware: true, moreData: true}
	o := identityEngine(t, ProbeS7, sim.serve).Interrogate(context.Background(), s7Target)
	if o.Service != ProbeS7 || o.Product != "6ES7 516-3AN01-0AB0" || o.Version != "" || o.Attributes["s7.firmware"] != "" ||
		o.Attributes["s7.system_name"] != "" || o.Attributes["s7.partial"] == "" || o.Evidence[0].Completeness != "partial" {
		t.Fatalf("partial identity must keep unknown fields unknown: %+v", o)
	}
}

func TestS7NegativeTruncatedAndCanceled(t *testing.T) {
	sim := &s7Sim{slot: 2, truncateSZL: true}
	if o := identityEngine(t, ProbeS7, sim.serve).Interrogate(context.Background(), s7Target); o.Service != "" || o.Evidence[0].Error == "" {
		t.Fatalf("truncated SZL response must not identify: %+v", o)
	}
	var mu sync.Mutex
	var connections int
	e := identityEngine(t, ProbeS7, func(c net.Conn) {
		mu.Lock()
		connections++
		mu.Unlock()
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	})
	o := e.Interrogate(context.Background(), s7Target)
	mu.Lock()
	if o.Service != "" || len(o.Evidence) != 1 || connections != 1 {
		t.Fatalf("a non-ISO-on-TCP peer gets exactly one connection request: %d %+v", connections, o)
	}
	mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sim = &s7Sim{slot: 2}
	var obs observe.Observation
	if identityEngine(t, ProbeS7, sim.serve).probeS7(ctx, s7Target, &obs) || len(obs.Evidence) != 0 || len(sim.received) != 0 {
		t.Fatalf("canceled probe transmitted: %+v", obs)
	}
}

func FuzzParseSZL(f *testing.F) {
	resp := (&s7Sim{}).szlResponse(2, 0x0011)[4+3+10:]
	f.Add(resp[:12], resp[12:], uint16(0x0011))
	f.Fuzz(func(t *testing.T, param, data []byte, id uint16) {
		records, _, err := parseSZL(s7PDU{rosctr: 7, param: param, data: data}, id)
		if err == nil {
			if len(records) > s7MaxRecords {
				t.Fatalf("unbounded records: %d", len(records))
			}
			applySZL(map[string]string{}, id, records)
		}
	})
}

// Captured from the python-snap7 3.3.0 server: SZL 0x0011 with a shortened
// 26-byte record, and SZL 0x001C with a zero record size and count.
func TestS7SnapServerResponses(t *testing.T) {
	param, _ := hex.DecodeString("000112081284010000000000")
	data11, _ := hex.DecodeString("ff09002200110000001a0001000136455337203331352d32454831342d304142300000030300030000")
	records, more, err := parseSZL(s7PDU{rosctr: 7, param: param, data: data11}, 0x0011)
	if err != nil || more || len(records) != 1 {
		t.Fatalf("SZL 0x0011: %v %v %v", records, more, err)
	}
	attrs := map[string]string{}
	applySZL(attrs, 0x0011, records)
	if attrs["s7.module"] != "6ES7 315-2EH14-0AB0" || attrs["s7.firmware"] != "" {
		t.Fatalf("short record: %v", attrs)
	}
	data1c, _ := hex.DecodeString("ff09000e001c00000000000053534e41503700")
	data1c[3] = byte(len(data1c) - 4)
	if _, _, err := parseSZL(s7PDU{rosctr: 7, param: param, data: data1c}, 0x001c); err == nil {
		t.Fatal("a list without a record size must be refused, not guessed")
	}
}
