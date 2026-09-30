package service

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

func identityEngine(t *testing.T, probe string, responder func(net.Conn)) *Engine {
	t.Helper()
	e, err := Start(context.Background(), Config{Probes: []string{probe}, Timeout: time.Second, Workers: 1,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go func() { defer server.Close(); responder(server) }()
			return client, nil
		}}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

func TestModbusIdentityRead(t *testing.T) {
	e := identityEngine(t, ProbeModbus, func(c net.Conn) {
		request := make([]byte, 11)
		if _, err := io.ReadFull(c, request); err != nil {
			t.Error(err)
			return
		}
		if binary.BigEndian.Uint16(request[4:6]) != 5 || request[7] != 0x2b || request[8] != 0x0e || request[9] != 1 || request[10] != 0 {
			t.Errorf("unsafe request %x", request)
			return
		}
		pdu := []byte{0x2b, 0x0e, 1, 1, 0, 0, 3,
			0, 4, 'A', 'C', 'M', 'E', 1, 3, 'P', 'L', 'C', 2, 3, '1', '.', '2'}
		response := append([]byte(nil), request[:7]...)
		binary.BigEndian.PutUint16(response[4:6], uint16(len(pdu)+1))
		_, _ = c.Write(append(response, pdu...))
	})
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 502})
	if o.Service != ProbeModbus || o.Product != "PLC" || o.Version != "1.2" || o.Attributes["modbus.vendor"] != "ACME" || o.Fingerprint != observe.FingerprintMatched {
		t.Fatalf("identity: %+v", o)
	}
	if len(o.Evidence) != 1 || o.Evidence[0].Matched != ProbeModbus || len(o.Evidence[0].Request) != 11 || len(o.Evidence[0].Response) == 0 {
		t.Fatalf("audit evidence: %+v", o.Evidence)
	}
}

func TestEtherNetIPIdentityRead(t *testing.T) {
	e := identityEngine(t, ProbeEtherNetIP, func(c net.Conn) {
		request := make([]byte, 24)
		if _, err := io.ReadFull(c, request); err != nil {
			t.Error(err)
			return
		}
		if binary.LittleEndian.Uint16(request[:2]) != 0x63 || binary.LittleEndian.Uint16(request[2:4]) != 0 {
			t.Errorf("unsafe request %x", request)
			return
		}
		item := make([]byte, 37)
		binary.LittleEndian.PutUint16(item[:2], 1)
		binary.LittleEndian.PutUint16(item[18:20], 77)
		binary.LittleEndian.PutUint16(item[20:22], 14)
		binary.LittleEndian.PutUint16(item[22:24], 9)
		item[24], item[25] = 2, 5
		item[32] = 3
		copy(item[33:], "PLC")
		body := make([]byte, 6)
		binary.LittleEndian.PutUint16(body[:2], 1)
		binary.LittleEndian.PutUint16(body[2:4], 0x0c)
		binary.LittleEndian.PutUint16(body[4:6], uint16(len(item)))
		body = append(body, item...)
		response := append([]byte(nil), request...)
		binary.LittleEndian.PutUint16(response[2:4], uint16(len(body)))
		_, _ = c.Write(append(response, body...))
	})
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 44818})
	if o.Service != ProbeEtherNetIP || o.Product != "PLC" || o.Version != "2.5" || o.Attributes["ethernetip.vendor_id"] != "77" || o.Fingerprint != observe.FingerprintMatched {
		t.Fatalf("identity: %+v", o)
	}
	if len(o.Evidence) != 1 || o.Evidence[0].Matched != ProbeEtherNetIP {
		t.Fatalf("audit evidence: %+v", o.Evidence)
	}
}
