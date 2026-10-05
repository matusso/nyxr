package service

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

const framedDSL = `schema: nyxr/protocol/v1
protocol: framed_test
transport: tcp
ports: [5432]
timeout: 1s
steps:
  - send: {hex: "00000008"}
  - receive:
      max_bytes: 64
      length: {offset: 0, bytes: 4, order: big}
  - expect: {prefix: HELLO, offset: 4}
    on_match: identity
  - send: {text: BAD}
  - label: identity
    extract: {test.version: 'HELLO([0-9]+)'}
`

func TestProtocolDSLStatefulFramingBranchAndEvidence(t *testing.T) {
	d, err := ParseProtocol(strings.NewReader(framedDSL))
	if err != nil {
		t.Fatal(err)
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			var request [4]byte
			if _, err := io.ReadFull(server, request[:]); err != nil {
				return
			}
			if string(request[:]) != "\x00\x00\x00\x08" {
				t.Errorf("request %x", request)
				return
			}
			response := make([]byte, 11)
			binary.BigEndian.PutUint32(response, 7)
			copy(response[4:], "HELLO42")
			_, _ = server.Write(response)
		}()
		return client, nil
	}
	e, err := Start(context.Background(), Config{Definitions: []ProtocolDefinition{d}, Timeout: time.Second, Workers: 1, Dial: dial}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 5432})
	if o.Service != "framed_test" || o.Fingerprint != observe.FingerprintMatched || o.Attributes["test.version"] != "42" {
		t.Fatalf("identity or extraction missing: %+v", o)
	}
	if len(o.Evidence) != 1 || string(o.Evidence[0].Request) != "\x00\x00\x00\x08" || string(o.Evidence[0].Response) != "\x00\x00\x00\x07HELLO42" {
		t.Fatalf("exchange not retained: %+v", o.Evidence)
	}
	if len(o.ProbeDecisions) != 1 || o.ProbeDecisions[0].InformationGain <= 0 || o.ServiceHypotheses[0].Family != "dsl/framed_test" {
		t.Fatalf("planner did not incorporate definition: %+v", o)
	}
}

func TestProtocolDSLRejectsUnsafeOrAmbiguousDefinitions(t *testing.T) {
	for _, src := range []string{
		strings.Replace(framedDSL, "schema: nyxr/protocol/v1", "schema: nyxr/protocol/v2", 1),
		strings.Replace(framedDSL, "ports: [5432]", "ports: [0]", 1),
		strings.Replace(framedDSL, "max_bytes: 64", "max_bytes: 65536", 1),
		strings.Replace(framedDSL, "on_match: identity", "on_match: missing", 1),
		strings.Replace(framedDSL, "on_match: identity", "on_match: identity\n    unknown_field: true", 1),
		strings.Replace(framedDSL, "transport: tcp", "transport: udp", 1) + "\n---\nprotocol: extra\n",
		"schema: nyxr/protocol/v1\nprotocol: bad\ntransport: udp\nports: [53]\nsteps:\n  - start_tls: true\n  - expect: {prefix: OK}\n",
		"schema: nyxr/protocol/v1\nprotocol: bad\ntransport: tcp\nports: [80]\nsteps:\n  - receive: {max_bytes: 16}\n  - expect: {regex: '.*'}\n",
	} {
		if _, err := ParseProtocol(strings.NewReader(src)); err == nil {
			t.Errorf("accepted invalid definition: %s", src)
		}
	}
}

func TestProtocolDSLUDPPlannerAndMismatch(t *testing.T) {
	d, err := ParseProtocol(strings.NewReader(`schema: nyxr/protocol/v1
protocol: udp_test
transport: udp
ports: [53]
steps:
  - send: {text: PING}
  - receive: {max_bytes: 4}
  - expect: {prefix: PONG}
`))
	if err != nil {
		t.Fatal(err)
	}
	e, err := Start(context.Background(), Config{Definitions: []ProtocolDefinition{d}, Timeout: time.Second, Workers: 1,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "udp" {
				t.Errorf("network %s", network)
			}
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				var b [4]byte
				_, _ = io.ReadFull(server, b[:])
				_, _ = server.Write([]byte("PONG"))
			}()
			return client, nil
		}}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 53, Transport: "udp"})
	if o.Transport != "udp" || o.Service != "udp_test" || o.Fingerprint != observe.FingerprintMatched || len(o.ProbeDecisions) != 1 {
		t.Fatalf("UDP definition did not run: %+v", o)
	}
}

func TestProtocolDSLBoundedRepeatAndSet(t *testing.T) {
	d, err := ParseProtocol(strings.NewReader(`schema: nyxr/protocol/v1
protocol: repeated
transport: tcp
ports: [9001]
steps:
  - label: request
    send: {text: P}
  - receive: {max_bytes: 1}
  - expect: {prefix: R}
  - repeat: {from: request, count: 2}
  - set: {repeated.rounds: "2"}
`))
	if err != nil {
		t.Fatal(err)
	}
	e, err := Start(context.Background(), Config{Definitions: []ProtocolDefinition{d}, Timeout: time.Second, Workers: 1,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				for i := 0; i < 2; i++ {
					var b [1]byte
					_, _ = io.ReadFull(server, b[:])
					if b[0] != 'P' {
						t.Errorf("request %x", b)
					}
					_, _ = server.Write([]byte("R"))
				}
			}()
			return client, nil
		}}, func(observe.Observation) {})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	o := e.Interrogate(context.Background(), Target{Addr: netip.MustParseAddr("127.0.0.1"), Port: 9001})
	if o.Service != "repeated" || o.Attributes["repeated.rounds"] != "2" || string(o.Evidence[0].Request) != "PP" || string(o.Evidence[0].Response) != "RR" {
		t.Fatalf("repeat did not preserve state: %+v", o)
	}
}

func FuzzParseProtocol(f *testing.F) {
	f.Add([]byte(framedDSL))
	f.Add([]byte("schema: nyxr/protocol/v1\nprotocol: x\ntransport: udp\nports: [53]\nsteps:\n  - expect: {hex: '00'}\n"))
	f.Add([]byte("\xff\x00---\nsteps: [!, [], {}]"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		d, err := ParseProtocol(strings.NewReader(string(input)))
		if err == nil && (len(d.steps) == 0 || len(d.steps) > 32 || len(d.Ports) == 0 || len(d.Ports) > 32) {
			t.Fatalf("unbounded compiled protocol: %+v", d)
		}
	})
}
