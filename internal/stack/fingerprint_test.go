package stack

import (
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/packet"
)

func reply(options []byte, ttl uint8) packet.Decoded {
	p := packet.Decoded{IPVersion: 4, TTL: ttl, DF: true, IPID: 42, TCPWindow: 64240, TCPFlags: 0x52,
		TCPSeq: 100, TCPAck: 200, Received: time.Unix(1, 0), TCPOptionsLen: uint8(len(options))}
	copy(p.TCPOptions[:], options)
	return p
}

var linuxOptions = []byte{2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 10, 0, 0, 0, 20, 1, 3, 3, 7}

func TestNativeFamiliesAndUnknowns(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options []byte
		ttl     uint8
		family  string
	}{
		{"linux", linuxOptions, 61, "Linux"},
		{"linux-no-timestamp", []byte{2, 4, 5, 180, 1, 1, 4, 2, 1, 3, 3, 7}, 64, "Linux"},
		{"windows", []byte{2, 4, 5, 180, 1, 3, 3, 8, 1, 1, 4, 2}, 120, "Windows"},
		{"bsd", []byte{2, 4, 5, 180, 1, 3, 3, 6, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 4, 2, 0, 0}, 64, "BSD/macOS"},
		{"ttl-alone", nil, 64, ""}, {"incompatible-ttl", linuxOptions, 128, ""},
		{"generic-mss", []byte{2, 4, 5, 180}, 64, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Sample(reply(tc.options, tc.ttl))
			f := &observe.TCPStack{Samples: []observe.StackSample{s}}
			Analyze(f)
			if tc.family == "" {
				if f.Status != observe.FingerprintUnknown || len(f.Candidates) != 0 {
					t.Fatalf("overconfident: %+v", f)
				}
				return
			}
			if f.Status != observe.FingerprintMatched || len(f.Candidates) != 1 || f.Candidates[0].Family != tc.family || f.Candidates[0].Confidence > 70 {
				t.Fatalf("classification: %+v", f)
			}
			if s.InitialTTL == 0 || s.MSS == nil || *s.MSS != 1460 || s.WindowScale == nil || !s.SACK || s.ECN != "negotiated" {
				t.Fatalf("missing fields: %+v", s)
			}
		})
	}
}

func TestInvalidOptionsStayUnknown(t *testing.T) {
	for _, raw := range [][]byte{{2}, {2, 1}, {2, 4, 0}, {2, 3, 0}, {3, 3, 15}, {8, 9, 0, 0, 0, 0, 0, 0, 0}, {4, 3, 0},
		append(append([]byte{}, linuxOptions...), 2, 4, 5, 180)} {
		s := Sample(reply(raw, 64))
		f := &observe.TCPStack{Samples: []observe.StackSample{s}}
		Analyze(f)
		if s.OptionsValid || f.Status != observe.FingerprintUnknown {
			t.Fatalf("invalid %x recognized: %+v", raw, f)
		}
	}
	p := reply(nil, 64)
	p.TCPOptionsLen = 255
	if Sample(p).OptionsValid {
		t.Fatal("accepted excessive option length")
	}
}

func TestOptionOrderIsReadableJSONAndUnexpectedFlagsStayUnknown(t *testing.T) {
	p := reply(linuxOptions, 64)
	body, err := json.Marshal(Sample(p))
	if err != nil || !strings.Contains(string(body), `"option_order":[2,4,8,1,3]`) {
		t.Fatalf("option ordering encoded as binary: %s %v", body, err)
	}
	p.TCPFlags |= 0x80
	f := &observe.TCPStack{Samples: []observe.StackSample{Sample(p)}}
	Analyze(f)
	if f.Status != observe.FingerprintUnknown || f.Samples[0].ECN != "unexpected-cwr" {
		t.Fatalf("unexpected SYN/ACK flags recognized: %+v", f)
	}
}

func TestSignatureNormalizesVolatileCountersAndHopDistance(t *testing.T) {
	p := reply(linuxOptions, 61)
	first := &observe.TCPStack{Samples: []observe.StackSample{Sample(p)}}
	Analyze(first)
	p.TTL = 60
	p.IPID++
	p.TCPSeq++
	p.TCPAck++
	p.Received = p.Received.Add(time.Second)
	binary.BigEndian.PutUint32(p.TCPOptions[8:12], 999)
	binary.BigEndian.PutUint32(p.TCPOptions[12:16], 1000)
	second := &observe.TCPStack{Samples: []observe.StackSample{Sample(p)}}
	Analyze(second)
	if first.Signature != second.Signature {
		t.Fatalf("volatile signature: %s != %s", first.Signature, second.Signature)
	}
	p.TCPWindow--
	second.Samples = []observe.StackSample{Sample(p)}
	Analyze(second)
	if first.Signature == second.Signature {
		t.Fatal("window change lost")
	}
}

func TestBehaviorEvidenceAndMixedResponses(t *testing.T) {
	p := reply(linuxOptions, 64)
	p.IPID = 65535
	a := Sample(p)
	p.IPID = 0
	p.Received = p.Received.Add(time.Second)
	b := Sample(p)
	f := &observe.TCPStack{Samples: []observe.StackSample{b, a}}
	Analyze(f)
	if f.IPIDBehavior != "increasing" || f.RetransmissionBehavior != "duplicate-or-retransmitted-syn-ack" || !reflect.DeepEqual(f.RepeatIntervals, []time.Duration{time.Second}) {
		t.Fatalf("behavior: %+v", f)
	}
	p.TCPFlags = 0x14
	p.TCPWindow = 0
	p.TCPOptionsLen = 0
	p.Received = p.Received.Add(time.Second)
	f.Samples = append(f.Samples, Sample(p))
	Analyze(f)
	if f.Status != observe.FingerprintUnknown || f.RSTBehavior != "acknowledged-reset-zero-window-no-options" {
		t.Fatalf("mixed response inferred an OS: %+v", f)
	}
	p.IPVersion = 6
	s := Sample(p)
	f.Samples = []observe.StackSample{s}
	Analyze(f)
	if s.DF != nil || s.IPID != nil || f.IPIDBehavior != "not-applicable" {
		t.Fatalf("IPv4 fields on IPv6: %+v", f)
	}
	for _, id := range []uint16{0, 42} {
		p.IPVersion = 4
		p.IPID = id
		f.Samples = []observe.StackSample{Sample(p), Sample(p)}
		Analyze(f)
		want := "constant"
		if id == 0 {
			want = "zero"
		}
		if f.IPIDBehavior != want {
			t.Fatalf("IP ID: %+v", f)
		}
	}
}
