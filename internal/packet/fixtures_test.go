package packet

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
)

func fixture(t testing.TB) []byte {
	t.Helper()
	data, err := os.ReadFile("../../tests/pcaps/phase0.pcap")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPhase0PCAPFixtures(t *testing.T) {
	reader, err := NewPCAPReader(bytes.NewReader(fixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		protocol, source string
		sourcePort       uint16
		valid, quote     bool
	}{
		{"tcp", "192.0.2.1", 443, true, false},
		{"udp", "192.0.2.1", 53, true, false},
		{"tcp", "2001:db8::1", 443, true, false},
		{"udp", "2001:db8::1", 53, true, false},
		{"icmp", "192.0.2.1", 0, true, false},
		{"icmp6", "2001:db8::1", 0, true, false},
		{"tcp", "192.0.2.1", 443, true, false},
		{"icmp", "192.0.2.2", 0, true, true},
		{"", "", 0, false, false},
		{"", "", 0, false, false},
	}
	decoder := NewDecoder()
	for i, tc := range cases {
		frame, err := reader.Next()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		got, ok := decoder.Decode(frame)
		if ok != tc.valid {
			t.Fatalf("frame %d: valid=%v, decoded=%+v", i, ok, got)
		}
		if !ok {
			continue
		}
		if got.Protocol != tc.protocol || got.Source.String() != tc.source || got.SourcePort != tc.sourcePort || got.Quote.Valid != tc.quote {
			t.Fatalf("frame %d: %+v", i, got)
		}
		if tc.quote && (got.Quote.Sequence != 7 || got.Quote.DestPort != 50000) {
			t.Fatalf("frame %d: quote %+v", i, got.Quote)
		}
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("trailing frame: %v", err)
	}
}

func FuzzDecoder(f *testing.F) {
	r, err := NewPCAPReader(bytes.NewReader(fixture(f)))
	if err != nil {
		f.Fatal(err)
	}
	for {
		frame, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			f.Fatal(err)
		}
		f.Add(frame)
	}
	f.Fuzz(func(t *testing.T, frame []byte) { _, _ = NewDecoder().Decode(frame); _ = parseQuotedTCP(frame) })
}

func FuzzPCAPReader(f *testing.F) {
	f.Add(fixture(f))
	f.Add([]byte{0xa1, 0xb2, 0xc3, 0xd4})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := NewPCAPReader(bytes.NewReader(data))
		if err != nil {
			return
		}
		for i := 0; i < 32; i++ {
			if _, err := r.Next(); err != nil {
				return
			}
		}
	})
}

func BenchmarkDecodeFixture(b *testing.B) {
	r, err := NewPCAPReader(bytes.NewReader(fixture(b)))
	if err != nil {
		b.Fatal(err)
	}
	var frames [][]byte
	for {
		frame, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			b.Fatal(err)
		}
		frames = append(frames, frame)
	}
	d := NewDecoder()
	b.ReportAllocs()
	var bytesTotal int
	for _, frame := range frames {
		bytesTotal += len(frame)
	}
	b.SetBytes(int64(bytesTotal / len(frames)))
	for i := 0; i < b.N; i++ {
		_, _ = d.Decode(frames[i%len(frames)])
	}
}
