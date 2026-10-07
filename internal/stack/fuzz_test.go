package stack

import (
	"testing"

	"github.com/matusso/nyxr/internal/observe"
)

func FuzzTCPStackOptions(f *testing.F) {
	f.Add(linuxOptions, uint8(64), uint8(0x52))
	f.Add([]byte{2, 1}, uint8(128), uint8(0x14))
	f.Add([]byte{0}, uint8(0), uint8(0x12))
	f.Fuzz(func(t *testing.T, raw []byte, ttl, flags uint8) {
		if len(raw) > 40 {
			raw = raw[:40]
		}
		p := reply(raw, ttl)
		p.TCPFlags = flags
		s := Sample(p)
		result := &observe.TCPStack{Samples: []observe.StackSample{s}}
		Analyze(result)
		if !s.OptionsValid && len(result.Candidates) > 0 {
			t.Fatal("invalid options identified an OS")
		}
		if flags&0x12 != 0x12 && len(result.Candidates) > 0 {
			t.Fatal("non-SYN/ACK identified an OS")
		}
		if len(s.OptionOrder) > 40 {
			t.Fatal("option ordering escaped header bounds")
		}
	})
}
