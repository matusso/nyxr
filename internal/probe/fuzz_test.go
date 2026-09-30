package probe

import (
	"bytes"
	"io/fs"
	"testing"
)

func FuzzDefinitionAndMatcher(f *testing.F) {
	f.Add([]byte("name: test\ntransport: udp\nsafety: safe\npayload:\n  encoding: ascii\n  data: hello\nmatch:\n  - type: any\n"), []byte("hello"))
	f.Add([]byte("name: dns\ntransport: udp\nsafety: safe\npayload:\n  encoding: hex\n  data: 000001000001000000000000\nmatch:\n  - type: dns\n"), []byte{0, 0, 0x81, 0})
	files, err := fs.Glob(native, "native/*.yaml")
	if err != nil {
		f.Fatal(err)
	}
	for _, name := range files {
		data, err := native.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data, []byte{0x30, 0x00})
	}
	f.Fuzz(func(t *testing.T, definition, response []byte) {
		p, err := Parse(bytes.NewReader(definition), "")
		if err != nil {
			return
		}
		request := Prepare(p, 12345)
		_ = Match(p, request, response)
	})
}
