package service

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixtureReadConn struct{ Reader *bytes.Reader }

func (c *fixtureReadConn) Read(p []byte) (int, error)       { return c.Reader.Read(p) }
func (c *fixtureReadConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *fixtureReadConn) Close() error                     { return nil }
func (c *fixtureReadConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *fixtureReadConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *fixtureReadConn) SetDeadline(time.Time) error      { return nil }
func (c *fixtureReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fixtureReadConn) SetWriteDeadline(time.Time) error { return nil }

func writeProtocolTestFile(t *testing.T, dir, name, text string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestV2RegistryInheritanceModulesAndCycles(t *testing.T) {
	dir := t.TempDir()
	module := writeProtocolTestFile(t, dir, "module.yaml", "schema: nyxr/protocol/v2\nmodule: hello\nsteps:\n  - send: {text: PING}\n  - receive: {max_bytes: 4}\n")
	base := writeProtocolTestFile(t, dir, "base.yaml", "schema: nyxr/protocol/v2\nprotocol: base\ntransport: tcp\nports: [9001]\nmodules: [hello]\nsteps:\n  - expect: {prefix: PONG}\n")
	child := writeProtocolTestFile(t, dir, "child.yaml", "schema: nyxr/protocol/v2\nprotocol: child\nextends: base\nsteps:\n  - set: {child.version: '1'}\n")
	definitions, err := LoadProtocolRegistry([]string{child, module, base})
	if err != nil || len(definitions) != 2 || definitions[0].Name != "child" || len(definitions[0].steps) != 4 || definitions[0].Transport != "tcp" || len(definitions[0].SourceSHA256) != 64 {
		t.Fatalf("v2 inheritance: %+v, %v", definitions, err)
	}
	cycle := writeProtocolTestFile(t, dir, "cycle.yaml", "schema: nyxr/protocol/v2\nprotocol: cycle\ntransport: tcp\nports: [9001]\nextends: cycle\nsteps:\n  - expect: {prefix: X}\n")
	if _, err := LoadProtocolRegistry([]string{cycle}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("accepted dependency cycle: %v", err)
	}
	tooMany := strings.Repeat("  - send: {text: X}\n", 33)
	writeProtocolTestFile(t, dir, "huge.yaml", "schema: nyxr/protocol/v2\nmodule: huge\nsteps:\n"+tooMany)
	if _, err := LoadProtocolRegistry([]string{filepath.Join(dir, "huge.yaml"), base}); err == nil {
		t.Fatal("accepted oversized module")
	}
}

func TestV2LengthArithmeticAndV1Compatibility(t *testing.T) {
	for _, action := range []string{"dtls", "quic"} {
		src := fmt.Sprintf("schema: nyxr/protocol/v2\nprotocol: custom_app\ntransport: udp\nports: [443]\nsteps:\n  - %s: true\n", action)
		if _, err := ParseProtocol(strings.NewReader(src)); err == nil {
			t.Fatalf("%s handshake claimed arbitrary application identity", action)
		}
	}
	for _, add := range []int{-4097, -4096, -2, 0, 4096, 4097} {
		src := fmt.Sprintf("schema: nyxr/protocol/v2\nprotocol: frame\ntransport: tcp\nports: [9001]\nsteps:\n  - receive: {max_bytes: 64, length: {offset: 0, bytes: 2, order: big, add: %d}}\n  - expect: {prefix: OK}\n", add)
		_, err := ParseProtocol(strings.NewReader(src))
		if (err == nil) != (add >= -4096 && add <= 4096) {
			t.Fatalf("add %d: %v", add, err)
		}
		if _, err := ParseProtocol(strings.NewReader(strings.Replace(src, "protocol/v2", "protocol/v1", 1))); err == nil {
			t.Fatalf("v1 accepted arithmetic add %d", add)
		}
	}
	length := -2
	for _, tc := range []struct {
		data string
		want int
		bad  bool
	}{
		{"\x00\x06OKv1", 6, false},
		{"\x00\x01", 0, true},
		{"\xff\xff", 0, true},
		{"\x00\x06OK", 4, true},
	} {
		conn := &fixtureReadConn{Reader: bytes.NewReader([]byte(tc.data))}
		got, err := receiveProtocol(conn, &receiveSpec{MaxBytes: 64, Length: &lengthSpec{Offset: 0, Bytes: 2, Order: "big", Add: &length}})
		if (err != nil) != tc.bad || !tc.bad && len(got) != tc.want {
			t.Fatalf("frame %x: got %x, err %v", tc.data, got, err)
		}
	}
}

func TestRegistryReloadKeepsPriorSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := writeProtocolTestFile(t, dir, "definition.yaml", "schema: nyxr/protocol/v1\nprotocol: first\ntransport: tcp\nports: [9001]\nsteps:\n  - expect: {prefix: OK}\n")
	r, err := NewRegistry([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	prior := r.Snapshot()
	prior.Definitions[0].Ports[0] = 1
	if r.Snapshot().Definitions[0].Ports[0] != 9001 {
		t.Fatal("snapshot leaked mutable port list")
	}
	writeProtocolTestFile(t, dir, "definition.yaml", "schema: nyxr/protocol/v2\nprotocol: broken\nextends: missing\nsteps:\n  - expect: {prefix: OK}\n")
	if _, err := r.Reload(); err == nil || r.Snapshot().Version != 1 || r.Snapshot().Definitions[0].Name != "first" {
		t.Fatalf("failed reload published changes: %v", err)
	}
	writeProtocolTestFile(t, dir, "definition.yaml", "schema: nyxr/protocol/v1\nprotocol: second\ntransport: tcp\nports: [9002]\nsteps:\n  - expect: {prefix: OK}\n")
	current, err := r.Reload()
	if err != nil || current.Version != 2 || current.Definitions[0].Name != "second" || prior.Definitions[0].Name != "first" {
		t.Fatalf("reload did not preserve immutable versions: %+v, %v", current, err)
	}
}

func TestRegistryConcurrentSnapshotsDuringReload(t *testing.T) {
	dir := t.TempDir()
	path := writeProtocolTestFile(t, dir, "definition.yaml", "schema: nyxr/protocol/v1\nprotocol: stable\ntransport: tcp\nports: [9001]\nsteps:\n  - expect: {prefix: OK}\n")
	r, err := NewRegistry([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				snapshot := r.Snapshot()
				if snapshot.Version == 0 || len(snapshot.Definitions) != 1 || snapshot.Definitions[0].Name != "stable" {
					t.Errorf("partial registry snapshot: %+v", snapshot)
					return
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		if _, err := r.Reload(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestProtocolFixtureCorpus(t *testing.T) {
	base := filepath.Join("..", "..", "tests", "protocol")
	definitions, err := LoadProtocolRegistry([]string{filepath.Join(base, "demo-module.yaml"), filepath.Join(base, "demo.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	results, err := RunProtocolFixtures(definitions, filepath.Join(base, "demo-fixtures.yaml"))
	if err != nil || len(results) != 4 {
		t.Fatalf("fixture corpus: %+v, %v", results, err)
	}
	for _, result := range results {
		if !result.Passed {
			t.Fatalf("fixture %s: %s", result.Name, result.Detail)
		}
	}
}

func FuzzV2FramedLength(f *testing.F) {
	f.Add([]byte("\x00\x06OKv1"), int16(-2))
	f.Add([]byte("\xff\xff"), int16(4096))
	f.Add([]byte("\x00\x01"), int16(-2))
	f.Fuzz(func(t *testing.T, data []byte, add int16) {
		if len(data) > 4096 {
			t.Skip()
		}
		a := int(add)
		conn := &fixtureReadConn{Reader: bytes.NewReader(data)}
		got, err := receiveProtocol(conn, &receiveSpec{MaxBytes: 4096, Length: &lengthSpec{Offset: 0, Bytes: 2, Order: "big", Add: &a}})
		if len(got) > 4096 {
			t.Fatalf("framed read exceeded bound: %d", len(got))
		}
		if err == nil && len(data) >= 2 {
			want := int(data[0])*256 + int(data[1]) + a + 2
			if want < 2 || want > 4096 || len(got) != want {
				t.Fatalf("accepted invalid frame: got %d, want %d", len(got), want)
			}
		}
	})
}
