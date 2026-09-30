package packetd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/packetio"
)

var ifaceMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 1}

// fakeIO is an in-memory interface: frames pushed to rx are received, sent
// frames are recorded.
type fakeIO struct {
	rx     chan []byte
	mu     sync.Mutex
	sent   [][]byte
	closed chan struct{}
	once   sync.Once
}

func newFakeIO() *fakeIO { return &fakeIO{rx: make(chan []byte, 64), closed: make(chan struct{})} }

func (f *fakeIO) ReceiveBatch(ctx context.Context, buffers [][]byte) (int, error) {
	select {
	case frame := <-f.rx:
		buffers[0] = buffers[0][:copy(buffers[0], frame)]
		return 1, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-f.closed:
		return 0, errors.New("closed")
	}
}

func (f *fakeIO) SendBatch(ctx context.Context, frames [][]byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, fr := range frames {
		f.sent = append(f.sent, append([]byte(nil), fr...))
	}
	return len(frames), nil
}

func (f *fakeIO) Stats() packetio.Stats { return packetio.Stats{Dropped: 3} }
func (f *fakeIO) Close() error          { f.once.Do(func() { close(f.closed) }); return nil }

func (f *fakeIO) sentFrames() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.sent...)
}

func start(t *testing.T, cfg ServerConfig) (string, *fakeIO) {
	t.Helper()
	dir, err := os.MkdirTemp("", "pd") // short path: Unix socket names are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	fio := newFakeIO()
	if cfg.Interfaces == nil {
		cfg.Interfaces = []string{"eth9"}
	}
	cfg.Open = func(string) (packetio.PacketIO, error) { return fio, nil }
	cfg.InterfaceMAC = func(string) net.HardwareAddr { return ifaceMAC }
	cfg.Logger = log.New(io.Discard, "", 0)
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen(sock, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, l); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return sock, fio
}

func frame(src net.HardwareAddr, n int) []byte {
	f := make([]byte, n)
	copy(f[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(f[6:12], src)
	f[12], f[13] = 0x08, 0x00
	for i := 14; i < n; i++ {
		f[i] = byte(i)
	}
	return f
}

func TestRelayRoundTrip(t *testing.T) {
	sock, fio := start(t, ServerConfig{})
	c, err := Dial(sock, "eth9")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	good := frame(ifaceMAC, 60)
	spoofed := frame(net.HardwareAddr{0x02, 9, 9, 9, 9, 9}, 60)
	if _, err := c.SendBatch(context.Background(), [][]byte{spoofed, good}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SendBatch(context.Background(), [][]byte{make([]byte, 4)}); err == nil {
		t.Fatal("client sent a runt frame")
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(fio.sentFrames()) < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	sent := fio.sentFrames()
	if len(sent) != 1 || !bytes.Equal(sent[0], good) {
		t.Fatalf("server transmitted %d frames; spoofed source MAC must be refused", len(sent))
	}

	rx := frame(net.HardwareAddr{0x02, 7, 7, 7, 7, 7}, 1500)
	fio.rx <- rx
	fio.rx <- rx[:100]
	buffers := [][]byte{make([]byte, 2048), make([]byte, 2048)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got := 0
	for got < 2 {
		n, err := c.ReceiveBatch(ctx, buffers[got:])
		if err != nil {
			t.Fatal(err)
		}
		got += n
	}
	if !bytes.Equal(buffers[0], rx) || !bytes.Equal(buffers[1], rx[:100]) {
		t.Fatal("received frames differ")
	}
	for c.Stats().Dropped < 4 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if st := c.Stats(); st.Received != 2 || st.Sent != 2 || st.Dropped != 4 {
		// 3 backend drops reported by the fake plus the refused spoofed frame.
		t.Fatalf("stats = %+v", st)
	}
}

func TestRefusesUnlistedInterfaceAndExtraClients(t *testing.T) {
	sock, _ := start(t, ServerConfig{MaxClients: 1})
	if _, err := Dial(sock, "eth0"); err == nil {
		t.Fatal("unlisted interface accepted")
	}
	c, err := Dial(sock, "eth9")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := Dial(sock, "eth9"); err == nil {
		t.Fatal("client beyond MaxClients accepted")
	}
}

func TestClientReportsClosedSession(t *testing.T) {
	sock, fio := start(t, ServerConfig{})
	c, err := Dial(sock, "eth9")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fio.Close() // backend fails: the server ends the session
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.ReceiveBatch(ctx, [][]byte{make([]byte, 64)}); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReceiveBatch error = %v, want closed session", err)
	}
}

func TestListenRefusesNonSocketFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, 0o600); err == nil {
		t.Fatal("Listen replaced a regular file")
	}
	if b, _ := os.ReadFile(path); string(b) != "keep" {
		t.Fatal("regular file modified")
	}
}

func TestReadMsgBoundsLength(t *testing.T) {
	var b bytes.Buffer
	b.Write([]byte{msgRX, 0xff, 0xff, 0xff, 0xff})
	_, _, err := readMsg(bufioReader(&b), make([]byte, MaxFrame))
	if err == nil {
		t.Fatal("oversized message accepted")
	}
}

func bufioReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }
