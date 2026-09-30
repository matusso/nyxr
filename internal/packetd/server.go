package packetd

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/matusso/nyxr/internal/packetio"
)

// ServerConfig is the privileged side's policy. Everything a client may do is
// bounded here, not in the client.
type ServerConfig struct {
	// Interfaces is the allowlist; a client naming any other is refused.
	Interfaces []string
	// MaxClients bounds concurrent sessions (default 4).
	MaxClients int
	// MaxPPS caps transmitted frames per second per session; 0 = unlimited.
	MaxPPS int
	// Open opens live I/O; nil uses packetio.OpenLive.
	Open packetio.Opener
	// InterfaceMAC returns the source MAC transmit frames must carry; nil
	// looks the interface up in the OS. A nil MAC (e.g. an Npcap device ID
	// unknown to the OS) disables the check for that interface.
	InterfaceMAC func(string) net.HardwareAddr
	Logger       *log.Logger
}

// Server relays frames between clients and live interfaces.
type Server struct {
	cfg     ServerConfig
	allowed map[string]bool
	slots   chan struct{}
	wg      sync.WaitGroup
}

func NewServer(cfg ServerConfig) (*Server, error) {
	if len(cfg.Interfaces) == 0 {
		return nil, errors.New("packetd requires at least one allowed interface")
	}
	if cfg.MaxClients <= 0 {
		cfg.MaxClients = 4
	}
	if cfg.MaxPPS < 0 {
		return nil, errors.New("packetd max pps must be nonnegative")
	}
	if cfg.Open == nil {
		cfg.Open = packetio.OpenLive
	}
	if cfg.InterfaceMAC == nil {
		cfg.InterfaceMAC = func(name string) net.HardwareAddr {
			if iface, err := net.InterfaceByName(name); err == nil && len(iface.HardwareAddr) == 6 {
				return iface.HardwareAddr
			}
			return nil
		}
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "packetd: ", log.LstdFlags)
	}
	s := &Server{cfg: cfg, allowed: map[string]bool{}, slots: make(chan struct{}, cfg.MaxClients)}
	for _, name := range cfg.Interfaces {
		s.allowed[name] = true
	}
	return s, nil
}

// Listen creates the Unix socket with the given permissions, replacing a
// stale socket file but never any other kind of file.
func Listen(path string, mode os.FileMode) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if c, err := net.Dial("unix", path); err == nil {
			_ = c.Close()
			return nil, fmt.Errorf("%s is in use by another packetd", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

// Serve accepts sessions until ctx ends or the listener fails, then waits for
// open sessions to close.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	defer s.wg.Wait()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case s.slots <- struct{}{}:
		default:
			w := bufio.NewWriter(conn)
			_ = writeJSONLine(w, helloReply{Error: "too many packetd clients"})
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.slots }()
			if err := s.session(ctx, conn); err != nil && ctx.Err() == nil {
				s.cfg.Logger.Printf("session ended: %v", err)
			}
		}()
	}
}

func (s *Server) session(parent context.Context, conn net.Conn) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	r := bufio.NewReader(conn)
	w := bufio.NewWriterSize(conn, 64<<10)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := readLine(r)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	var h hello
	if err := jsonStrict(line, &h); err != nil {
		_ = writeJSONLine(w, helloReply{Error: "malformed hello"})
		return err
	}
	if h.Version != ProtocolVersion {
		_ = writeJSONLine(w, helloReply{Error: fmt.Sprintf("unsupported protocol version %d", h.Version)})
		return fmt.Errorf("client protocol version %d", h.Version)
	}
	if !s.allowed[h.Interface] {
		_ = writeJSONLine(w, helloReply{Error: fmt.Sprintf("interface %q is not allowed by packetd", h.Interface)})
		return fmt.Errorf("refused interface %q", h.Interface)
	}
	pio, err := s.cfg.Open(h.Interface)
	if err != nil {
		_ = writeJSONLine(w, helloReply{Error: fmt.Sprintf("open %s: %v", h.Interface, err)})
		return err
	}
	defer pio.Close()
	if err := writeJSONLine(w, helloReply{OK: true}); err != nil {
		return err
	}
	s.cfg.Logger.Printf("session opened on %s", h.Interface)
	defer s.cfg.Logger.Printf("session closed on %s", h.Interface)

	var wmu sync.Mutex
	var rejected atomic.Uint64
	send := func(typ byte, payload []byte, flush bool) error {
		wmu.Lock()
		defer wmu.Unlock()
		if err := writeMsg(w, typ, payload); err != nil {
			return err
		}
		if flush {
			return w.Flush()
		}
		return nil
	}
	var bg sync.WaitGroup
	defer bg.Wait()
	defer cancel()
	bg.Add(2)
	go func() { // RX: live frames to the client
		defer bg.Done()
		defer cancel()
		buffers := make([][]byte, 32)
		for i := range buffers {
			buffers[i] = make([]byte, MaxFrame)
		}
		for {
			n, err := pio.ReceiveBatch(ctx, buffers)
			for i := 0; i < n; i++ {
				if len(buffers[i]) > 0 && send(msgRX, buffers[i], false) != nil {
					return
				}
				buffers[i] = buffers[i][:cap(buffers[i])]
			}
			if n > 0 {
				wmu.Lock()
				ferr := w.Flush()
				wmu.Unlock()
				if ferr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() { // stats
		defer bg.Done()
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				st := pio.Stats()
				var b [statsSize]byte
				binary.BigEndian.PutUint64(b[0:], st.Received)
				binary.BigEndian.PutUint64(b[8:], st.Sent)
				binary.BigEndian.PutUint64(b[16:], st.Dropped+rejected.Load())
				if send(msgStats, b[:], true) != nil {
					return
				}
			}
		}
	}()

	mac := s.cfg.InterfaceMAC(h.Interface)
	var interval time.Duration
	if s.cfg.MaxPPS > 0 {
		interval = time.Second / time.Duration(s.cfg.MaxPPS)
	}
	next := time.Now()
	buf := make([]byte, MaxFrame)
	frames := make([][]byte, 1)
	for {
		typ, payload, err := readMsg(r, buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if typ != msgTX {
			return fmt.Errorf("unexpected message type %q", typ)
		}
		if len(payload) < MinFrame {
			rejected.Add(1)
			continue
		}
		if mac != nil && string(payload[6:12]) != string(mac) {
			// Frames may only leave with the interface's own source MAC.
			rejected.Add(1)
			continue
		}
		if interval > 0 {
			if d := time.Until(next); d > 0 {
				select {
				case <-time.After(d):
				case <-ctx.Done():
					return nil
				}
			}
			next = maxTime(next, time.Now()).Add(interval)
		}
		frames[0] = payload
		if _, err := pio.SendBatch(ctx, frames); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
