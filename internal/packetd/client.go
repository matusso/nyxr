package packetd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/matusso/nyxr/internal/packetio"
)

// rxQueue bounds frames buffered between the socket reader and
// ReceiveBatch; frames beyond it are counted as dropped, never queued without
// limit.
const rxQueue = 4096

// Client is live packet I/O relayed through packetd.
type Client struct {
	conn    net.Conn
	w       *bufio.Writer
	wmu     sync.Mutex
	rx      chan []byte
	pool    sync.Pool
	done    chan struct{}
	readErr error

	received, sent, localDrops atomic.Uint64
	serverDrops                atomic.Uint64
	closeOnce                  sync.Once
}

// Opener returns a packetio.Opener that connects to the packetd socket.
func Opener(socket string) packetio.Opener {
	return func(device string) (packetio.PacketIO, error) { return Dial(socket, device) }
}

// Dial opens a session for one interface.
func Dial(socket, device string) (*Client, error) {
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("packetd %s: %w", socket, err)
	}
	c, err := newClient(conn, device)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return c, nil
}

func newClient(conn net.Conn, device string) (*Client, error) {
	r := bufio.NewReaderSize(conn, 64<<10)
	w := bufio.NewWriterSize(conn, 64<<10)
	if err := writeJSONLine(w, hello{Version: ProtocolVersion, Interface: device}); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := readLine(r)
	if err != nil {
		return nil, fmt.Errorf("packetd handshake: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	var reply helloReply
	if err := jsonStrict(line, &reply); err != nil {
		return nil, fmt.Errorf("packetd handshake: %w", err)
	}
	if !reply.OK {
		return nil, fmt.Errorf("packetd: %s", reply.Error)
	}
	c := &Client{conn: conn, w: w, rx: make(chan []byte, rxQueue), done: make(chan struct{})}
	c.pool.New = func() any { b := make([]byte, MaxFrame); return &b }
	go c.read(r)
	return c, nil
}

func (c *Client) read(r *bufio.Reader) {
	defer close(c.done)
	buf := make([]byte, MaxFrame)
	for {
		typ, payload, err := readMsg(r, buf)
		if err != nil {
			c.readErr = err
			return
		}
		switch typ {
		case msgRX:
			bp := c.pool.Get().(*[]byte)
			frame := (*bp)[:copy(*bp, payload)]
			select {
			case c.rx <- frame:
			default:
				c.localDrops.Add(1)
				c.pool.Put(bp)
			}
		case msgStats:
			if len(payload) == statsSize {
				c.serverDrops.Store(binary.BigEndian.Uint64(payload[16:]))
			}
		default:
			c.readErr = fmt.Errorf("unexpected packetd message type %q", typ)
			return
		}
	}
}

// ReceiveBatch blocks for at least one frame, then fills as many caller
// buffers as are immediately available, like the live backends.
func (c *Client) ReceiveBatch(ctx context.Context, buffers [][]byte) (int, error) {
	count := 0
	for count < len(buffers) {
		var frame []byte
		if count == 0 {
			select {
			case frame = <-c.rx:
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-c.done:
				select {
				case frame = <-c.rx:
				default:
					return 0, c.closedErr()
				}
			}
		} else {
			select {
			case frame = <-c.rx:
			default:
				return count, nil
			}
		}
		buf := buffers[count]
		if len(buf) == 0 {
			return count, errors.New("receive buffer is empty")
		}
		buffers[count] = buf[:copy(buf, frame)]
		frame = frame[:cap(frame)]
		c.pool.Put(&frame)
		c.received.Add(1)
		count++
	}
	return count, nil
}

func (c *Client) closedErr() error {
	if c.readErr != nil {
		return fmt.Errorf("packetd connection closed: %w", c.readErr)
	}
	return errors.New("packetd connection closed")
}

func (c *Client) SendBatch(ctx context.Context, frames [][]byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	for i, f := range frames {
		if err := ctx.Err(); err != nil {
			return i, err
		}
		if len(f) < MinFrame || len(f) > MaxFrame {
			return i, fmt.Errorf("frame of %d bytes outside %d..%d", len(f), MinFrame, MaxFrame)
		}
		if err := writeMsg(c.w, msgTX, f); err != nil {
			return i, err
		}
		c.sent.Add(1)
	}
	return len(frames), c.w.Flush()
}

// Stats counts frames seen by this client; Dropped adds frames the server's
// backend dropped or refused and frames that overflowed the local queue.
func (c *Client) Stats() packetio.Stats {
	return packetio.Stats{Received: c.received.Load(), Sent: c.sent.Load(),
		Dropped: c.localDrops.Load() + c.serverDrops.Load()}
}

func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.conn.Close()
		<-c.done
	})
	return err
}

func jsonStrict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
