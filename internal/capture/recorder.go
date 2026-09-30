package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
)

// Options bound every resource the recorder may use. Zero values select the
// defaults noted on each field.
type Options struct {
	Path      string
	Interface string
	// Targets restricts the capture to frames to or from these addresses.
	Targets []netip.Addr
	// QueueFrames is the reader-to-writer queue depth (default 4096). A full
	// queue drops the frame and counts it; the reader never blocks on disk.
	QueueFrames int
	// MaxBytes caps the file size (default 1 GiB). Frames beyond it are
	// counted as dropped.
	MaxBytes int64
	// Snaplen truncates stored frames (default 65535).
	Snaplen int
	// MaxPacketsPerFlow and MaxFlows bound the in-memory packet index
	// (defaults 64 and 65536).
	MaxPacketsPerFlow int
	MaxFlows          int
}

func (o *Options) defaults() {
	if o.QueueFrames <= 0 {
		o.QueueFrames = 4096
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = 1 << 30
	}
	if o.Snaplen <= 0 || o.Snaplen > 65535 {
		o.Snaplen = 65535
	}
	if o.MaxPacketsPerFlow <= 0 {
		o.MaxPacketsPerFlow = 64
	}
	if o.MaxFlows <= 0 {
		o.MaxFlows = 65536
	}
}

// FlowKey identifies the observation a frame belongs to: the scanned address,
// its transport and the scanned port (0 for ICMP).
type FlowKey struct {
	Target    netip.Addr
	Transport string
	Port      uint16
}

// Flow is the indexed packet list for one key.
type Flow struct {
	Key       FlowKey
	Packets   []observe.Packet
	Truncated bool
}

// Result is returned once the recorder has stopped and the file is closed.
type Result struct {
	Stats observe.CaptureStats
	Flows []Flow
}

type frame struct {
	data []byte
	ts   time.Time
}

// Recorder owns one capture handle and one pcapng file.
type Recorder struct {
	opts    Options
	src     packetio.PacketIO
	file    *os.File
	out     *PCAPNGWriter
	targets map[netip.Addr]struct{}
	pool    chan []byte
	queue   chan frame
	cancel  context.CancelFunc
	readers sync.WaitGroup
	written chan struct{}

	droppedQueue atomic.Uint64
	readErr      error

	// Owned by the writer goroutine until written is closed.
	stats     observe.CaptureStats
	flows     map[FlowKey]*Flow
	writeErr  error
	nextID    uint64
	decoder   *packet.Decoder
	stopOnce  sync.Once
	stopState Result
	stopErr   error
}

// Start creates the pcapng file and begins capturing from src. The recorder
// takes ownership of src and closes it on Stop.
func Start(parent context.Context, src packetio.PacketIO, opts Options) (*Recorder, error) {
	opts.defaults()
	if opts.Path == "" {
		return nil, errors.New("capture path is required")
	}
	if len(opts.Targets) == 0 {
		return nil, errors.New("capture requires at least one target address")
	}
	f, err := os.OpenFile(opts.Path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	w, err := NewPCAPNGWriter(f, opts.Interface, opts.Snaplen, "nyxr")
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	r := &Recorder{
		opts: opts, src: src, file: f, out: w,
		targets: make(map[netip.Addr]struct{}, len(opts.Targets)),
		pool:    make(chan []byte, opts.QueueFrames+32),
		queue:   make(chan frame, opts.QueueFrames),
		written: make(chan struct{}),
		flows:   make(map[FlowKey]*Flow),
		decoder: packet.NewDecoder(),
	}
	for _, t := range opts.Targets {
		r.targets[t.Unmap()] = struct{}{}
	}
	r.stats.Path, r.stats.Interface = opts.Path, opts.Interface
	// Buffers are allocated lazily up to the pool size so a small scan does
	// not reserve QueueFrames × 64 KiB up front.
	ctx, cancel := context.WithCancel(parent)
	r.cancel = cancel
	r.readers.Add(1)
	go r.read(ctx)
	go r.write()
	return r, nil
}

func (r *Recorder) buffer() []byte {
	select {
	case b := <-r.pool:
		return b[:cap(b)]
	default:
		return make([]byte, 65535)
	}
}

func (r *Recorder) release(b []byte) {
	select {
	case r.pool <- b[:cap(b)]:
	default:
	}
}

func (r *Recorder) read(ctx context.Context) {
	defer r.readers.Done()
	var buffers [16][]byte
	for {
		for i := range buffers {
			if buffers[i] == nil {
				buffers[i] = r.buffer()
			}
		}
		n, err := r.src.ReceiveBatch(ctx, buffers[:])
		now := time.Now()
		for i := 0; i < n; i++ {
			b := buffers[i]
			if !r.wanted(b) {
				buffers[i] = b[:cap(b)]
				continue
			}
			select {
			case r.queue <- frame{data: b, ts: now}:
				buffers[i] = nil
			default:
				r.droppedQueue.Add(1)
				buffers[i] = b[:cap(b)]
			}
		}
		if err != nil {
			if ctx.Err() == nil {
				r.readErr = err
			}
			return
		}
	}
}

// wanted is a cheap header check run on the capture reader: only IPv4/IPv6
// frames to or from a target are queued for the writer.
func (r *Recorder) wanted(f []byte) bool {
	if len(f) < 14 {
		return false
	}
	offset := 12
	ethType := binary.BigEndian.Uint16(f[offset:])
	for (ethType == 0x8100 || ethType == 0x88a8) && len(f) >= offset+6 {
		offset += 4
		ethType = binary.BigEndian.Uint16(f[offset:])
	}
	ip := f[offset+2:]
	var src, dst, quoted netip.Addr
	switch ethType {
	case 0x0800:
		if len(ip) < 20 {
			return false
		}
		src = netip.AddrFrom4([4]byte(ip[12:16]))
		dst = netip.AddrFrom4([4]byte(ip[16:20]))
		// An ICMP error from a router quotes the probe's IP header.
		if hl := int(ip[0]&15) * 4; ip[9] == 1 && hl >= 20 && len(ip) >= hl+8+20 {
			inner := ip[hl+8:]
			quoted = netip.AddrFrom4([4]byte(inner[16:20]))
		}
	case 0x86dd:
		if len(ip) < 40 {
			return false
		}
		src = netip.AddrFrom16([16]byte(ip[8:24]))
		dst = netip.AddrFrom16([16]byte(ip[24:40]))
		if ip[6] == 58 && len(ip) >= 40+8+40 {
			inner := ip[48:]
			quoted = netip.AddrFrom16([16]byte(inner[24:40]))
		}
	default:
		return false
	}
	_, s := r.targets[src]
	_, d := r.targets[dst]
	_, q := r.targets[quoted]
	return s || d || q
}

func (r *Recorder) write() {
	defer close(r.written)
	for f := range r.queue {
		r.writeFrame(f)
		r.release(f.data)
	}
	if err := r.out.Flush(); err != nil && r.writeErr == nil {
		r.writeErr = err
	}
}

func (r *Recorder) writeFrame(f frame) {
	if r.writeErr != nil {
		r.stats.DroppedLimit++
		return
	}
	data := f.data
	if len(data) > r.opts.Snaplen {
		data = data[:r.opts.Snaplen]
	}
	key, dir, summary := r.classify(f.data)
	if r.out.Bytes()+BlockSize(len(data), len(summary)) > r.opts.MaxBytes {
		r.stats.DroppedLimit++
		return
	}
	r.nextID++
	if err := r.out.WritePacket(f.ts, data, len(f.data), dir, r.nextID, summary); err != nil {
		r.writeErr = err
		r.stats.DroppedLimit++
		return
	}
	r.stats.Written++
	if !key.Target.IsValid() {
		return
	}
	flow := r.flows[key]
	if flow == nil {
		if len(r.flows) >= r.opts.MaxFlows {
			r.stats.FlowsTruncate++
			return
		}
		flow = &Flow{Key: key}
		r.flows[key] = flow
	}
	if len(flow.Packets) >= r.opts.MaxPacketsPerFlow {
		flow.Truncated = true
		return
	}
	flow.Packets = append(flow.Packets, observe.Packet{
		ID: r.nextID, Timestamp: f.ts.UTC(), Direction: dir.String(), Length: len(f.data), Summary: summary,
	})
}

// classify maps a frame to the observation it supports. ICMP errors quoting a
// TCP probe belong to that TCP port; other ICMP belongs to the host.
func (r *Recorder) classify(data []byte) (FlowKey, Direction, string) {
	p, ok := r.decoder.Decode(data)
	if !ok {
		return FlowKey{}, DirectionUnknown, ""
	}
	src, dst := p.Source.Unmap(), p.Destination.Unmap()
	_, dstTarget := r.targets[dst]
	_, srcTarget := r.targets[src]
	dir, target, targetPort := DirectionUnknown, netip.Addr{}, uint16(0)
	switch {
	case !dstTarget && !srcTarget:
		// Only a quoted ICMP error passes the pre-filter this way.
		dir = DirectionRX
	case dstTarget && !srcTarget:
		dir, target, targetPort = DirectionTX, dst, p.DestPort
	case srcTarget:
		dir, target, targetPort = DirectionRX, src, p.SourcePort
	}
	switch p.Protocol {
	case "tcp":
		summary := fmt.Sprintf("tcp %s:%d > %s:%d [%s] seq=%d ack=%d", p.Source, p.SourcePort, p.Destination, p.DestPort, tcpFlags(p.TCPFlags), p.TCPSeq, p.TCPAck)
		return FlowKey{Target: target, Transport: "tcp", Port: targetPort}, dir, summary
	case "udp":
		summary := fmt.Sprintf("udp %s:%d > %s:%d", p.Source, p.SourcePort, p.Destination, p.DestPort)
		return FlowKey{Target: target, Transport: "udp", Port: targetPort}, dir, summary
	case "icmp", "icmp6":
		summary := fmt.Sprintf("%s %s > %s type=%d code=%d", p.Protocol, p.Source, p.Destination, p.ICMPType, p.ICMPCode)
		if p.Quote.Valid {
			quoted := p.Quote.Destination.Unmap()
			if _, ok := r.targets[quoted]; ok {
				return FlowKey{Target: quoted, Transport: "tcp", Port: p.Quote.DestPort}, DirectionRX, summary + fmt.Sprintf(" quoting tcp %s:%d", quoted, p.Quote.DestPort)
			}
		}
		return FlowKey{Target: target, Transport: "icmp"}, dir, summary
	}
	return FlowKey{}, dir, p.Protocol
}

func tcpFlags(f uint8) string {
	const names = "FSRPAUEC"
	out := make([]byte, 0, 8)
	for i := 0; i < 8; i++ {
		if f&(1<<i) != 0 {
			out = append(out, names[i])
		}
	}
	if len(out) == 0 {
		return "none"
	}
	return string(out)
}

// Stop ends the capture, drains every queued frame to disk, closes the file
// and the capture handle, and returns the flow index. It is idempotent.
func (r *Recorder) Stop() (Result, error) {
	r.stopOnce.Do(func() {
		r.cancel()
		r.readers.Wait()
		close(r.queue)
		<-r.written
		backend := r.src.Stats()
		closeErr := r.src.Close()
		fileErr := r.file.Close()
		r.stats.Bytes = r.out.Bytes()
		r.stats.DroppedQueue = r.droppedQueue.Load()
		r.stats.BackendDrops = backend.Dropped
		r.stats.FlowsIndexed = len(r.flows)
		flows := make([]Flow, 0, len(r.flows))
		for _, f := range r.flows {
			flows = append(flows, *f)
		}
		sort.Slice(flows, func(i, j int) bool {
			a, b := flows[i].Key, flows[j].Key
			if c := a.Target.Compare(b.Target); c != 0 {
				return c < 0
			}
			if a.Transport != b.Transport {
				return a.Transport < b.Transport
			}
			return a.Port < b.Port
		})
		r.stopState = Result{Stats: r.stats, Flows: flows}
		r.stopErr = errors.Join(r.readErr, r.writeErr, fileErr, ignoreClosed(closeErr))
	})
	return r.stopState, r.stopErr
}

func ignoreClosed(err error) error {
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}
