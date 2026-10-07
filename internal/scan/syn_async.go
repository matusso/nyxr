package scan

import (
	"container/heap"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
	"github.com/matusso/nyxr/internal/stack"
)

const synBatchSize = 32
const maxSYNInFlight = 16384

type synKey struct {
	target netip.Addr
	port   uint16
	seq    uint32
}

type synPending struct {
	key      synKey
	obs      Observation
	sent     time.Time
	deadline time.Time
	index    int
}

type synWork struct {
	task task
	mac  net.HardwareAddr
}

type synDeadlines []*synPending

func (q synDeadlines) Len() int           { return len(q) }
func (q synDeadlines) Less(i, j int) bool { return q[i].deadline.Before(q[j].deadline) }
func (q synDeadlines) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].index, q[j].index = i, j
}
func (q *synDeadlines) Push(v any) {
	p := v.(*synPending)
	p.index = len(*q)
	*q = append(*q, p)
}
func (q *synDeadlines) Pop() any {
	old := *q
	p := old[len(old)-1]
	p.index = -1
	*q = old[:len(old)-1]
	return p
}

func runSYNAsync(parent context.Context, cfg config.Config, emit func(Observation) error, io packetio.PacketIO, srcMAC net.HardwareAddr, source netip.Addr, neighbors map[netip.Addr]net.HardwareAddr, limiter *probeLimiter, resolve func(context.Context, []netip.Addr) (map[netip.Addr]net.HardwareAddr, error)) (runErr error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return err
	}
	var seed [2]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return err
	}
	port := uint16(49152 + binary.BigEndian.Uint16(seed[:])%16384)
	if filter, ok := io.(interface{ SetSYNFilter(uint16) error }); ok {
		// Reserve the source port in the host TCP stack while XDP redirects
		// replies for it. This prevents an unrelated connection from being
		// assigned the same ephemeral port and losing its packets to Nyxr.
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP(source.AsSlice())})
		if err != nil {
			return fmt.Errorf("reserve AF_XDP SYN port: %w", err)
		}
		defer listener.Close()
		port = uint16(listener.Addr().(*net.TCPAddr).Port)
		if err := filter.SetSYNFilter(port); err != nil {
			return fmt.Errorf("configure AF_XDP SYN filter: %w", err)
		}
	}
	destination := cfg.NextHopMAC
	if len(destination) == 0 {
		destination = srcMAC
	}
	tmpl, err := packet.NewSYNTemplate(srcMAC, destination, source, port)
	if err != nil {
		return err
	}
	if cfg.StackFingerprint {
		tmpl.EnableFingerprint()
	}
	if limiter == nil {
		limiter = newScopedProbeLimiter(cfg)
	}
	defer limiter.Close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	responses := make(chan packet.Decoded, maxSYNInFlight)
	rxErr := make(chan error, 1)
	go func() {
		rxErr <- receiveSYN(ctx, io, []chan packet.Decoded{responses}, source, port, min(cfg.Workers, runtime.GOMAXPROCS(0), 8))
	}()
	tasks := make(chan synWork, synBatchSize*2)
	producerErr := make(chan error, 1)
	go func() {
		defer close(tasks)
		var chunk []netip.Addr
		var produceError error
		flush := func() bool {
			if len(chunk) == 0 {
				return true
			}
			var macs map[netip.Addr]net.HardwareAddr
			if resolve != nil {
				macs, produceError = resolve(ctx, chunk)
				if produceError != nil {
					return false
				}
			}
			for _, target := range chunk {
				for _, p := range cfg.Ports {
					if !cfg.Includes(target, "tcp", p) {
						continue
					}
					work := synWork{task: task{target: target, port: p, transport: "tcp"}, mac: macs[target]}
					select {
					case tasks <- work:
					case <-ctx.Done():
						return false
					}
				}
			}
			chunk = chunk[:0]
			return true
		}
		cfg.EachTarget(func(target netip.Addr) bool {
			chunk = append(chunk, target)
			if len(chunk) == 128 {
				return flush()
			}
			return true
		})
		if produceError == nil && ctx.Err() == nil {
			flush()
		}
		producerErr <- produceError
	}()
	h := hmac.New(sha256.New, secret[:])
	batchLimit := synBatchSize
	if cfg.Rate > 0 {
		batchLimit = max(1, min(synBatchSize, cfg.Rate/500))
	}
	if cfg.HostRate > 0 || cfg.SubnetRate > 0 || cfg.InterfaceRate > 0 {
		batchLimit = 1
	}
	pending := make(map[synKey]*synPending)
	deadlines := make(synDeadlines, 0, min(maxSYNInFlight, cfg.Workers*256))
	// Every exit caused by caller cancellation retains validated replies,
	// including cancellation during a rate-limit wait or the RX error path.
	defer func() {
		if parent.Err() == nil {
			return
		}
		for _, entry := range pending {
			if entry.obs.PacketsRX == 0 {
				continue
			}
			stack.Analyze(entry.obs.TCPStack)
			if err := emit(entry.obs); err != nil {
				runErr = err
				return
			}
		}
	}()
	var ordinal uint64
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	stopTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	handleReply := func(p packet.Decoded) error {
		var key synKey
		switch {
		case p.Protocol == "tcp" && p.Destination == source && p.TCPFlags&16 != 0:
			key = synKey{p.Source, p.SourcePort, p.TCPAck - 1}
		case p.Protocol == "icmp" && p.ICMPType == 3 && p.Destination == source && p.Quote.Valid && p.Quote.Source == source:
			key = synKey{p.Quote.Destination, p.Quote.DestPort, p.Quote.Sequence}
		default:
			return nil
		}
		entry := pending[key]
		if entry == nil {
			return nil
		}
		if !p.Received.IsZero() && p.Received.After(entry.deadline) {
			return nil
		}
		o := entry.obs
		if p.Protocol == "tcp" && p.DestPort == port {
			switch {
			case p.TCPFlags&0x12 == 0x12 && p.TCPFlags&0x04 == 0:
				o.State, o.Confidence, o.Reason = "open", 100, "matching TCP SYN/ACK"
			case p.TCPFlags&0x04 != 0:
				o.State, o.Confidence, o.Reason = "closed", 100, "matching TCP RST/ACK"
			default:
				return nil
			}
		} else if p.Protocol == "icmp" && p.Quote.SourcePort == port {
			o.State, o.Confidence, o.Reason = "filtered", 95, fmt.Sprintf("ICMP destination unreachable (code %d)", p.ICMPCode)
		} else {
			return nil
		}
		if cfg.StackFingerprint && p.Protocol == "tcp" {
			if entry.obs.PacketsRX == 0 {
				entry.obs = o
				entry.obs.RTT = time.Since(entry.sent)
				entry.obs.TCPStack = &observe.TCPStack{ObservationWindow: cfg.Timeout}
			}
			entry.obs.PacketsRX++
			f := entry.obs.TCPStack
			if len(f.Samples) < stack.MaxSamples {
				f.Samples = append(f.Samples, stack.Sample(p))
			} else {
				f.Truncated = true
			}
			return nil // retain until the original deadline to observe repeats
		}
		if entry.obs.PacketsRX > 0 {
			return nil
		} // ICMP cannot replace a TCP reply
		delete(pending, key)
		heap.Remove(&deadlines, entry.index)
		o.PacketsRX = 1
		o.RTT = time.Since(entry.sent)
		return emit(o)
	}
	for {
		// Process queued replies before expiring probes at the same instant.
		for i := 0; i < 64; i++ {
			select {
			case p := <-responses:
				if err := handleReply(p); err != nil {
					cancel()
					<-rxErr
					return err
				}
			default:
				i = 64
			}
		}
		now := time.Now()
		for deadlines.Len() > 0 && !deadlines[0].deadline.After(now) {
			entry := heap.Pop(&deadlines).(*synPending)
			delete(pending, entry.key)
			o := entry.obs
			if o.PacketsRX == 0 {
				o.State, o.Confidence, o.Reason = "filtered", 60, "TCP SYN timed out"
				o.RTT = now.Sub(entry.sent)
			} else {
				o.TCPStack.CollectionComplete = true
				stack.Analyze(o.TCPStack)
			}
			if err := emit(o); err != nil {
				cancel()
				<-rxErr
				return err
			}
		}
		if ctx.Err() != nil {
			break
		}
		if tasks == nil && len(pending) == 0 {
			break
		}
		var taskInput <-chan synWork
		if len(pending) < maxSYNInFlight {
			taskInput = tasks
		}
		var timerC <-chan time.Time
		if deadlines.Len() > 0 {
			stopTimer()
			timer.Reset(max(0, time.Until(deadlines[0].deadline)))
			timerC = timer.C
		}
		select {
		case work, ok := <-taskInput:
			if !ok {
				if err := <-producerErr; err != nil {
					cancel()
					<-rxErr
					return err
				}
				tasks = nil
				continue
			}
			var batch [synBatchSize][]byte
			var storage [synBatchSize][74]byte
			var entries [synBatchSize]*synPending
			count := 0
			add := func(work synWork) error {
				t := work.task
				if neighbors != nil || resolve != nil {
					mac := work.mac
					if neighbors != nil {
						mac = neighbors[t.target]
					}
					if len(mac) == 0 {
						o := base(t, "tcp-syn")
						o.State, o.Confidence, o.Reason = "no-response", 80, "next-hop ARP unanswered; SYN not sent"
						return emit(o)
					}
					if err := tmpl.SetDestination(mac); err != nil {
						return err
					}
				}
				if err := limiter.WaitFor(ctx, t.target); err != nil {
					return err
				}
				ordinal++
				if ordinal%1024 == 0 {
					limiter.PruneExpired(time.Now())
				}
				seq := synToken(h, t, port, ordinal)
				frame := tmpl.Frame(t.target, t.port, seq)
				copy(storage[count][:], frame)
				batch[count] = storage[count][:len(frame)]
				entries[count] = &synPending{key: synKey{t.target, t.port, seq}, obs: base(t, "tcp-syn")}
				count++
				return nil
			}
			if err := add(work); err != nil {
				cancel()
				<-rxErr
				return err
			}
			for count < batchLimit && len(pending)+count < maxSYNInFlight {
				select {
				case work, ok := <-tasks:
					if !ok {
						if err := <-producerErr; err != nil {
							cancel()
							<-rxErr
							return err
						}
						tasks = nil
						break
					}
					if err := add(work); err != nil {
						cancel()
						<-rxErr
						return err
					}
				default:
					break
				}
				if tasks == nil || len(tasks) == 0 {
					break
				}
			}
			if count == 0 {
				continue
			}
			sentAt := time.Now()
			n, sendErr := io.SendBatch(ctx, batch[:count])
			if n < 0 || n > count {
				n = 0
				sendErr = fmt.Errorf("invalid batch send count")
			}
			for i := 0; i < count; i++ {
				entry := entries[i]
				if i < n {
					entry.obs.PacketsTX = 1
					entry.sent = sentAt
					entry.deadline = sentAt.Add(cfg.Timeout)
					pending[entry.key] = entry
					heap.Push(&deadlines, entry)
				} else {
					entry.obs.State, entry.obs.Reason = "error", fmt.Sprintf("send SYN: sent %d/%d frames: %v", n, count, sendErr)
					if err := emit(entry.obs); err != nil {
						cancel()
						<-rxErr
						return err
					}
				}
			}
		case p := <-responses:
			if err := handleReply(p); err != nil {
				cancel()
				<-rxErr
				return err
			}
		case <-timerC:
		case err := <-rxErr:
			cancel()
			if err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return parent.Err()
		case <-ctx.Done():
		}
	}
	cancel()
	if err := <-rxErr; err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return parent.Err()
}
