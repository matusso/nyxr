package scan

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
)

type liveOpener func(string) (packetio.PacketIO, error)

// runSYN uses fixed transmit workers with one outstanding probe each. An RX
// worker owns its decoder and routes compact values by the probe source port.
// No packet buffer escapes the RX worker and no goroutine is made per target.
func runSYN(parent context.Context, cfg config.Config, emit func(Observation) error, open liveOpener) error {
	iface, lookupErr := net.InterfaceByName(cfg.Interface)
	var source netip.Addr
	var srcMAC net.HardwareAddr
	if lookupErr == nil {
		if len(iface.HardwareAddr) != 6 {
			return fmt.Errorf("interface %s is not Ethernet", cfg.Interface)
		}
		var err error
		source, err = selectIPv4Source(iface, cfg.SourceIP)
		if err != nil {
			return err
		}
		srcMAC = iface.HardwareAddr
		if len(cfg.SourceMAC) != 0 && string(cfg.SourceMAC) != string(srcMAC) {
			return fmt.Errorf("source MAC does not match interface %s", cfg.Interface)
		}
	} else {
		// Npcap device IDs need not be OS interface names. Explicit source
		// addressing makes that mapping unambiguous.
		if !cfg.SourceIP.Is4() || len(cfg.SourceMAC) != 6 {
			return fmt.Errorf("interface %s not found by OS; specify source IP and source MAC for an Npcap adapter", cfg.Interface)
		}
		source, srcMAC = cfg.SourceIP, cfg.SourceMAC
	}
	io, err := open(cfg.Interface)
	if err != nil {
		return fmt.Errorf("raw packet I/O on %s: %w", cfg.Interface, err)
	}
	defer io.Close()
	limiter := newScopedProbeLimiter(cfg)
	if len(cfg.NextHopMAC) == 0 {
		neighbors, err := resolveNextHops(parent, cfg, io, srcMAC, source, limiter)
		if err != nil {
			return fmt.Errorf("resolve SYN next hops: %w", err)
		}
		return runSYNWithIOResolved(parent, cfg, emit, io, srcMAC, source, neighbors, limiter)
	}
	return runSYNWithIOResolved(parent, cfg, emit, io, srcMAC, source, nil, limiter)
}

func selectIPv4Source(iface *net.Interface, requested netip.Addr) (netip.Addr, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	var selected netip.Addr
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		a := prefix.Addr()
		if requested.IsValid() {
			if a == requested {
				return a, nil
			}
			continue
		}
		if selected.IsValid() {
			return netip.Addr{}, fmt.Errorf("interface %s has multiple IPv4 addresses; specify --source-ip", iface.Name)
		}
		selected = a
	}
	if requested.IsValid() {
		return netip.Addr{}, fmt.Errorf("source IP %s is not assigned to interface %s", requested, iface.Name)
	}
	if !selected.IsValid() {
		return netip.Addr{}, fmt.Errorf("interface %s has no IPv4 address", iface.Name)
	}
	return selected, nil
}

func runSYNWithIO(parent context.Context, cfg config.Config, emit func(Observation) error, io packetio.PacketIO, srcMAC net.HardwareAddr, source netip.Addr) error {
	return runSYNWithIOResolved(parent, cfg, emit, io, srcMAC, source, nil, nil)
}

func runSYNWithIOResolved(parent context.Context, cfg config.Config, emit func(Observation) error, io packetio.PacketIO, srcMAC net.HardwareAddr, source netip.Addr, neighbors map[netip.Addr]net.HardwareAddr, limiter *probeLimiter) error {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return err
	}
	var portSeed [2]byte
	if _, err := rand.Read(portSeed[:]); err != nil {
		return err
	}
	basePort := uint16(49152 + int(binary.BigEndian.Uint16(portSeed[:]))%(16384-cfg.Workers))
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if limiter == nil {
		limiter = newScopedProbeLimiter(cfg)
	}
	defer limiter.Close()
	results := make(chan Observation, cfg.Workers*2)
	queues := make([]chan task, cfg.Workers)
	responses := make([]chan packet.Decoded, cfg.Workers)
	var txMu sync.Mutex
	var workers sync.WaitGroup
	for i := range queues {
		queues[i] = make(chan task, 2)
		responses[i] = make(chan packet.Decoded, 16)
		destination := cfg.NextHopMAC
		if len(destination) == 0 {
			destination = srcMAC
		}
		template, err := packet.NewSYNTemplate(srcMAC, destination, source, basePort+uint16(i))
		if err != nil {
			return err
		}
		workers.Add(1)
		go func(i int, tmpl *packet.SYNTemplate) {
			defer workers.Done()
			h := hmac.New(sha256.New, secret[:])
			var ordinal uint64
			var frameBatch [1][]byte
			for t := range queues[i] {
				if neighbors != nil {
					mac := neighbors[t.target]
					if len(mac) == 0 {
						o := base(t, "tcp-syn")
						o.State, o.Confidence, o.Reason = "no-response", 80, "next-hop ARP unanswered; SYN not sent"
						select {
						case results <- o:
						case <-ctx.Done():
							return
						}
						continue
					}
					if err := tmpl.SetDestination(mac); err != nil {
						o := base(t, "tcp-syn")
						o.State, o.Reason = "error", err.Error()
						select {
						case results <- o:
						case <-ctx.Done():
							return
						}
						continue
					}
				}
				if err := limiter.WaitFor(ctx, t.target); err != nil {
					return
				}
				ordinal++
				seq := synToken(h, t, basePort+uint16(i), ordinal)
				start := time.Now()
				o := base(t, "tcp-syn")
				frameBatch[0] = tmpl.Frame(t.target, t.port, seq)
				txMu.Lock()
				n, sendErr := io.SendBatch(ctx, frameBatch[:])
				txMu.Unlock()
				if n > 0 {
					o.PacketsTX = 1
				}
				if sendErr != nil || n != 1 {
					o.State, o.Reason = "error", fmt.Sprintf("send SYN: sent %d/1 frames: %v", n, sendErr)
				} else {
					o = waitSYN(ctx, responses[i], t, source, basePort+uint16(i), seq, start, cfg.Timeout, o)
				}
				select {
				case results <- o:
				case <-ctx.Done():
					return
				}
			}
		}(i, template)
	}
	rxErr := make(chan error, 1)
	decodeWorkers := min(cfg.Workers, runtime.GOMAXPROCS(0), 8)
	go func() {
		rxErr <- receiveSYN(ctx, io, responses, source, basePort, decodeWorkers)
		cancel()
	}()
	go func() {
		defer func() {
			for _, q := range queues {
				close(q)
			}
		}()
		var next int
		for _, target := range cfg.Targets {
			for _, port := range cfg.Ports {
				select {
				case queues[next] <- task{target: target, port: port, transport: "tcp"}:
					next = (next + 1) % len(queues)
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()
	var firstErr error
	for obs := range results {
		if firstErr == nil {
			if err := emit(obs); err != nil {
				firstErr = err
				cancel()
			}
		}
	}
	cancel()
	if err := <-rxErr; err != nil && !errors.Is(err, context.Canceled) && firstErr == nil {
		firstErr = err
	}
	if firstErr != nil {
		return firstErr
	}
	return parent.Err()
}

func synToken(h hash.Hash, t task, sourcePort uint16, ordinal uint64) uint32 {
	var input [16]byte
	addr := t.target.As4()
	copy(input[:4], addr[:])
	binary.BigEndian.PutUint16(input[4:6], t.port)
	binary.BigEndian.PutUint16(input[6:8], sourcePort)
	binary.BigEndian.PutUint64(input[8:16], ordinal)
	h.Reset()
	_, _ = h.Write(input[:])
	var digest [32]byte
	sum := h.Sum(digest[:0])
	return binary.BigEndian.Uint32(sum[:4])
}

func receiveSYN(parent context.Context, io packetio.PacketIO, channels []chan packet.Decoded, source netip.Addr, basePort uint16, workerCount int) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	queues := make([]chan []byte, workerCount)
	pool := make(chan []byte, 16+workerCount*8)
	for i := 0; i < cap(pool); i++ {
		pool <- make([]byte, 65535)
	}
	var workers sync.WaitGroup
	for i := range queues {
		queues[i] = make(chan []byte, 8)
		workers.Add(1)
		go func(q <-chan []byte) {
			defer workers.Done()
			decoder := packet.NewDecoder()
			for {
				select {
				case frame := <-q:
					if p, ok := decoder.Decode(frame); ok {
						var port uint16
						switch {
						case p.Protocol == "tcp" && p.Destination == source:
							port = p.DestPort
						case p.Protocol == "icmp" && p.ICMPType == 3 && p.Destination == source && p.Quote.Valid && p.Quote.Source == source:
							port = p.Quote.SourcePort
						}
						if port >= basePort && int(port-basePort) < len(channels) {
							select {
							case channels[int(port-basePort)] <- p:
							default: // bounded response queue
							}
						}
					}
					pool <- frame[:cap(frame)]
				case <-ctx.Done():
					return
				}
			}
		}(queues[i])
	}
	defer workers.Wait()
	var buffers [16][]byte
	var next int
	for {
		for i := range buffers {
			select {
			case buffers[i] = <-pool:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		n, err := io.ReceiveBatch(ctx, buffers[:])
		for i := 0; i < len(buffers); i++ {
			frame := buffers[i]
			if i >= n || !candidateSYNFrame(frame, source) {
				pool <- frame[:cap(frame)]
				continue
			}
			select {
			case queues[next] <- frame:
			default:
				pool <- frame[:cap(frame)]
			}
			next = (next + 1) % len(queues)
		}
		if err != nil {
			cancel()
			return err
		}
	}
}

// Filter obvious unrelated frames before they occupy the bounded decode queues.
func candidateSYNFrame(frame []byte, local netip.Addr) bool {
	if len(frame) < 34 || !local.Is4() {
		return false
	}
	offset := 12
	ethType := binary.BigEndian.Uint16(frame[offset : offset+2])
	if ethType == 0x8100 || ethType == 0x88a8 {
		if len(frame) < 38 {
			return false
		}
		offset += 4
		ethType = binary.BigEndian.Uint16(frame[offset : offset+2])
	}
	if ethType != 0x0800 {
		return false
	}
	ip := frame[offset+2:]
	if len(ip) < 20 || ip[0]>>4 != 4 || ip[0]&15 < 5 || (ip[9] != 6 && ip[9] != 1) {
		return false
	}
	dst := local.As4()
	return ip[16] == dst[0] && ip[17] == dst[1] && ip[18] == dst[2] && ip[19] == dst[3]
}

func waitSYN(ctx context.Context, responses <-chan packet.Decoded, t task, source netip.Addr, sourcePort uint16, seq uint32, sent time.Time, timeout time.Duration, o Observation) Observation {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case p := <-responses:
			if p.Protocol == "tcp" && p.Source == t.target && p.Destination == source && p.SourcePort == t.port && p.DestPort == sourcePort && p.TCPAck == seq+1 && p.TCPFlags&16 != 0 {
				switch {
				case p.TCPFlags&0x12 == 0x12 && p.TCPFlags&0x04 == 0:
					o.State, o.Confidence, o.Reason = "open", 100, "matching TCP SYN/ACK"
				case p.TCPFlags&0x04 != 0:
					o.State, o.Confidence, o.Reason = "closed", 100, "matching TCP RST/ACK"
				default:
					continue
				}
			} else if p.Protocol == "icmp" && p.ICMPType == 3 && p.Quote.Valid && p.Quote.Source == source && p.Quote.Destination == t.target && p.Quote.SourcePort == sourcePort && p.Quote.DestPort == t.port && p.Quote.Sequence == seq {
				o.State, o.Confidence, o.Reason = "filtered", 95, fmt.Sprintf("ICMP destination unreachable (code %d)", p.ICMPCode)
			} else {
				continue
			}
			o.PacketsRX = 1
			o.RTT = time.Since(sent)
			return o
		case <-timer.C:
			o.State, o.Confidence, o.Reason = "filtered", 60, "TCP SYN timed out"
			o.RTT = time.Since(sent)
			return o
		case <-ctx.Done():
			o.State, o.Reason = "error", ctx.Err().Error()
			return o
		}
	}
}
