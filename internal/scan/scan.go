package scan

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/probe"
)

type Observation struct {
	Timestamp       time.Time     `json:"timestamp"`
	Target          netip.Addr    `json:"target"`
	Transport       string        `json:"transport"`
	Port            uint16        `json:"port,omitempty"`
	State           string        `json:"state"`
	Confidence      int           `json:"confidence"`
	Reason          string        `json:"reason"`
	Probe           string        `json:"probe"`
	Service         string        `json:"service,omitempty"`
	RTT             time.Duration `json:"rtt_ns"`
	PacketsTX       int           `json:"packets_tx"`
	PacketsRX       int           `json:"packets_rx"`
	ProbesAttempted []string      `json:"probes_attempted,omitempty"`
	ResponseHex     string        `json:"response_hex,omitempty"`
}

type task struct {
	target    netip.Addr
	port      uint16
	transport string
}

// Run streams observations through a fixed worker pool. There is no goroutine
// per target or probe, and the producer applies a global probe-rate limit.
func Run(parent context.Context, cfg config.Config, emit func(Observation) error) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	var udpProbes []probe.Probe
	var secret [32]byte
	if cfg.UDP {
		udpProbes = cfg.UDPProbes
		if len(udpProbes) == 0 {
			var err error
			udpProbes, err = probe.Builtins()
			if err != nil {
				return err
			}
		}
		if _, err := rand.Read(secret[:]); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	limiter := newProbeLimiter(cfg.Rate)
	defer limiter.Close()
	tasks := make(chan task, cfg.Workers*2)
	results := make(chan Observation, cfg.Workers*2)
	var workers sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for t := range tasks {
				var result Observation
				switch t.transport {
				case "tcp":
					if limiter.Wait(ctx) != nil {
						return
					}
					result = probeTCP(ctx, t, cfg.Timeout)
				case "udp":
					result = probeUDPCampaign(ctx, t, cfg.Timeout, udpProbes, cfg.UDPRetries, secret[:], limiter)
				case "icmp":
					if limiter.Wait(ctx) != nil {
						return
					}
					result = probeICMP(ctx, t, cfg.Timeout)
				}
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() { workers.Wait(); close(results) }()
	go func() {
		defer close(tasks)
		send := func(t task) bool {
			select {
			case tasks <- t:
				return true
			case <-ctx.Done():
				return false
			}
		}
		for _, target := range cfg.Targets {
			if cfg.ICMP && !send(task{target: target, transport: "icmp"}) {
				return
			}
			for _, port := range cfg.Ports {
				if cfg.TCP && !send(task{target: target, port: port, transport: "tcp"}) {
					return
				}
				if cfg.UDP && !send(task{target: target, port: port, transport: "udp"}) {
					return
				}
			}
		}
	}()
	var firstErr error
	for obs := range results {
		if firstErr == nil {
			if err := emit(obs); err != nil {
				firstErr = err
				cancel()
			}
		}
	}
	if firstErr != nil {
		return firstErr
	}
	return parent.Err()
}

func base(t task, probe string) Observation {
	return Observation{Timestamp: time.Now().UTC(), Target: t.target, Port: t.port,
		Transport: t.transport, Probe: probe, State: "unknown"}
}

func probeTCP(ctx context.Context, t task, timeout time.Duration) Observation {
	o := base(t, "tcp-connect")
	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(t.target.String(), fmt.Sprint(t.port)))
	o.RTT = time.Since(start)
	o.PacketsTX = 1
	if err == nil {
		_ = conn.Close()
		o.State, o.Confidence, o.Reason, o.PacketsRX = "open", 100, "TCP connection established", 1
	} else if errors.Is(err, syscall.ECONNREFUSED) {
		o.State, o.Confidence, o.Reason, o.PacketsRX = "closed", 100, "connection refused", 1
	} else if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		o.State, o.Confidence, o.Reason = "filtered", 65, "connection timed out"
	} else {
		o.State, o.Reason = "error", err.Error()
	}
	return o
}

var echoSeq atomic.Uint32

func probeICMP(ctx context.Context, t task, timeout time.Duration) Observation {
	o := base(t, "icmp-echo")
	if !t.target.Is4() {
		o.State, o.Reason = "unsupported", "IPv6 ICMP echo is not implemented"
		return o
	}
	remote := &net.IPAddr{IP: net.IP(t.target.AsSlice())}
	conn, err := net.DialIP("ip4:icmp", nil, remote)
	if err != nil {
		o.State, o.Reason = "error", "raw ICMP socket: "+err.Error()
		return o
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	seq := uint16(echoSeq.Add(1))
	id := uint16(os.Getpid())
	var msg [16]byte
	msg[0] = 8 // echo request
	binary.BigEndian.PutUint16(msg[4:6], id)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	binary.BigEndian.PutUint64(msg[8:], uint64(time.Now().UnixNano()))
	binary.BigEndian.PutUint16(msg[2:4], checksum(msg[:]))
	start := time.Now()
	_, err = conn.Write(msg[:])
	if err != nil {
		o.State, o.Reason = "error", err.Error()
		return o
	}
	o.PacketsTX = 1
	var buf [1500]byte
	for {
		n, err := conn.Read(buf[:])
		o.RTT = time.Since(start)
		if err != nil {
			if isTimeout(err) {
				o.State, o.Confidence, o.Reason = "no-response", 40, "ICMP echo timed out"
			} else {
				o.State, o.Reason = "error", err.Error()
			}
			return o
		}
		packet := buf[:n]
		if len(packet) >= 20 && packet[0]>>4 == 4 {
			headerLen := int(packet[0]&0xf) * 4
			if headerLen > len(packet) {
				continue
			}
			packet = packet[headerLen:]
		}
		if len(packet) >= 8 && packet[0] == 0 && binary.BigEndian.Uint16(packet[4:6]) == id && binary.BigEndian.Uint16(packet[6:8]) == seq {
			o.State, o.Confidence, o.Reason, o.PacketsRX = "responsive", 100, "matching ICMP echo reply", 1
			return o
		}
		select {
		case <-ctx.Done():
			o.State, o.Reason = "error", ctx.Err().Error()
			return o
		default:
		}
	}
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func isTimeout(err error) bool { var nerr net.Error; return errors.As(err, &nerr) && nerr.Timeout() }
