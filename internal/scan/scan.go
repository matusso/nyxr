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
	"github.com/matusso/nyxr/internal/packetio"
	"github.com/matusso/nyxr/internal/probe"
)

type Observation struct {
	Timestamp       time.Time         `json:"timestamp"`
	Target          netip.Addr        `json:"target"`
	Transport       string            `json:"transport"`
	Port            uint16            `json:"port,omitempty"`
	State           string            `json:"state"`
	Confidence      int               `json:"confidence"`
	Reason          string            `json:"reason"`
	Probe           string            `json:"probe"`
	Service         string            `json:"service,omitempty"`
	MAC             string            `json:"mac,omitempty"`
	RTT             time.Duration     `json:"rtt_ns"`
	PacketsTX       int               `json:"packets_tx"`
	PacketsRX       int               `json:"packets_rx"`
	ProbesAttempted []string          `json:"probes_attempted,omitempty"`
	ResponseHex     string            `json:"response_hex,omitempty"`
	Fields          map[string]string `json:"fields,omitempty"`
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
	if cfg.ARP || cfg.NDP {
		return runNeighbor(parent, cfg, emit)
	}
	if cfg.TCPMode == "syn" {
		return runSYN(parent, cfg, emit, packetio.OpenLive)
	}
	var udpProbes []probe.Probe
	var icmpObserver *udpICMPObserver
	var udpSignals *udpFeedback
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
		icmpObserver = openUDPICMP(cfg.Targets)
		defer icmpObserver.Close()
		udpSignals = newUDPFeedback()
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	limiter := newScopedProbeLimiter(cfg)
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
					if limiter.WaitFor(ctx, t.target) != nil {
						return
					}
					result = probeTCP(ctx, t, cfg.Timeout)
				case "udp":
					result = probeUDPCampaignWithICMP(ctx, t, cfg.Timeout, udpProbes, cfg.UDPRetries+udpSignals.retryBonus(t.target), secret[:], limiter, icmpObserver)
					udpSignals.record(result)
				case "icmp":
					if limiter.WaitFor(ctx, t.target) != nil {
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
	if err := ctx.Err(); err != nil {
		o.State, o.Reason = "error", err.Error()
		return o
	}
	network := "ip4:icmp"
	requestType, replyType := byte(8), byte(0)
	if t.target.Is6() {
		network, requestType, replyType = "ip6:ipv6-icmp", 128, 129
	}
	remote := &net.IPAddr{IP: net.IP(t.target.AsSlice()), Zone: t.target.Zone()}
	conn, err := net.DialIP(network, nil, remote)
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
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	seq := uint16(echoSeq.Add(1))
	id := uint16(os.Getpid())
	var msg [16]byte
	msg[0] = requestType
	binary.BigEndian.PutUint16(msg[4:6], id)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	if _, err := rand.Read(msg[8:]); err != nil {
		o.State, o.Reason = "error", err.Error()
		return o
	}
	if t.target.Is4() {
		binary.BigEndian.PutUint16(msg[2:4], checksum(msg[:]))
	} else {
		local := conn.LocalAddr().(*net.IPAddr).IP.To16()
		if local == nil {
			o.State, o.Reason = "error", "no IPv6 source address selected"
			return o
		}
		binary.BigEndian.PutUint16(msg[2:4], icmp6Checksum(local, remote.IP.To16(), msg[:]))
	}
	start := time.Now()
	_, err = conn.Write(msg[:])
	if err != nil {
		o.State, o.Reason = "error", err.Error()
		return o
	}
	o.PacketsTX = 1
	var buf [1500]byte
	for {
		n, from, err := conn.ReadFromIP(buf[:])
		o.RTT = time.Since(start)
		if err != nil {
			if ctx.Err() != nil {
				o.State, o.Reason = "error", ctx.Err().Error()
			} else if isTimeout(err) {
				o.State, o.Confidence, o.Reason = "no-response", 40, "ICMP echo timed out"
			} else {
				o.State, o.Reason = "error", err.Error()
			}
			return o
		}
		if from == nil || !from.IP.Equal(remote.IP) {
			continue
		}
		if matchesEchoReply(buf[:n], replyType, msg[:]) {
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

func matchesEchoReply(packet []byte, replyType byte, request []byte) bool {
	if len(packet) >= 20 && packet[0]>>4 == 4 {
		headerLen := int(packet[0]&0xf) * 4
		if headerLen < 20 || headerLen > len(packet) {
			return false
		}
		packet = packet[headerLen:]
	} else if len(packet) >= 40 && packet[0]>>4 == 6 {
		if packet[6] != 58 {
			return false
		}
		packet = packet[40:]
	}
	return len(packet) >= 16 && len(request) >= 16 && packet[0] == replyType && packet[1] == 0 &&
		binary.BigEndian.Uint16(packet[4:6]) == binary.BigEndian.Uint16(request[4:6]) &&
		binary.BigEndian.Uint16(packet[6:8]) == binary.BigEndian.Uint16(request[6:8]) &&
		string(packet[8:16]) == string(request[8:16])
}

func icmp6Checksum(source, destination net.IP, message []byte) uint16 {
	var pseudo [40]byte
	copy(pseudo[:16], source)
	copy(pseudo[16:32], destination)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(message)))
	pseudo[39] = 58 // ICMPv6 next header
	var sum uint32
	for _, data := range [][]byte{pseudo[:], message} {
		for len(data) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
		}
		if len(data) == 1 {
			sum += uint32(data[0]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
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
