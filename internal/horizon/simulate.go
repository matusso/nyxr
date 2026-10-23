package horizon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
)

// Simulator is a bounded in-memory PacketIO fixture. It never opens sockets.
// Its replies are synthetic and must not be used as network ground truth.
type Simulator struct {
	mu       sync.Mutex
	scenario string
	queue    chan []byte
	stats    packetio.Stats
	closed   bool
	// Limiter scenarios: one-token buckets refilled after limiterRefill,
	// shared across ports or kept per destination port.
	tokens map[uint16]time.Time
}

const limiterRefill = 250 * time.Millisecond

func NewSimulator(scenario string) (*Simulator, error) {
	switch scenario {
	case "sack", "stable", "loss", "noise", "shared-limit", "port-limit":
	default:
		return nil, fmt.Errorf("unknown simulation %q (sack, stable, loss, noise, shared-limit, port-limit)", scenario)
	}
	return &Simulator{scenario: scenario, queue: make(chan []byte, 4), tokens: map[uint16]time.Time{}}, nil
}

func (s *Simulator) SendBatch(ctx context.Context, frames [][]byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.closed {
		return 0, errors.New("simulator closed")
	}
	for i, frame := range frames {
		p, ok := packet.NewDecoder().Decode(frame)
		if !ok || p.Protocol != "tcp" {
			return i, errors.New("simulator requires TCP")
		}
		s.stats.Sent++
		if p.TCPFlags != 2 || s.scenario == "loss" || !s.admit(p.DestPort) {
			continue
		}
		withSack := s.scenario == "sack" && sack(p.TCPOptions[:p.TCPOptionsLen])
		reply, err := syntheticReply(frame, p, withSack)
		if err != nil {
			return i + 1, err
		}
		copies := 1
		if s.scenario == "noise" {
			copies = 2
		}
		for j := 0; j < copies; j++ {
			select {
			case s.queue <- reply:
			default:
				s.stats.Dropped++
			}
		}
	}
	return len(frames), nil
}

// admit spends the bucket token for a SYN in limiter scenarios.
func (s *Simulator) admit(port uint16) bool {
	if s.scenario != "shared-limit" && s.scenario != "port-limit" {
		return true
	}
	if s.scenario == "shared-limit" {
		if port != 443 && port != 8443 {
			return true
		}
		port = 0 // one bucket shared by 443 and 8443
	}
	now := time.Now()
	if next, ok := s.tokens[port]; ok && now.Before(next) {
		return false
	}
	s.tokens[port] = now.Add(limiterRefill)
	return true
}

func syntheticReply(frame []byte, p packet.Decoded, withSack bool) ([]byte, error) {
	eth := &layers.Ethernet{SrcMAC: frame[:6], DstMAC: frame[6:12]}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(p.DestPort), DstPort: layers.TCPPort(p.SourcePort), Seq: 12345, Ack: p.TCPSeq + 1, SYN: true, ACK: true, Window: 64240}
	tcp.Options = []layers.TCPOption{{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{5, 180}}}
	if withSack {
		tcp.Options = append(tcp.Options, layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2})
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	var err error
	if p.Source.Is4() {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: p.Destination.AsSlice(), DstIP: p.Source.AsSlice(), Flags: layers.IPv4DontFragment}
		if err = tcp.SetNetworkLayerForChecksum(ip); err == nil {
			err = gopacket.SerializeLayers(buf, opts, eth, ip, tcp)
		}
	} else {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP, SrcIP: p.Destination.AsSlice(), DstIP: p.Source.AsSlice()}
		if err = tcp.SetNetworkLayerForChecksum(ip); err == nil {
			err = gopacket.SerializeLayers(buf, opts, eth, ip, tcp)
		}
	}
	return buf.Bytes(), err
}

func (s *Simulator) ReceiveBatch(ctx context.Context, buffers [][]byte) (int, error) {
	if len(buffers) == 0 {
		return 0, nil
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case frame := <-s.queue:
		if len(buffers[0]) < len(frame) {
			return 0, errors.New("short receive buffer")
		}
		buffers[0] = buffers[0][:copy(buffers[0], frame)]
		s.mu.Lock()
		s.stats.Received++
		s.mu.Unlock()
		return 1, nil
	}
}
func (s *Simulator) Stats() packetio.Stats { s.mu.Lock(); defer s.mu.Unlock(); return s.stats }
func (s *Simulator) Close() error          { s.mu.Lock(); defer s.mu.Unlock(); s.closed = true; return nil }
