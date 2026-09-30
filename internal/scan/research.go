package scan

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
)

// runResearch is deliberately sequential: at most one outstanding raw probe
// is correlated at a time, and every transmitted fragment consumes rate budget.
func runResearch(ctx context.Context, cfg config.Config, emit func(Observation) error, open packetio.Opener) error {
	iface, lookupErr := net.InterfaceByName(cfg.Interface)
	var source netip.Addr
	var sourceMAC net.HardwareAddr
	if lookupErr == nil {
		if len(iface.HardwareAddr) != 6 {
			return fmt.Errorf("interface %s is not Ethernet", cfg.Interface)
		}
		var err error
		if cfg.Targets[0].Is4() {
			source, err = selectIPv4Source(iface, cfg.SourceIP)
		} else {
			source, err = selectIPv6Source(iface, cfg.SourceIP)
		}
		if err != nil {
			return err
		}
		sourceMAC = iface.HardwareAddr
		if len(cfg.SourceMAC) != 0 && string(cfg.SourceMAC) != string(sourceMAC) {
			return errors.New("research source MAC does not match interface")
		}
	} else {
		if !cfg.SourceIP.IsValid() || len(cfg.SourceMAC) != 6 {
			return errors.New("unmapped packet adapter requires --source-ip and --source-mac")
		}
		source, sourceMAC = cfg.SourceIP, cfg.SourceMAC
	}
	io, err := open(cfg.Interface)
	if err != nil {
		return fmt.Errorf("raw packet I/O on %s: %w", cfg.Interface, err)
	}
	defer io.Close()
	limiter := newScopedProbeLimiter(cfg)
	defer limiter.Close()
	var neighbors map[netip.Addr]net.HardwareAddr
	if len(cfg.NextHopMAC) == 0 {
		if source.Is6() {
			return errors.New("IPv6 research requires --next-hop-mac until automatic NDP routing is available")
		}
		neighbors, err = resolveNextHops(ctx, cfg, io, sourceMAC, source, limiter)
		if err != nil {
			return err
		}
	}
	return runResearchWithIO(ctx, cfg, emit, io, sourceMAC, source, neighbors, limiter)
}

func selectIPv6Source(iface *net.Interface, requested netip.Addr) (netip.Addr, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	var selected netip.Addr
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil || !p.Addr().Is6() || p.Addr().IsLinkLocalUnicast() {
			continue
		}
		if requested.IsValid() {
			if p.Addr() == requested {
				return requested, nil
			}
			continue
		}
		if selected.IsValid() {
			return netip.Addr{}, errors.New("interface has multiple IPv6 addresses; specify --source-ip")
		}
		selected = p.Addr()
	}
	if requested.IsValid() {
		return netip.Addr{}, errors.New("requested IPv6 source is not assigned to interface")
	}
	if !selected.IsValid() {
		return netip.Addr{}, errors.New("interface has no global IPv6 address")
	}
	return selected, nil
}

func runResearchWithIO(ctx context.Context, cfg config.Config, emit func(Observation) error, io packetio.PacketIO, sourceMAC net.HardwareAddr, source netip.Addr, neighbors map[netip.Addr]net.HardwareAddr, limiter *probeLimiter) error {
	if limiter == nil {
		limiter = newScopedProbeLimiter(cfg)
		defer limiter.Close()
	}
	for _, target := range cfg.Targets {
		ports := cfg.Ports
		if len(ports) == 0 {
			ports = []uint16{0}
		}
		for _, port := range ports {
			if err := ctx.Err(); err != nil {
				return err
			}
			t := task{target: target, port: port, transport: cfg.Research.Kind}
			o := researchProbe(ctx, cfg, t, io, sourceMAC, source, neighbors, limiter)
			if err := emit(o); err != nil {
				return err
			}
		}
	}
	return nil
}

func researchProbe(ctx context.Context, cfg config.Config, t task, io packetio.PacketIO, sourceMAC net.HardwareAddr, source netip.Addr, neighbors map[netip.Addr]net.HardwareAddr, limiter *probeLimiter) Observation {
	r := cfg.Research
	o := base(t, "forge-"+r.Kind)
	destMAC := cfg.NextHopMAC
	if len(destMAC) == 0 {
		destMAC = neighbors[t.target]
	}
	if len(destMAC) == 0 {
		o.State, o.Reason = "no-response", "next-hop ARP unanswered; no research packet sent"
		return o
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		o.State, o.Reason = "error", err.Error()
		return o
	}
	token := binary.BigEndian.Uint32(random[:4])
	if token == 0 {
		token = 1
	}
	sourcePort := uint16(49152 + binary.BigEndian.Uint16(random[4:6])%16384)
	protocol := map[string]uint8{"tcp": 6, "udp": 17, "icmp": 1, "sctp": 132, "ip": r.IPProtocol}[r.Kind]
	if r.Kind == "icmp" && source.Is6() {
		protocol = 58
	}
	payload := r.Payload
	if r.Kind == "icmp" {
		payload = make([]byte, 12+len(r.Payload))
		if source.Is6() {
			payload[0] = 128
		} else {
			payload[0] = 8
		}
		binary.BigEndian.PutUint16(payload[4:6], uint16(token>>16))
		binary.BigEndian.PutUint16(payload[6:8], uint16(token))
		copy(payload[8:], random[:4])
		copy(payload[12:], r.Payload)
	}
	s := packet.ForgeSpec{SourceMAC: sourceMAC, DestinationMAC: destMAC, SourceIP: source, DestinationIP: t.target,
		Protocol: protocol, RawProtocol: r.Kind == "ip", SourcePort: sourcePort, DestPort: t.port, TCPFlags: r.TCPFlags, Sequence: token, Window: 64240,
		Payload: payload, HopLimit: 64, ID: token, FragmentSize: r.FragmentSize, Malformed: r.BadChecksum || r.IPLength != 0, Experiment: true}
	if r.BadChecksum {
		s.CorruptChecksum = true
	}
	if r.Kind == "ip" {
		s.SourcePort, s.DestPort = 0, 0
	}
	if r.IPLength != 0 {
		length := r.IPLength
		s.IPLengthOverride = &length
	}
	frames, err := packet.ForgeFrames(s)
	if err != nil {
		o.State, o.Reason = "error", err.Error()
		return o
	}
	start := time.Now()
	for _, frame := range frames {
		if err := limiter.WaitFor(ctx, t.target); err != nil {
			o.State, o.Reason = "error", err.Error()
			return o
		}
		n, err := io.SendBatch(ctx, [][]byte{frame})
		o.PacketsTX += n
		if err != nil || n != 1 {
			o.State, o.Reason = "error", fmt.Sprintf("send research frame: %d/1: %v", n, err)
			return o
		}
	}
	deadline, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	buffer := make([]byte, 65535)
	for deadline.Err() == nil {
		batch := [][]byte{buffer}
		n, err := io.ReceiveBatch(deadline, batch)
		if n > 0 {
			p, ok := packet.DecodeResearch(batch[0])
			if ok {
				if state, confidence, reason, matched := matchResearch(p, s); matched {
					o.State, o.Confidence, o.Reason = state, confidence, reason
					o.PacketsRX, o.RTT = 1, time.Since(start)
					return o
				}
			}
		}
		if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			o.State, o.Reason = "error", err.Error()
			return o
		}
	}
	o.State, o.Confidence, o.Reason = "no-response", 50, "no correlated research reply"
	o.RTT = time.Since(start)
	return o
}

func matchResearch(p packet.ResearchDecoded, sent packet.ForgeSpec) (string, int, string, bool) {
	if p.Destination != sent.SourceIP {
		return "", 0, "", false
	}
	if (p.Protocol == 1 || p.Protocol == 58) && p.Quote.Valid {
		q := p.Quote
		if q.Source != sent.SourceIP || q.Destination != sent.DestinationIP || q.Protocol != sent.Protocol {
			return "", 0, "", false
		}
		if sent.SourceIP.Is4() && q.ID != uint16(sent.ID) {
			return "", 0, "", false
		}
		if sent.SourceIP.Is6() && q.FlowLabel != sent.ID&0xfffff {
			return "", 0, "", false
		}
		if !sent.RawProtocol && (sent.Protocol == 6 || sent.Protocol == 17 || sent.Protocol == 132) {
			if q.SourcePort != sent.SourcePort || q.DestPort != sent.DestPort {
				return "", 0, "", false
			}
			if sent.Protocol == 6 && q.Sequence != sent.Sequence {
				return "", 0, "", false
			}
		}
		if p.Protocol == 1 && p.ICMPType == 3 && p.ICMPCode == 2 {
			return "protocol-unreachable", 100, "matching ICMP protocol unreachable", true
		}
		if (p.Protocol == 1 && p.ICMPType == 3 && p.ICMPCode == 13) || (p.Protocol == 58 && p.ICMPType == 1 && p.ICMPCode == 1) {
			return "administratively-prohibited", 100, "matching ICMP administrative prohibition", true
		}
		return "responsive", 90, fmt.Sprintf("matching ICMP error type %d code %d", p.ICMPType, p.ICMPCode), true
	}
	if p.Source != sent.DestinationIP || p.Protocol != sent.Protocol {
		return "", 0, "", false
	}
	if sent.RawProtocol {
		return "responsive", 70, "reply with matching IP protocol; no transaction token", true
	}
	switch sent.Protocol {
	case 6:
		if p.SourcePort != sent.DestPort || p.DestPort != sent.SourcePort || p.TCPFlags&0x10 == 0 {
			return "", 0, "", false
		}
		advance := uint32(len(sent.Payload))
		if sent.TCPFlags&0x03 != 0 {
			advance++
		}
		if p.TCPAck != sent.Sequence+advance {
			return "", 0, "", false
		}
		if sent.TCPFlags == 2 && p.TCPFlags&0x12 == 0x12 {
			return "open", 100, "matching TCP SYN/ACK", true
		}
		if sent.TCPFlags == 2 && p.TCPFlags&0x04 != 0 {
			return "closed", 100, "matching TCP RST/ACK", true
		}
		return "responsive", 95, "matching TCP acknowledgment", true
	case 17:
		if p.SourcePort == sent.DestPort && p.DestPort == sent.SourcePort {
			return "responsive", 80, "matching UDP tuple; protocol payload not authenticated", true
		}
	case 132:
		if p.SourcePort == sent.DestPort && p.DestPort == sent.SourcePort && p.SCTPTag == sent.Sequence {
			if p.SCTPChunk == 2 {
				return "open", 100, "matching SCTP INIT ACK", true
			}
			if p.SCTPChunk == 6 {
				return "closed", 95, "matching SCTP ABORT", true
			}
		}
	case 1, 58:
		want := uint8(0)
		if sent.Protocol == 58 {
			want = 129
		}
		if p.ICMPType == want && len(sent.Payload) >= 8 && p.ICMPID == binary.BigEndian.Uint16(sent.Payload[4:6]) && p.ICMPSeq == binary.BigEndian.Uint16(sent.Payload[6:8]) {
			return "responsive", 100, "matching ICMP echo reply", true
		}
	default:
		return "responsive", 70, "reply with matching IP protocol; no transaction token", true
	}
	return "", 0, "", false
}
