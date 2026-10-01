package scan

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
)

type fakePacketIO struct {
	frames       chan []byte
	flags        byte
	stale        bool
	mu           sync.Mutex
	sent         int
	maxBatch     int
	destinations []net.HardwareAddr
	arpReplies   map[netip.Addr]net.HardwareAddr
}

func (f *fakePacketIO) ReceiveBatch(ctx context.Context, buffers [][]byte) (int, error) {
	select {
	case frame := <-f.frames:
		copy(buffers[0], frame)
		buffers[0] = buffers[0][:len(frame)]
		return 1, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}
func (f *fakePacketIO) SendBatch(ctx context.Context, frames [][]byte) (int, error) {
	f.mu.Lock()
	if len(frames) > f.maxBatch {
		f.maxBatch = len(frames)
	}
	f.mu.Unlock()
	for _, frame := range frames {
		f.sendFrame(frame)
	}
	return len(frames), nil
}

func TestRawSYNHasManyProbesInFlight(t *testing.T) {
	ports := make([]uint16, 100)
	for i := range ports {
		ports[i] = uint16(20000 + i)
	}
	fake := &fakePacketIO{frames: make(chan []byte)}
	cfg := config.Config{Targets: []netip.Addr{netip.MustParseAddr("198.51.100.20")}, Ports: ports,
		TCP: true, TCPMode: "syn", Timeout: 100 * time.Millisecond, Workers: 1,
		NextHopMAC: net.HardwareAddr{6, 5, 4, 3, 2, 1}}
	start := time.Now()
	var count int
	err := runSYNWithIO(context.Background(), cfg, func(o Observation) error {
		count++
		if o.State != "filtered" || o.PacketsTX != 1 {
			t.Errorf("observation: %+v", o)
		}
		return nil
	}, fake, net.HardwareAddr{1, 2, 3, 4, 5, 6}, netip.MustParseAddr("192.0.2.10"))
	if err != nil || count != 100 || fake.sent != 100 || fake.maxBatch < 2 || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("count=%d sent=%d batch=%d elapsed=%s err=%v", count, fake.sent, fake.maxBatch, time.Since(start), err)
	}
}
func (f *fakePacketIO) sendFrame(frame []byte) {
	f.mu.Lock()
	f.sent++
	f.destinations = append(f.destinations, append(net.HardwareAddr(nil), frame[:6]...))
	f.mu.Unlock()
	if len(frame) >= 42 && binary.BigEndian.Uint16(frame[12:14]) == 0x0806 && f.arpReplies != nil {
		request := frame
		hop := netip.AddrFrom4([4]byte(request[38:42]))
		if mac := f.arpReplies[hop]; len(mac) == 6 {
			reply := append([]byte(nil), request...)
			copy(reply[:6], request[6:12])
			copy(reply[6:12], mac)
			binary.BigEndian.PutUint16(reply[20:22], 2)
			copy(reply[22:28], mac)
			copy(reply[28:32], request[38:42])
			copy(reply[32:38], request[22:28])
			copy(reply[38:42], request[28:32])
			f.frames <- reply
		}
	}
	if f.flags != 0 {
		request := frame
		reply := make([]byte, len(request))
		copy(reply, request)
		copy(reply[:6], request[6:12])
		copy(reply[6:12], request[:6])
		copy(reply[26:30], request[30:34])
		copy(reply[30:34], request[26:30])
		copy(reply[34:36], request[36:38])
		copy(reply[36:38], request[34:36])
		binary.BigEndian.PutUint32(reply[42:46], binary.BigEndian.Uint32(request[38:42])+1)
		reply[47] = f.flags
		if f.stale {
			wrong := append([]byte(nil), reply...)
			binary.BigEndian.PutUint32(wrong[42:46], 0)
			f.frames <- wrong
		}
		f.frames <- reply
	}
}
func (f *fakePacketIO) Stats() packetio.Stats { return packetio.Stats{} }
func (f *fakePacketIO) Close() error          { return nil }

func TestRawSYNMatchesOnlyCurrentToken(t *testing.T) {
	for _, tc := range []struct {
		flags byte
		want  string
	}{{0x12, "open"}, {0x14, "closed"}, {0, "filtered"}} {
		fake := &fakePacketIO{frames: make(chan []byte, 8), flags: tc.flags, stale: true}
		cfg := config.Config{Targets: []netip.Addr{netip.MustParseAddr("198.51.100.20")}, Ports: []uint16{443}, TCP: true, TCPMode: "syn", Timeout: 20 * time.Millisecond, Workers: 1, NextHopMAC: net.HardwareAddr{6, 5, 4, 3, 2, 1}}
		var got []Observation
		err := runSYNWithIO(context.Background(), cfg, func(o Observation) error { got = append(got, o); return nil }, fake, net.HardwareAddr{1, 2, 3, 4, 5, 6}, netip.MustParseAddr("192.0.2.10"))
		if err != nil || len(got) != 1 || got[0].State != tc.want || got[0].PacketsTX != 1 {
			t.Fatalf("flags %x: observations %+v, error %v", tc.flags, got, err)
		}
		if tc.flags != 0 && got[0].PacketsRX != 1 {
			t.Fatalf("invalid reply count: %+v", got[0])
		}
		if fake.sent != 1 {
			t.Fatalf("sent %d probes", fake.sent)
		}
	}
}

func TestRawSYNShardedWorkers(t *testing.T) {
	fake := &fakePacketIO{frames: make(chan []byte, 16), flags: 0x12}
	cfg := config.Config{Targets: []netip.Addr{netip.MustParseAddr("198.51.100.20"), netip.MustParseAddr("198.51.100.21")}, Ports: []uint16{80, 443}, TCP: true, TCPMode: "syn", Timeout: time.Second, Workers: 4, NextHopMAC: net.HardwareAddr{6, 5, 4, 3, 2, 1}}
	var got []Observation
	err := runSYNWithIO(context.Background(), cfg, func(o Observation) error { got = append(got, o); return nil }, fake, net.HardwareAddr{1, 2, 3, 4, 5, 6}, netip.MustParseAddr("192.0.2.10"))
	if err != nil || len(got) != 4 || fake.sent != 4 {
		t.Fatalf("observations %+v, sent %d, error %v", got, fake.sent, err)
	}
	for _, o := range got {
		if o.State != "open" || o.PacketsRX != 1 {
			t.Fatalf("sharded reply = %+v", o)
		}
	}
}

func TestRawSYNUsesResolvedMACPerTarget(t *testing.T) {
	first := netip.MustParseAddr("198.51.100.20")
	second := netip.MustParseAddr("198.51.100.21")
	mac1 := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	mac2 := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	fake := &fakePacketIO{frames: make(chan []byte, 16), flags: 0x12}
	cfg := config.Config{Targets: []netip.Addr{first, second}, Ports: []uint16{80}, TCP: true,
		TCPMode: "syn", Timeout: time.Second, Workers: 1}
	var got []Observation
	err := runSYNWithIOResolved(context.Background(), cfg, func(o Observation) error {
		got = append(got, o)
		return nil
	}, fake, net.HardwareAddr{2, 1, 2, 3, 4, 5}, netip.MustParseAddr("192.0.2.10"),
		map[netip.Addr]net.HardwareAddr{first: mac1, second: mac2}, nil)
	if err != nil || len(got) != 2 || len(fake.destinations) != 2 ||
		string(fake.destinations[0]) != string(mac1) || string(fake.destinations[1]) != string(mac2) {
		t.Fatalf("resolved destinations: %+v, %+v, %v", got, fake.destinations, err)
	}
}

func TestRawSYNAfterARPResolution(t *testing.T) {
	target := netip.MustParseAddr("192.0.2.20")
	source := netip.MustParseAddr("192.0.2.10")
	sourceMAC := net.HardwareAddr{2, 1, 2, 3, 4, 5}
	targetMAC := net.HardwareAddr{2, 6, 7, 8, 9, 10}
	fake := &fakePacketIO{frames: make(chan []byte, 8), flags: 0x12}
	arpFake := &fakePacketIO{frames: make(chan []byte, 8),
		arpReplies: map[netip.Addr]net.HardwareAddr{target: targetMAC}}
	cfg := config.Config{Targets: []netip.Addr{target}, Ports: []uint16{80}, TCP: true,
		TCPMode: "syn", Timeout: time.Second, Workers: 1}
	limiter := newProbeLimiter(0)
	resolve := func(ctx context.Context, targets []netip.Addr) (map[netip.Addr]net.HardwareAddr, error) {
		chunk := cfg
		chunk.Targets = targets
		return resolveNextHopsWithLookup(ctx, chunk, arpFake, sourceMAC, source, limiter,
			func(a netip.Addr) (netip.Addr, error) { return a, nil },
			func(string, netip.Addr) net.HardwareAddr { return nil })
	}
	var got []Observation
	err := runSYNAsync(context.Background(), cfg, func(o Observation) error { got = append(got, o); return nil },
		fake, sourceMAC, source, nil, limiter, resolve)
	if err != nil || len(got) != 1 || got[0].State != "open" || got[0].PacketsTX != 1 ||
		arpFake.sent != 1 || fake.sent != 1 || string(fake.destinations[0]) != string(targetMAC) {
		t.Fatalf("ARP then SYN: observations=%+v arp=%d syn=%d destinations=%v err=%v", got, arpFake.sent, fake.sent, fake.destinations, err)
	}
}

func TestSYNICMPQuoteRequiresCurrentToken(t *testing.T) {
	target := netip.MustParseAddr("198.51.100.20")
	source := netip.MustParseAddr("192.0.2.10")
	task := task{target: target, port: 443, transport: "tcp"}
	responses := make(chan packet.Decoded, 2)
	base := packet.Decoded{Protocol: "icmp", ICMPType: 3, ICMPCode: 13, Destination: source, Quote: packet.QuotedTCP{Source: source, Destination: target, SourcePort: 50000, DestPort: 443, Sequence: 7, Valid: true}}
	responses <- base
	base.Quote.Sequence = 8
	responses <- base
	got := waitSYN(context.Background(), responses, task, source, 50000, 8, time.Now(), time.Second, Observation{})
	if got.State != "filtered" || got.PacketsRX != 1 || got.Confidence != 95 {
		t.Fatalf("ICMP match = %+v", got)
	}
}

func TestCandidateSYNFrameFiltersUnrelatedTraffic(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.10")
	target := netip.MustParseAddr("198.51.100.20")
	tmpl, err := packet.NewSYNTemplate(net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.HardwareAddr{6, 5, 4, 3, 2, 1}, target, 443)
	if err != nil {
		t.Fatal(err)
	}
	frame := append([]byte(nil), tmpl.Frame(source, 50000, 7)...)
	if !candidateSYNFrame(frame, source) {
		t.Fatal("missed local IPv4 frame")
	}
	if candidateSYNFrame(frame, target) {
		t.Fatal("accepted unrelated destination")
	}
	vlan := make([]byte, len(frame)+4)
	copy(vlan[:12], frame[:12])
	binary.BigEndian.PutUint16(vlan[12:14], 0x8100)
	binary.BigEndian.PutUint16(vlan[16:18], 0x0800)
	copy(vlan[18:], frame[14:])
	if !candidateSYNFrame(vlan, source) {
		t.Fatal("missed tagged frame")
	}
}
