package scan

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
)

var (
	v6Source   = netip.MustParseAddr("2001:db8:1::10")
	v6Target   = netip.MustParseAddr("2001:db8:2::20")
	v6Router   = netip.MustParseAddr("fe80::1")
	v6LocalMAC = net.HardwareAddr{2, 1, 2, 3, 4, 5}
	v6PeerMAC  = net.HardwareAddr{2, 6, 7, 8, 9, 10}
)

// fakeIPv6IO answers each transmitted frame with respond's frames.
type fakeIPv6IO struct {
	frames       chan []byte
	respond      func([]byte) [][]byte
	mu           sync.Mutex
	sent         int
	destinations []net.HardwareAddr
}

func (f *fakeIPv6IO) ReceiveBatch(ctx context.Context, buffers [][]byte) (int, error) {
	select {
	case frame := <-f.frames:
		copy(buffers[0], frame)
		buffers[0] = buffers[0][:len(frame)]
		return 1, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (f *fakeIPv6IO) SendBatch(_ context.Context, frames [][]byte) (int, error) {
	for _, frame := range frames {
		f.mu.Lock()
		f.sent++
		f.destinations = append(f.destinations, append(net.HardwareAddr(nil), frame[:6]...))
		f.mu.Unlock()
		if f.respond != nil {
			for _, reply := range f.respond(append([]byte(nil), frame...)) {
				f.frames <- reply
			}
		}
	}
	return len(frames), nil
}
func (f *fakeIPv6IO) Stats() packetio.Stats { return packetio.Stats{} }
func (f *fakeIPv6IO) Close() error          { return nil }

// ipv6TCPReply mirrors a SYN as the target's reply. ext is a raw extension
// chain whose first header type is nh; its last header must name TCP (6).
func ipv6TCPReply(request []byte, flags byte, nh byte, ext []byte) []byte {
	tcp := append([]byte(nil), request[54:]...)
	copy(tcp[0:2], request[56:58])
	copy(tcp[2:4], request[54:56])
	binary.BigEndian.PutUint32(tcp[8:12], binary.BigEndian.Uint32(request[58:62])+1)
	binary.BigEndian.PutUint32(tcp[4:8], 0x01020304)
	tcp[13] = flags
	if nh == 0 && len(ext) == 0 {
		nh = 6
	}
	frame := make([]byte, 54, 54+len(ext)+len(tcp))
	copy(frame[:6], request[6:12])
	copy(frame[6:12], request[:6])
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
	frame[14] = 0x60
	binary.BigEndian.PutUint16(frame[18:20], uint16(len(ext)+len(tcp)))
	frame[20], frame[21] = nh, 64
	copy(frame[22:38], request[38:54])
	copy(frame[38:54], request[22:38])
	frame = append(frame, ext...)
	return append(frame, tcp...)
}

// ipv6Unreachable quotes the whole SYN in an ICMPv6 destination unreachable.
func ipv6Unreachable(request []byte, code byte) []byte {
	icmp := append([]byte{1, code, 0, 0, 0, 0, 0, 0}, request[14:]...)
	router := netip.MustParseAddr("2001:db8:1::fe").As16()
	frame := make([]byte, 54, 54+len(icmp))
	copy(frame[:6], request[6:12])
	copy(frame[6:12], request[:6])
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
	frame[14] = 0x60
	binary.BigEndian.PutUint16(frame[18:20], uint16(len(icmp)))
	frame[20], frame[21] = 58, 64
	copy(frame[22:38], router[:])
	copy(frame[38:54], request[22:38])
	binary.BigEndian.PutUint16(icmp[2:4], testICMPv6Checksum(frame[22:38], frame[38:54], icmp))
	return append(frame, icmp...)
}

// ipv6Advertisement answers a neighbor solicitation for target with mac.
func ipv6Advertisement(request []byte, mac net.HardwareAddr) []byte {
	reply := append([]byte(nil), request...)
	target := reply[62:78]
	copy(reply[:6], request[6:12])
	copy(reply[6:12], mac)
	copy(reply[38:54], request[22:38])
	copy(reply[22:38], target)
	reply[54], reply[56], reply[57] = 136, 0, 0
	reply[58] = 0x60 // solicited, override
	reply[78], reply[79] = 2, 1
	copy(reply[80:86], mac)
	binary.BigEndian.PutUint16(reply[56:58], testICMPv6Checksum(reply[22:38], reply[38:54], reply[54:]))
	return reply
}

func isIPv6SYN(frame []byte) bool {
	return len(frame) >= 74 && binary.BigEndian.Uint16(frame[12:14]) == 0x86dd && frame[20] == 6
}

func runIPv6SYN(t *testing.T, cfg config.Config, respond func([]byte) [][]byte) ([]Observation, *fakeIPv6IO) {
	t.Helper()
	fake := &fakeIPv6IO{frames: make(chan []byte, 64), respond: respond}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Millisecond
	}
	cfg.TCP, cfg.TCPMode, cfg.Workers = true, "syn", 2
	if len(cfg.NextHopMAC) == 0 {
		cfg.NextHopMAC = v6PeerMAC
	}
	var got []Observation
	err := runSYNWithIO(context.Background(), cfg, func(o Observation) error { got = append(got, o); return nil }, fake, v6LocalMAC, v6Source)
	if err != nil {
		t.Fatal(err)
	}
	return got, fake
}

func TestIPv6SYNClassifiesOpenClosedFilteredAndICMPv6(t *testing.T) {
	stale := func(reply []byte) []byte {
		wrong := append([]byte(nil), reply...)
		binary.BigEndian.PutUint32(wrong[62:66], 0) // ack of a token never sent
		return wrong
	}
	for _, tc := range []struct {
		name    string
		respond func([]byte) [][]byte
		state   string
		reason  string
	}{
		{"open", func(r []byte) [][]byte {
			reply := ipv6TCPReply(r, 0x12, 0, nil)
			return [][]byte{stale(reply), reply}
		}, "open", "SYN/ACK"},
		{"closed", func(r []byte) [][]byte { return [][]byte{ipv6TCPReply(r, 0x14, 0, nil)} }, "closed", "RST/ACK"},
		{"silent", func([]byte) [][]byte { return nil }, "filtered", "timed out"},
		{"unreachable", func(r []byte) [][]byte { return [][]byte{ipv6Unreachable(r, 1)} }, "filtered", "ICMPv6 destination unreachable (code 1)"},
		{"stale-only", func(r []byte) [][]byte { return [][]byte{stale(ipv6TCPReply(r, 0x12, 0, nil))} }, "filtered", "timed out"},
	} {
		got, fake := runIPv6SYN(t, config.Config{Targets: []netip.Addr{v6Target}, Ports: []uint16{443}}, tc.respond)
		if len(got) != 1 || fake.sent != 1 || got[0].State != tc.state || !strings.Contains(got[0].Reason, tc.reason) || got[0].Target != v6Target {
			t.Fatalf("%s: %+v sent=%d", tc.name, got, fake.sent)
		}
	}
}

func TestIPv6SYNBoundedExtensionHeaders(t *testing.T) {
	hopByHop := []byte{60, 0, 1, 4, 0, 0, 0, 0}
	destination := []byte{6, 0, 1, 4, 0, 0, 0, 0}
	chain := append(append([]byte(nil), hopByHop...), destination...)
	got, _ := runIPv6SYN(t, config.Config{Targets: []netip.Addr{v6Target}, Ports: []uint16{22}}, func(r []byte) [][]byte {
		return [][]byte{ipv6TCPReply(r, 0x12, 0, chain)}
	})
	if len(got) != 1 || got[0].State != "open" {
		t.Fatalf("extension chain reply: %+v", got)
	}
	var long []byte
	for range 9 {
		long = append(long, 60, 0, 1, 4, 0, 0, 0, 0)
	}
	long[len(long)-8] = 6
	fragment := []byte{6, 0, 0, 0, 0, 0, 0, 1}
	for name, reply := range map[string]func([]byte) []byte{
		"fragment":   func(r []byte) []byte { return ipv6TCPReply(r, 0x12, 44, fragment) },
		"nine-hops":  func(r []byte) []byte { return ipv6TCPReply(r, 0x12, 60, long) },
		"truncated":  func(r []byte) []byte { return ipv6TCPReply(r, 0x12, 0, hopByHop[:4]) },
		"esp-hidden": func(r []byte) []byte { return ipv6TCPReply(r, 0x12, 50, destination) },
	} {
		got, _ := runIPv6SYN(t, config.Config{Targets: []netip.Addr{v6Target}, Ports: []uint16{22}}, func(r []byte) [][]byte { return [][]byte{reply(r)} })
		if len(got) != 1 || got[0].State != "filtered" || got[0].PacketsRX != 0 {
			t.Fatalf("%s reply was accepted: %+v", name, got)
		}
	}
}

func TestIPv6SYNStackEvidenceOmitsIPv4Fields(t *testing.T) {
	got, fake := runIPv6SYN(t, config.Config{Targets: []netip.Addr{v6Target}, Ports: []uint16{443}, StackFingerprint: true}, func(r []byte) [][]byte {
		reply := ipv6TCPReply(r, 0x52, 0, nil)
		out := [][]byte{reply}
		for range 10 {
			out = append(out, append([]byte(nil), reply...))
		}
		return out
	})
	if len(got) != 1 || fake.sent != 1 {
		t.Fatalf("fingerprint scan: %+v", got)
	}
	f := got[0].TCPStack
	if got[0].State != "open" || f == nil || f.ProbeProfile != "nyxr-syn6-v1" || !strings.HasPrefix(f.Signature, "nx_tcp6_v1_") ||
		f.IPIDBehavior != "not-applicable" || len(f.Samples) != 8 || !f.Truncated || got[0].PacketsRX != 11 {
		t.Fatalf("IPv6 stack evidence: %+v", f)
	}
	s := f.Samples[0]
	if s.IPVersion != 6 || s.DF != nil || s.IPID != nil || s.InitialTTL != 64 || s.MSS == nil || *s.MSS != 1440 {
		t.Fatalf("IPv6 sample: %+v", s)
	}
	// A truncated collection never claims a family; the same reply does
	// once, and its reason speaks of hop limit rather than TTL.
	got, _ = runIPv6SYN(t, config.Config{Targets: []netip.Addr{v6Target}, Ports: []uint16{443}, StackFingerprint: true}, func(r []byte) [][]byte {
		return [][]byte{ipv6TCPReply(r, 0x52, 0, nil)}
	})
	f = got[0].TCPStack
	if f == nil || len(f.Candidates) != 1 || f.Candidates[0].Family != "Linux" || !strings.Contains(strings.Join(f.Candidates[0].Reasons, " "), "hop limit 64") {
		t.Fatalf("IPv6 candidate: %+v", f)
	}
}

func TestIPv6SYNRejectsWrongTuple(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"source":      func(b []byte) { b[37] ^= 1 },
		"destination": func(b []byte) { b[53] ^= 1 },
		"port":        func(b []byte) { b[55] ^= 1 },
	} {
		got, _ := runIPv6SYN(t, config.Config{Targets: []netip.Addr{v6Target}, Ports: []uint16{443}, StackFingerprint: true}, func(r []byte) [][]byte {
			reply := ipv6TCPReply(r, 0x12, 0, nil)
			mutate(reply)
			return [][]byte{reply}
		})
		if len(got) != 1 || got[0].State != "filtered" || got[0].TCPStack != nil {
			t.Fatalf("%s mismatch accepted: %+v", name, got)
		}
	}
}

func TestIPv6SYNResolvesNextHopsByNDP(t *testing.T) {
	silentRouter := netip.MustParseAddr("fe80::2")
	far := netip.MustParseAddr("2001:db8:3::30")
	onLink := netip.MustParseAddr("fe80::20")
	linkLocal := netip.MustParseAddr("fe80::10")
	lookup := func(target netip.Addr) (netip.Addr, error) {
		switch {
		case target.IsLinkLocalUnicast():
			return target, nil
		case target == far:
			return silentRouter, nil
		}
		return v6Router, nil
	}
	answers := map[netip.Addr]net.HardwareAddr{v6Router: v6PeerMAC, onLink: {2, 9, 9, 9, 9, 9}}
	var mu sync.Mutex
	solicitations := map[netip.Addr]netip.Addr{} // hop -> NS source
	neighbor := &fakeIPv6IO{frames: make(chan []byte, 16)}
	neighbor.respond = func(r []byte) [][]byte {
		if len(r) < 86 || r[54] != 135 {
			return nil
		}
		hop := netip.AddrFrom16([16]byte(r[62:78]))
		mu.Lock()
		solicitations[hop] = netip.AddrFrom16([16]byte(r[22:38]))
		mu.Unlock()
		if mac := answers[hop]; mac != nil {
			return [][]byte{ipv6Advertisement(r, mac)}
		}
		return nil
	}
	cfg := config.Config{Interface: "en0", Timeout: 200 * time.Millisecond}
	solicitFrom := func(hop netip.Addr) netip.Addr {
		if hop.IsLinkLocalUnicast() {
			return linkLocal
		}
		return v6Source
	}
	cache := map[netip.Addr]net.HardwareAddr{}
	got, err := resolveIPv6NextHops(context.Background(), cfg, neighbor, v6LocalMAC, v6Source, solicitFrom, newProbeLimiter(0),
		lookup, cache, []netip.Addr{v6Target, far, onLink})
	if err != nil || string(got[v6Target]) != string(v6PeerMAC) || got[far] != nil || string(got[onLink]) != string(answers[onLink]) {
		t.Fatalf("NDP next hops: %+v %v", got, err)
	}
	if solicitations[v6Router] != linkLocal || solicitations[onLink] != linkLocal {
		t.Fatalf("link-local hops must be solicited from the link-local source: %+v", solicitations)
	}
	sent := neighbor.sent
	if _, err := resolveIPv6NextHops(context.Background(), cfg, neighbor, v6LocalMAC, v6Source, solicitFrom, newProbeLimiter(0),
		lookup, cache, []netip.Addr{v6Target}); err != nil || neighbor.sent != sent {
		t.Fatalf("cached router re-solicited: sent %d->%d %v", sent, neighbor.sent, err)
	}

	// The engine sends only to resolved hops and reports the rest unsent.
	syn := &fakeIPv6IO{frames: make(chan []byte, 16), respond: func(r []byte) [][]byte {
		if isIPv6SYN(r) {
			return [][]byte{ipv6TCPReply(r, 0x14, 0, nil)}
		}
		return nil
	}}
	scan := config.Config{Interface: "en0", Targets: []netip.Addr{v6Target, far}, Ports: []uint16{80}, TCP: true, TCPMode: "syn", Timeout: 50 * time.Millisecond, Workers: 1}
	resolve := func(ctx context.Context, chunk []netip.Addr) (map[netip.Addr]net.HardwareAddr, error) {
		return resolveIPv6NextHops(ctx, scan, neighbor, v6LocalMAC, v6Source, solicitFrom, newProbeLimiter(0), lookup, cache, chunk)
	}
	var obs []Observation
	if err := runSYNAsync(context.Background(), scan, func(o Observation) error { obs = append(obs, o); return nil }, syn, v6LocalMAC, v6Source, nil, nil, resolve); err != nil {
		t.Fatal(err)
	}
	states := map[netip.Addr]Observation{}
	for _, o := range obs {
		states[o.Target] = o
	}
	if states[v6Target].State != "closed" || states[far].State != "no-response" || !strings.Contains(states[far].Reason, "NDP") ||
		syn.sent != 1 || string(syn.destinations[0]) != string(v6PeerMAC) {
		t.Fatalf("NDP-resolved SYN: %+v sent=%d", obs, syn.sent)
	}
}

func TestIPv6SYNScopesAndSources(t *testing.T) {
	targets, zones, err := unscopedSYN6Targets([]netip.Addr{
		netip.MustParseAddr("fe80::20%en0"), netip.MustParseAddr("fe80::20"), v6Target}, "en0")
	if err != nil || len(targets) != 2 || targets[0].Zone() != "" || zones[netip.MustParseAddr("fe80::20")] != "en0" || zones[v6Target] != "" {
		t.Fatalf("unscoped targets: %v %v %v", targets, zones, err)
	}
	for _, bad := range []string{"fe80::20%en1", "2001:db8::1%en0"} {
		if _, _, err := unscopedSYN6Targets([]netip.Addr{netip.MustParseAddr(bad)}, "en0"); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	addrs := []netip.Prefix{
		netip.MustParsePrefix("fe80::10/64"),
		netip.MustParsePrefix("2001:db8:1::10/64"),
		netip.MustParsePrefix("2001:db8:2::10/64"),
		netip.MustParsePrefix("fd00::10/64"),
	}
	groups, err := groupIPv6Sources("en0", addrs, netip.Addr{}, []netip.Addr{
		netip.MustParseAddr("fe80::20"), netip.MustParseAddr("2001:db8:2::99"), netip.MustParseAddr("fd00::99"), netip.MustParseAddr("2001:db8:9::1")})
	if err != nil || len(groups) != 4 {
		t.Fatalf("groups: %+v %v", groups, err)
	}
	bySource := map[netip.Addr][]netip.Addr{}
	for _, g := range groups {
		bySource[g.source] = g.targets
	}
	if bySource[netip.MustParseAddr("fe80::10")][0] != netip.MustParseAddr("fe80::20") ||
		bySource[netip.MustParseAddr("2001:db8:2::10")][0] != netip.MustParseAddr("2001:db8:2::99") ||
		bySource[netip.MustParseAddr("fd00::10")][0] != netip.MustParseAddr("fd00::99") ||
		bySource[netip.MustParseAddr("2001:db8:1::10")][0] != netip.MustParseAddr("2001:db8:9::1") {
		t.Fatalf("source selection: %+v", bySource)
	}
	if _, err := groupIPv6Sources("en0", addrs[:1], netip.Addr{}, []netip.Addr{v6Target}); err == nil || !strings.Contains(err.Error(), "no global") {
		t.Fatalf("link-local-only interface accepted a global target: %v", err)
	}
	if _, err := groupIPv6Sources("en0", addrs, netip.MustParseAddr("2001:db8::99"), []netip.Addr{v6Target}); err == nil {
		t.Fatal("accepted an unassigned source")
	}
}

func TestIPv6SYNNpcapPathKeepsZoneAndRejectsXDP(t *testing.T) {
	scoped := netip.MustParseAddr("fe80::20%npcap-test0")
	fake := &fakeIPv6IO{frames: make(chan []byte, 8)}
	fake.respond = func(r []byte) [][]byte {
		if isIPv6SYN(r) {
			return [][]byte{ipv6TCPReply(r, 0x12, 0, nil)}
		}
		return nil
	}
	cfg := config.Config{Interface: "npcap-test0", Targets: []netip.Addr{scoped}, Ports: []uint16{22}, TCP: true, TCPMode: "syn",
		Timeout: 30 * time.Millisecond, Workers: 1, SourceIP: netip.MustParseAddr("fe80::10"), SourceMAC: v6LocalMAC, NextHopMAC: v6PeerMAC}
	var got []Observation
	opener := func(string) (packetio.PacketIO, error) { return fake, nil }
	if err := runSYN(context.Background(), cfg, func(o Observation) error { got = append(got, o); return nil }, opener); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].State != "open" || got[0].Target != scoped {
		t.Fatalf("scoped observation: %+v", got)
	}
	cfg.XDPPinDir = "/sys/fs/bpf/nyxr"
	if err := runSYN(context.Background(), cfg, func(Observation) error { return nil }, opener); err == nil || !strings.Contains(err.Error(), "AF_XDP") {
		t.Fatalf("XDP accepted for IPv6: %v", err)
	}
	cfg.XDPPinDir, cfg.SourceIP = "", netip.Addr{}
	if err := runSYN(context.Background(), cfg, func(Observation) error { return nil }, opener); err == nil || !strings.Contains(err.Error(), "Npcap") {
		t.Fatalf("missing explicit Npcap addressing: %v", err)
	}
}

func TestCandidateSYNFrameIPv6(t *testing.T) {
	tmpl, err := packet.NewSYNTemplate(v6LocalMAC, v6PeerMAC, v6Source, 50000)
	if err != nil {
		t.Fatal(err)
	}
	request := tmpl.Frame(v6Target, 443, 7)
	reply := ipv6TCPReply(request, 0x12, 0, nil)
	if !candidateSYNFrame(reply, v6Source) || candidateSYNFrame(reply, v6Target) || candidateSYNFrame(request, v6Source) {
		t.Fatal("IPv6 candidate filter")
	}
	if candidateSYNFrame(reply, netip.MustParseAddr("192.0.2.10")) {
		t.Fatal("IPv6 frame matched an IPv4 source")
	}
}
