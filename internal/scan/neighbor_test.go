package scan

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/packet"
)

func TestARPNeighborMatchesReply(t *testing.T) {
	local, target := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20")
	localMAC := net.HardwareAddr{2, 1, 2, 3, 4, 5}
	targetMAC := net.HardwareAddr{2, 6, 7, 8, 9, 10}
	request, err := packet.ARPRequest(localMAC, local, target)
	if err != nil {
		t.Fatal(err)
	}
	reply := append([]byte(nil), request...)
	copy(reply[:6], localMAC)
	copy(reply[6:12], targetMAC)
	binary.BigEndian.PutUint16(reply[20:22], 2)
	copy(reply[22:28], targetMAC)
	copy(reply[28:32], target.AsSlice())
	copy(reply[32:38], localMAC)
	copy(reply[38:42], local.AsSlice())
	fake := &fakePacketIO{frames: make(chan []byte, 2)}
	fake.frames <- request // outbound request must be ignored
	fake.frames <- reply
	got, err := arpNeighbor(context.Background(), fake, localMAC, local, target, 100*time.Millisecond)
	if err != nil || string(got) != string(targetMAC) || fake.sent != 1 {
		t.Fatalf("ARP result: %v, sent %d, %v", got, fake.sent, err)
	}
}

func TestNDPNeighborMatchesReply(t *testing.T) {
	local, target := netip.MustParseAddr("2001:db8:1::10"), netip.MustParseAddr("2001:db8:1::20")
	localMAC := net.HardwareAddr{2, 1, 2, 3, 4, 5}
	targetMAC := net.HardwareAddr{2, 6, 7, 8, 9, 10}
	request, err := packet.NeighborSolicitation(localMAC, local, target)
	if err != nil {
		t.Fatal(err)
	}
	reply := append([]byte(nil), request...)
	copy(reply[:6], localMAC)
	copy(reply[6:12], targetMAC)
	copy(reply[22:38], target.AsSlice())
	copy(reply[38:54], local.AsSlice())
	reply[54] = 136
	reply[78], reply[79] = 2, 1
	copy(reply[80:86], targetMAC)
	reply[56], reply[57] = 0, 0
	binary.BigEndian.PutUint16(reply[56:58], testICMPv6Checksum(reply[22:38], reply[38:54], reply[54:]))
	fake := &fakePacketIO{frames: make(chan []byte, 2)}
	fake.frames <- request
	fake.frames <- reply
	got, err := ndpNeighbor(context.Background(), fake, localMAC, local, target, 100*time.Millisecond)
	if err != nil || string(got) != string(targetMAC) || fake.sent != 1 {
		t.Fatalf("NDP result: %v, sent %d, %v", got, fake.sent, err)
	}
}

func TestARPBatchCorrelatesRepliesAndSilence(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.10")
	first := netip.MustParseAddr("192.0.2.20")
	silent := netip.MustParseAddr("192.0.2.21")
	mac := net.HardwareAddr{2, 6, 7, 8, 9, 10}
	fake := &fakePacketIO{frames: make(chan []byte, 4), arpReplies: map[netip.Addr]net.HardwareAddr{first: mac}}
	got, err := resolveARPBatch(context.Background(), fake, net.HardwareAddr{2, 1, 2, 3, 4, 5}, local,
		[]netip.Addr{first, silent}, 200*time.Millisecond, newProbeLimiter(0))
	if err != nil || fake.sent != 3 || string(got[first]) != string(mac) || len(got[silent]) != 0 {
		t.Fatalf("ARP batch: %+v, sent %d, %v", got, fake.sent, err)
	}
}

func TestResolvedGatewayCacheSkipsARP(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.10")
	gateway := netip.MustParseAddr("192.0.2.1")
	targets := []netip.Addr{netip.MustParseAddr("198.51.100.20"), netip.MustParseAddr("198.51.100.21")}
	mac := net.HardwareAddr{2, 6, 7, 8, 9, 10}
	fake := &fakePacketIO{frames: make(chan []byte, 2)}
	calls := 0
	got, err := resolveNextHopsWithLookup(context.Background(), config.Config{Interface: "en0", Targets: targets, Timeout: time.Second}, fake,
		net.HardwareAddr{2, 1, 2, 3, 4, 5}, local, newProbeLimiter(0),
		func(netip.Addr) (netip.Addr, error) { return gateway, nil },
		func(device string, hop netip.Addr) net.HardwareAddr {
			calls++
			if device != "en0" || hop != gateway {
				t.Fatalf("wrong cache lookup: %s %s", device, hop)
			}
			return mac
		})
	if err != nil || calls != 1 || fake.sent != 0 {
		t.Fatalf("gateway cache: calls=%d sent=%d err=%v", calls, fake.sent, err)
	}
	for _, target := range targets {
		if string(got[target]) != string(mac) {
			t.Fatalf("target %s resolved to %v", target, got[target])
		}
	}
}

func TestCachedOnLinkNeighborSkipsARP(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.10")
	target := netip.MustParseAddr("192.0.2.1")
	mac := net.HardwareAddr{2, 6, 7, 8, 9, 10}
	fake := &fakePacketIO{frames: make(chan []byte)}
	got, err := resolveNextHopsWithLookup(context.Background(), config.Config{Interface: "en0", Targets: []netip.Addr{target}, Timeout: time.Second}, fake,
		net.HardwareAddr{2, 1, 2, 3, 4, 5}, local, newProbeLimiter(0),
		func(a netip.Addr) (netip.Addr, error) { return a, nil },
		func(string, netip.Addr) net.HardwareAddr { return mac })
	if err != nil || fake.sent != 0 || string(got[target]) != string(mac) {
		t.Fatalf("cached direct neighbor: resolved=%v sent=%d err=%v", got[target], fake.sent, err)
	}
}

func TestUnresolvedGatewayTriesARP(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.10")
	gateway := netip.MustParseAddr("192.0.2.1")
	target := netip.MustParseAddr("198.51.100.20")
	mac := net.HardwareAddr{2, 6, 7, 8, 9, 10}
	fake := &fakePacketIO{frames: make(chan []byte, 2), arpReplies: map[netip.Addr]net.HardwareAddr{gateway: mac}}
	got, err := resolveNextHopsWithLookup(context.Background(), config.Config{Interface: "en0", Targets: []netip.Addr{target}, Timeout: time.Second}, fake,
		net.HardwareAddr{2, 1, 2, 3, 4, 5}, local, newProbeLimiter(0),
		func(netip.Addr) (netip.Addr, error) { return gateway, nil },
		func(string, netip.Addr) net.HardwareAddr { return nil })
	if err != nil || fake.sent != 1 || string(got[target]) != string(mac) {
		t.Fatalf("ARP fallback: resolved=%v sent=%d err=%v", got[target], fake.sent, err)
	}
}

func TestGatewayCacheRecheckedAfterUnansweredARP(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.10")
	gateway := netip.MustParseAddr("192.0.2.1")
	target := netip.MustParseAddr("198.51.100.20")
	mac := net.HardwareAddr{2, 6, 7, 8, 9, 10}
	fake := &fakePacketIO{frames: make(chan []byte)}
	calls := 0
	got, err := resolveNextHopsWithLookup(context.Background(), config.Config{Interface: "en0", Targets: []netip.Addr{target}, Timeout: 50 * time.Millisecond}, fake,
		net.HardwareAddr{2, 1, 2, 3, 4, 5}, local, newProbeLimiter(0),
		func(netip.Addr) (netip.Addr, error) { return gateway, nil },
		func(string, netip.Addr) net.HardwareAddr {
			calls++
			if calls == 2 {
				return mac
			}
			return nil
		})
	if err != nil || fake.sent != 2 || calls != 2 || string(got[target]) != string(mac) {
		t.Fatalf("cache recheck: resolved=%v sent=%d calls=%d err=%v", got[target], fake.sent, calls, err)
	}
}

func testICMPv6Checksum(source, destination, message []byte) uint16 {
	var pseudo [40]byte
	copy(pseudo[:16], source)
	copy(pseudo[16:32], destination)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(message)))
	pseudo[39] = 58
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
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}
