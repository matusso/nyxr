package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/matusso/nyxr/internal/observe"

	"github.com/matusso/nyxr/internal/packet"
	"github.com/matusso/nyxr/internal/packetio"
)

var (
	scanner = netip.MustParseAddr("192.0.2.10")
	target  = netip.MustParseAddr("192.0.2.20")
	other   = netip.MustParseAddr("198.51.100.7")
)

func tcpFrame(t *testing.T, src, dst netip.Addr, sport, dport uint16, syn, ack bool) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), SYN: syn, ACK: ack, Seq: 1000, Window: 1024}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

func TestRecorderIndexesQuotedUDP(t *testing.T) {
	quote := make([]byte, 28)
	quote[0], quote[9] = 0x45, 17
	copy(quote[12:16], scanner.AsSlice())
	copy(quote[16:20], target.AsSlice())
	binary.BigEndian.PutUint16(quote[20:22], 50000)
	binary.BigEndian.PutUint16(quote[22:24], 53)
	binary.BigEndian.PutUint16(quote[24:26], 16)
	binary.BigEndian.PutUint16(quote[26:28], 0xabcd)
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: other.AsSlice(), DstIP: scanner.AsSlice()}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(3, 3)}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, icmp, gopacket.Payload(quote)); err != nil {
		t.Fatal(err)
	}
	r := &Recorder{decoder: packet.NewDecoder(), targets: map[netip.Addr]struct{}{target: {}}}
	key, direction, _ := r.classify(buf.Bytes())
	if key != (FlowKey{Target: target, Transport: "udp", Port: 53}) || direction != DirectionRX {
		t.Fatalf("classified as %+v %v", key, direction)
	}
}

// fakeIO delivers a fixed frame list, then idles until the context ends.
type fakeIO struct {
	mu     sync.Mutex
	frames [][]byte
	closed bool
}

func (f *fakeIO) ReceiveBatch(ctx context.Context, buffers [][]byte) (int, error) {
	f.mu.Lock()
	n := 0
	for n < len(buffers) && len(f.frames) > 0 {
		buffers[n] = buffers[n][:copy(buffers[n], f.frames[0])]
		f.frames = f.frames[1:]
		n++
	}
	f.mu.Unlock()
	if n > 0 {
		return n, nil
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-time.After(time.Millisecond):
		return 0, nil
	}
}

func (f *fakeIO) SendBatch(context.Context, [][]byte) (int, error) { return 0, packetio.ErrUnavailable }
func (f *fakeIO) Stats() packetio.Stats                            { return packetio.Stats{Dropped: 3} }
func (f *fakeIO) Close() error                                     { f.closed = true; return nil }

func (f *fakeIO) drained() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.frames) == 0
}

func TestRecorderWritesFilteredIndexedPCAPNG(t *testing.T) {
	syn := tcpFrame(t, scanner, target, 50000, 443, true, false)
	synAck := tcpFrame(t, target, scanner, 443, 50000, true, true)
	unrelated := tcpFrame(t, scanner, other, 50001, 80, true, false)
	src := &fakeIO{frames: [][]byte{syn, unrelated, synAck}}
	path := filepath.Join(t.TempDir(), "scan.pcapng")
	r, err := Start(context.Background(), src, Options{Path: path, Interface: "test0", Targets: []netip.Addr{target}})
	if err != nil {
		t.Fatal(err)
	}
	for !src.drained() {
		time.Sleep(time.Millisecond)
	}
	result, err := r.Stop()
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := os.ReadFile(result.Stats.Path)
	if err != nil || result.Stats.ArtifactID != observe.ArtifactID(artifact) {
		t.Fatalf("capture identity: %+v %v", result.Stats, err)
	}
	if !src.closed {
		t.Fatal("recorder must close its capture handle")
	}
	if result.Stats.Written != 2 || result.Stats.BackendDrops != 3 || result.Stats.Bytes == 0 {
		t.Fatalf("unexpected stats %+v", result.Stats)
	}
	if len(result.Flows) != 1 {
		t.Fatalf("want one flow, got %+v", result.Flows)
	}
	flow := result.Flows[0]
	if flow.Key != (FlowKey{Target: target, Transport: "tcp", Port: 443}) || len(flow.Packets) != 2 {
		t.Fatalf("unexpected flow %+v", flow)
	}
	if flow.Packets[0].Direction != "tx" || flow.Packets[1].Direction != "rx" || flow.Packets[0].ID != 1 || flow.Packets[1].ID != 2 {
		t.Fatalf("unexpected packet refs %+v", flow.Packets)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reader, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("pcapgo cannot read our pcapng: %v", err)
	}
	if reader.LinkType() != layers.LinkTypeEthernet {
		t.Fatalf("link type %v", reader.LinkType())
	}
	for i, want := range [][]byte{syn, synAck} {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if !bytes.Equal(data, want) || ci.CaptureLength != len(want) || ci.Length != len(want) {
			t.Fatalf("packet %d mismatch", i)
		}
		if ci.Timestamp.IsZero() || time.Since(ci.Timestamp) > time.Minute {
			t.Fatalf("packet %d has implausible timestamp %v", i, ci.Timestamp)
		}
	}
}

func TestRecorderEnforcesDiskBudget(t *testing.T) {
	frame := tcpFrame(t, scanner, target, 50000, 22, true, false)
	src := &fakeIO{frames: [][]byte{frame, frame, frame}}
	path := filepath.Join(t.TempDir(), "small.pcapng")
	// Header blocks plus exactly one packet block.
	budget := int64(200) + BlockSize(len(frame), 64)
	r, err := Start(context.Background(), src, Options{Path: path, Targets: []netip.Addr{target}, MaxBytes: budget})
	if err != nil {
		t.Fatal(err)
	}
	for !src.drained() {
		time.Sleep(time.Millisecond)
	}
	result, err := r.Stop()
	if err != nil {
		t.Fatal(err)
	}
	if result.Stats.Written != 1 || result.Stats.DroppedLimit != 2 || result.Stats.Bytes > budget {
		t.Fatalf("budget not enforced: %+v (budget %d)", result.Stats, budget)
	}
}

func TestRecorderLinksRouterICMPErrorToProbedPort(t *testing.T) {
	// ICMP destination unreachable from a router, quoting our SYN to target:443.
	quoted := tcpFrame(t, scanner, target, 50000, 443, true, false)[14:]
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: other.AsSlice(), DstIP: scanner.AsSlice()}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(3, 13)}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, icmp, gopacket.Payload(quoted[:28])); err != nil {
		t.Fatal(err)
	}
	unreachable := append([]byte(nil), buf.Bytes()...)
	if !(&Recorder{targets: map[netip.Addr]struct{}{target: {}}}).wanted(unreachable) {
		t.Fatal("the pre-filter must keep a router's ICMP error quoting a target")
	}
	src := &fakeIO{frames: [][]byte{unreachable}}
	path := filepath.Join(t.TempDir(), "icmp.pcapng")
	rec, err := Start(context.Background(), src, Options{Path: path, Targets: []netip.Addr{target}})
	if err != nil {
		t.Fatal(err)
	}
	for !src.drained() {
		time.Sleep(time.Millisecond)
	}
	result, err := rec.Stop()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Flows) != 1 || result.Flows[0].Key != (FlowKey{Target: target, Transport: "tcp", Port: 443}) {
		t.Fatalf("quoted ICMP error must be linked to the probed port: %+v", result.Flows)
	}
	if result.Flows[0].Packets[0].Direction != "rx" {
		t.Fatalf("router ICMP error is received traffic: %+v", result.Flows[0].Packets)
	}
}
