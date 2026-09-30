package pipeline

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/packetio"
	"github.com/matusso/nyxr/internal/scan"
	"github.com/matusso/nyxr/internal/storage"
)

func sshServer(t *testing.T) (netip.Addr, uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, "SSH-2.0-OpenSSH_9.6\r\n")
			_ = c.Close()
		}
	}()
	ap := netip.MustParseAddrPort(ln.Addr().String())
	return ap.Addr(), ap.Port()
}

func ftpServer(t *testing.T) (netip.Addr, uint16) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, "220 ProFTPD 1.3.5 Server ready.\r\n")
			time.Sleep(200 * time.Millisecond)
			_ = c.Close()
		}
	}()
	ap := netip.MustParseAddrPort(ln.Addr().String())
	return ap.Addr(), ap.Port()
}

func TestNmapServiceProbesEndToEnd(t *testing.T) {
	addr, open := ftpServer(t)
	path := filepath.Join(t.TempDir(), "nmap-service-probes")
	probes := "Probe TCP NULL q||\nmatch ftp m|^220[- ].*ProFTPD ([\\w.]+)| p/ProFTPD/ v/$1/\n"
	if err := os.WriteFile(path, []byte(probes), 0o644); err != nil {
		t.Fatal(err)
	}
	rate := 0
	cfg, err := config.Build(config.Options{Targets: []string{"127.0.0.1"}, Profile: "service",
		Ports: strconv.Itoa(int(open)), Rate: &rate})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := config.BuildService(cfg, config.ServiceOptions{Timeout: "1s", NmapProbes: path})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	summary, err := Run(context.Background(), cfg, Options{Service: svc, Sinks: []Sink{NewJSONSink(&out)}})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Services != 1 {
		t.Fatalf("expected one identified service: %+v", summary)
	}
	_, records := decodeKinds(t, out.Bytes())
	found := false
	for _, r := range records {
		if r["kind"] == "service" {
			if r["service"] != "ftp" || r["product"] != "ProFTPD" || r["version"] != "1.3.5" {
				t.Fatalf("nmap did not identify the service: %v", r)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no service record for %s:%d", addr, open)
	}
}

func serviceConfig(t *testing.T, port uint16, extra ...uint16) (config.Config, config.Service) {
	t.Helper()
	ports := []string{strconv.Itoa(int(port))}
	for _, p := range extra {
		ports = append(ports, strconv.Itoa(int(p)))
	}
	rate := 0
	cfg, err := config.Build(config.Options{Targets: []string{"127.0.0.1"}, Profile: "service", Ports: strings.Join(ports, ","), Rate: &rate})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := config.BuildService(cfg, config.ServiceOptions{Timeout: "1s"})
	if err != nil {
		t.Fatal(err)
	}
	return cfg, svc
}

// decodeKinds splits an NDJSON stream into record kinds, in order.
func decodeKinds(t *testing.T, data []byte) ([]string, []map[string]any) {
	t.Helper()
	var kinds []string
	var records []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad NDJSON line %q: %v", sc.Text(), err)
		}
		if m["schema"] != observe.SchemaVersion {
			t.Fatalf("record without schema version: %v", m)
		}
		kinds = append(kinds, m["kind"].(string))
		records = append(records, m)
	}
	return kinds, records
}

func TestConnectScanFeedsServiceProbesAndStore(t *testing.T) {
	addr, open := sshServer(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := uint16(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	cfg, svc := serviceConfig(t, open, closed)

	store, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "nyxr.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var out bytes.Buffer
	summary, err := Run(context.Background(), cfg, Options{Service: svc, Sinks: []Sink{NewJSONSink(&out), NewStoreSink(context.Background(), store)}})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Status != "completed" || summary.Observations != 3 || summary.Services != 1 {
		t.Fatalf("summary %+v", summary)
	}
	kinds, records := decodeKinds(t, out.Bytes())
	if strings.Join(kinds, ",") != "port,port,service,scan" && strings.Join(kinds, ",") != "port,service,port,scan" {
		t.Fatalf("record order %v", kinds)
	}
	for _, r := range records {
		if r["kind"] == "service" && (r["product"] != "OpenSSH" || r["port"].(float64) != float64(open)) {
			t.Fatalf("service record %v", r)
		}
	}

	stored, err := store.Observations(context.Background(), storage.Filter{ScanID: summary.ID, Kind: observe.KindService})
	if err != nil || len(stored) != 1 || stored[0].Target != addr || len(stored[0].Evidence) == 0 {
		t.Fatalf("stored service: %+v %v", stored, err)
	}
	scans, _ := store.Scans(context.Background(), 1)
	if len(scans) != 1 || scans[0].Status != "completed" || scans[0].Services != 1 {
		t.Fatalf("stored scan %+v", scans)
	}
}

// fakeCapture replays frames once and then idles.
type fakeCapture struct {
	mu     sync.Mutex
	frames [][]byte
}

func (f *fakeCapture) ReceiveBatch(ctx context.Context, b [][]byte) (int, error) {
	f.mu.Lock()
	n := 0
	for n < len(b) && len(f.frames) > 0 {
		b[n] = b[n][:copy(b[n], f.frames[0])]
		f.frames = f.frames[1:]
		n++
	}
	f.mu.Unlock()
	if n == 0 {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
	return n, nil
}
func (f *fakeCapture) SendBatch(context.Context, [][]byte) (int, error) { return 0, nil }
func (f *fakeCapture) Stats() packetio.Stats                            { return packetio.Stats{} }
func (f *fakeCapture) Close() error                                     { return nil }

func synFrame(t *testing.T, src, dst netip.Addr, sport, dport uint16, ack bool) []byte {
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), SYN: true, ACK: ack}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

func TestCaptureEvidenceLinkedAfterObservations(t *testing.T) {
	target := netip.MustParseAddr("192.0.2.9")
	local := netip.MustParseAddr("192.0.2.1")
	cfg, err := config.Build(config.Options{Targets: []string{target.String()}, Profile: "tcp", Ports: "443"})
	if err != nil {
		t.Fatal(err)
	}
	src := &fakeCapture{frames: [][]byte{synFrame(t, local, target, 50000, 443, false), synFrame(t, target, local, 443, 50000, true)}}
	discover := func(ctx context.Context, _ config.Config, emit func(scan.Observation) error) error {
		for {
			src.mu.Lock()
			done := len(src.frames) == 0
			src.mu.Unlock()
			if done {
				break
			}
			time.Sleep(time.Millisecond)
		}
		return emit(scan.Observation{Timestamp: time.Now(), Target: target, Transport: "tcp", Port: 443, State: "open", Confidence: 100})
	}
	path := filepath.Join(t.TempDir(), "scan.pcapng")
	var out bytes.Buffer
	summary, err := Run(context.Background(), cfg, Options{
		Capture: &CaptureOptions{Path: path, Interface: "fake0"}, Discover: discover,
		OpenCapture: func(string) (packetio.PacketIO, error) { return src, nil },
		Sinks:       []Sink{NewJSONSink(&out)}, CaptureGrace: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	kinds, records := decodeKinds(t, out.Bytes())
	if strings.Join(kinds, ",") != "port,packet-evidence,scan" {
		t.Fatalf("record order %v", kinds)
	}
	pe := records[1]
	if pe["scan_id"] != summary.ID || pe["port"].(float64) != 443 || len(pe["packets"].([]any)) != 2 || pe["capture"] != path {
		t.Fatalf("packet evidence %v", pe)
	}
	if summary.Capture == nil || summary.Capture.Written != 2 || summary.Capture.FlowsIndexed != 1 {
		t.Fatalf("capture stats %+v", summary.Capture)
	}
}

func TestCaptureRequiresInterface(t *testing.T) {
	cfg, _ := config.Build(config.Options{Targets: []string{"192.0.2.9"}, Profile: "tcp"})
	var out bytes.Buffer
	summary, err := Run(context.Background(), cfg, Options{Capture: &CaptureOptions{Path: "x.pcapng"}, Sinks: []Sink{NewTextSink(&out)},
		Discover: func(context.Context, config.Config, func(scan.Observation) error) error {
			t.Fatal("discovery must not start without capture")
			return nil
		}})
	if err == nil || !strings.Contains(err.Error(), "requires --interface") || summary.Status != "failed" {
		t.Fatalf("got %v, %+v", err, summary)
	}
	if !strings.Contains(out.String(), "failed") {
		t.Fatalf("failure summary not printed: %q", out.String())
	}
}

type failingSink struct{ JSONSink }

func (failingSink) Observation(observe.Observation) error { return errors.New("disk full") }

func TestSinkErrorStopsDiscovery(t *testing.T) {
	cfg, _ := config.Build(config.Options{Targets: []string{"192.0.2.9"}, Profile: "tcp", Ports: "1-100"})
	var emitted int
	_, err := Run(context.Background(), cfg, Options{
		Sinks: []Sink{&failingSink{*NewJSONSink(io.Discard)}},
		Discover: func(ctx context.Context, _ config.Config, emit func(scan.Observation) error) error {
			for i := 0; i < 100; i++ {
				emitted++
				if err := emit(scan.Observation{Target: netip.MustParseAddr("192.0.2.9"), Transport: "tcp", Port: uint16(i + 1), State: "closed"}); err != nil {
					return err
				}
			}
			return nil
		}})
	if err == nil || err.Error() != "disk full" || emitted != 1 {
		t.Fatalf("got %v after %d emits", err, emitted)
	}
}
