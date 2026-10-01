package scan

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/probe"
)

func TestTCPConnectOpenAndClosed(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	target := netip.MustParseAddr("127.0.0.1")
	var got []Observation
	cfg := config.Config{Targets: []netip.Addr{target}, Ports: []uint16{port}, TCP: true, Timeout: time.Second, Workers: 2}
	if err := Run(context.Background(), cfg, func(o Observation) error { got = append(got, o); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].State != "open" {
		t.Fatalf("got %+v", got)
	}
	listener.Close()
	closed := probeTCP(context.Background(), task{target: target, port: port, transport: "tcp"}, time.Second)
	if closed.State != "closed" {
		t.Fatalf("got %+v", closed)
	}
}

func TestUDPReply(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	go func() {
		var buf [64]byte
		n, addr, err := server.ReadFromUDP(buf[:])
		if err == nil && n == 0 {
			_, _ = server.WriteToUDP([]byte{1}, addr)
		}
	}()
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"}, time.Second, nil, 0, []byte("test-secret"), newProbeLimiter(0))
	if got.State != "open" || got.PacketsRX != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestUDPBasicAndCommonFallbackSendEmptyDatagram(t *testing.T) {
	all, err := probe.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []config.UDPMode{config.UDPBasic, config.UDPCommon} {
		t.Run(string(mode), func(t *testing.T) {
			server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Skipf("loopback unavailable: %v", err)
			}
			defer server.Close()
			go func() {
				var buf [64]byte
				n, peer, err := server.ReadFromUDP(buf[:])
				if err == nil && n == 0 {
					_, _ = server.WriteToUDP([]byte{1}, peer)
				}
			}()
			port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
			got := probeUDPCampaignWithICMPMode(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"},
				100*time.Millisecond, all, 0, []byte("secret"), newProbeLimiter(0), nil, mode)
			wantProbe := "udp-empty"
			if mode == config.UDPCommon {
				wantProbe = "udp-null"
			}
			if got.State != "open" || got.PacketsTX != 1 || got.Probe != wantProbe {
				t.Fatalf("%s sent unexpected probes: %+v", mode, got)
			}
		})
	}
}

func TestUDPDeepFindsSNMPv3OnNonstandardPort(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	all, err := probe.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	report, err := hex.DecodeString("3058020103300f02021234020300ffe3040100020103041e301c040b800000090354a274dfdb420201020204038787de040004000400302204000400a81c0201010201000201003011300f060a2b060106030f01010400410101")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		var buf [4096]byte
		for {
			n, peer, err := server.ReadFromUDP(buf[:])
			if err != nil {
				return
			}
			if n == 60 && bytes.HasPrefix(buf[:n], []byte{0x30, 0x3a, 2, 1, 3}) {
				copy(report[9:11], buf[9:11])
				_, _ = server.WriteToUDP(report, peer)
			}
		}
	}()
	got := probeUDPCampaignWithICMPMode(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"},
		40*time.Millisecond, all, 0, []byte("secret"), newProbeLimiter(0), nil, config.UDPDeep)
	if got.State != "open" || got.Service != "snmp" || got.Probe != "snmp-v3-discovery" ||
		got.Fields["snmp.engine_id_data"] != "54:a2:74:df:db:42" || got.Fields["snmp.engine_boots"] != "2" {
		t.Fatalf("deep scan should identify SNMPv3 on port %d: %+v", port, got)
	}
}

func TestUDPBACnetFallsBackWhenFirstProbeIsSilent(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	all, err := probe.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	var selected []probe.Probe
	for _, p := range probe.ForPort(all, 47808) {
		if p.Matcher == "bacnet" || p.Matcher == "bacnet-read" || p.Matcher == "bacnet-fdt" {
			p.Timeout = 40 * time.Millisecond
			selected = append(selected, p)
		}
	}
	go func() {
		var buf [64]byte
		for {
			n, addr, err := server.ReadFromUDP(buf[:])
			if err != nil {
				return
			}
			if n == 17 && buf[1] == 0x0a && buf[9] == 0x0c {
				response := []byte{0x81, 0x0a, 0, 9, 1, 0, 0x30, buf[8], 0x0c}
				_, _ = server.WriteToUDP(response, addr)
			}
		}
	}()
	got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"},
		time.Second, selected, 0, []byte("secret"), newProbeLimiter(0))
	if got.State != "open" || got.Service != "bacnet" || got.Probe != "bacnet-read-device" || got.Confidence != 100 {
		t.Fatalf("BACnet read response should confirm open port: %+v", got)
	}
}

func TestUDPBACnetForeignDeviceTableConfirmsOpen(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	all, err := probe.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	var fdt probe.Probe
	for _, p := range probe.ForPort(all, 47808) {
		if p.Matcher == "bacnet-fdt" {
			fdt = p
		}
	}
	if fdt.Name == "" {
		t.Fatal("FDT probe missing")
	}
	fdt.Ports = []uint16{port}
	go func() {
		var buf [32]byte
		for {
			n, addr, err := server.ReadFromUDP(buf[:])
			if err != nil {
				return
			}
			if n == 4 && buf[1] == 6 {
				response := []byte{0x81, 0x07, 0, 14, 217, 75, 94, 18, 0x62, 0x2d, 0, 30, 0, 34}
				_, _ = server.WriteToUDP(response, addr)
			} else if n == 17 && buf[9] == 12 {
				response := []byte{0x81, 0x0a, 0, 9, 1, 0, 0x60, buf[8], 0}
				if buf[16] == 75 {
					response = []byte{0x81, 0x0a, 0, 23, 1, 0, 0x30, buf[8], 12,
						12, 2, 0x20, 8, 1, 0x19, 75, 0x3e, 0xc4, 2, 0x20, 8, 1, 0x3f}
				}
				_, _ = server.WriteToUDP(response, addr)
			}
		}
	}()
	got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"},
		time.Second, []probe.Probe{fdt}, 0, []byte("secret"), newProbeLimiter(0))
	if got.State != "open" || got.Service != "bacnet" || got.Probe != "bacnet-fdt" ||
		got.Fields["bacnet.device_id"] != "2099201" || got.Fields["bacnet.fdt_entries"] != "1" ||
		got.Fields["bacnet.fdt.0"] != "217.75.94.18:25133:ttl=30:timeout=34" {
		t.Fatalf("FDT response should confirm BACnet open port: %+v", got)
	}
}

func TestUDPBACnetReadsDeviceMetadataAfterOpening(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	all, err := probe.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	var read probe.Probe
	for _, p := range probe.ForPort(all, 47808) {
		if p.Matcher == "bacnet-read" {
			read = p
		}
	}
	if read.Name == "" {
		t.Fatal("Device read probe missing")
	}
	properties := map[byte]string{
		77:  "Site01'PkMajer",
		121: "Siemens Building Technologies",
		12:  `JK CONTROL\SK\Banska Bystrica\TBB_PkMajer\PkMajer`,
		44:  "FW=V6.00.314 / SBC=11.01 / FLI=06.00 / BBI=13.06 / CIO=01.20 / STF=01.20",
		70:  "PXC22.1-E.D / HW=V6.00",
		28:  "PXC Contr. 01",
		58:  "Banska Bystrica",
	}
	go func() {
		var buf [128]byte
		for {
			n, peer, err := server.ReadFromUDP(buf[:])
			if err != nil {
				return
			}
			if n == 4 && buf[1] == 6 {
				_, _ = server.WriteToUDP([]byte{0x81, 7, 0, 14, 217, 75, 94, 18, 0x62, 0x2d, 0, 30, 0, 34}, peer)
				continue
			}
			if n != 17 || buf[9] != 12 {
				continue
			}
			property := buf[16]
			response := []byte{0x81, 0x0a, 0, 0, 1, 0, 0x30, buf[8], 12,
				12, 2, 0x20, 8, 1, 0x19, property, 0x3e}
			switch property {
			case 75:
				response = append(response, 0xc4, 2, 0x20, 8, 1)
			case 120:
				response = append(response, 0x22, 0, 7)
			default:
				value, ok := properties[property]
				if !ok {
					continue
				}
				response = append(response, 0x75, byte(len(value)+1), 0)
				response = append(response, value...)
			}
			response = append(response, 0x3f)
			binary.BigEndian.PutUint16(response[2:4], uint16(len(response)))
			_, _ = server.WriteToUDP(response, peer)
		}
	}()
	got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"},
		300*time.Millisecond, []probe.Probe{read}, 0, []byte("secret"), newProbeLimiter(0))
	if got.State != "open" || got.Service != "bacnet" || got.Fields["bacnet.device_id"] != "2099201" ||
		got.Fields["bacnet.object_name"] != properties[77] || got.Fields["bacnet.vendor_name"] != properties[121] ||
		got.Fields["bacnet.application_software"] != properties[12] || got.Fields["bacnet.firmware"] != properties[44] ||
		got.Fields["bacnet.model_name"] != properties[70] || got.Fields["bacnet.description"] != properties[28] ||
		got.Fields["bacnet.fdt.0"] != "217.75.94.18:25133:ttl=30:timeout=34" || got.PacketsTX != 10 {
		t.Fatalf("BACnet enrichment missing: %+v", got)
	}
}

func TestUDPCampaignTriesOffPortProbesAndAcceptsTFTPTransferPort(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	transfer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer transfer.Close()
	all, err := probe.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	var dns, tftp probe.Probe
	for _, p := range all {
		switch p.Name {
		case "dns-a":
			dns = p
		case "tftp-read":
			tftp = p
		}
	}
	if dns.Name == "" || tftp.Name == "" {
		t.Fatal("missing native probes")
	}
	go func() {
		var buf [64]byte
		for {
			n, peer, err := server.ReadFromUDP(buf[:])
			if err != nil {
				return
			}
			if n >= 2 && buf[0] == 0 && buf[1] == 1 {
				_, _ = transfer.WriteToUDP([]byte{0, 5, 0, 1, 'x', 0}, peer)
			}
		}
	}()
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"},
		100*time.Millisecond, []probe.Probe{dns, tftp}, 0, []byte("secret"), newProbeLimiter(0))
	if got.State != "open" || got.Service != "tftp" || got.Probe != "tftp-read" ||
		got.PacketsTX != 2 || got.Fields["tftp.error_code"] != "1" {
		t.Fatalf("off-port TFTP probe failed: %+v", got)
	}
}

func TestUDPCampaignMatchesAfterStrayReply(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	go func() {
		var buf [64]byte
		n, addr, err := server.ReadFromUDP(buf[:])
		if err != nil {
			return
		}
		wrong := append([]byte(nil), buf[:n]...)
		wrong[0] ^= 1
		wrong[2] |= 0x80
		_, _ = server.WriteToUDP(wrong, addr)
		valid := append([]byte(nil), buf[:n]...)
		valid[2] |= 0x80
		_, _ = server.WriteToUDP(valid, addr)
	}()
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	p := probe.Probe{Name: "dns-test", Payload: make([]byte, 12), Matcher: "dns"}
	got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"}, time.Second, []probe.Probe{p}, 0, []byte("secret"), newProbeLimiter(0))
	if got.State != "open" || got.Confidence != 100 || got.PacketsRX != 2 {
		t.Fatalf("got %+v", got)
	}
}

func TestMatchRecentAcceptsDelayedProbeResponse(t *testing.T) {
	p := probe.Probe{Name: "dns-a", Payload: make([]byte, 12), Matcher: "dns"}
	first := probe.Prepare(p, 0x1234)
	second := probe.Prepare(p, 0x5678)
	response := append([]byte(nil), first...)
	response[2] |= 0x80
	recent := []sentProbe{{probe: p, request: first}, {probe: p, request: second}}
	matched, ok := matchRecent(recent, response)
	if !ok || string(matched.request) != string(first) {
		t.Fatal("late response did not match the earlier request")
	}
}

func TestUDPCampaignRetriesNoResponse(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	received := make(chan int, 1)
	go func() {
		var buf [16]byte
		count := 0
		for count < 2 {
			if _, _, err := server.ReadFromUDP(buf[:]); err != nil {
				break
			}
			count++
		}
		received <- count
	}()
	port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
	p := probe.Probe{Name: "silent", Payload: []byte{1}, Matcher: "any", Retries: 1}
	got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: port, transport: "udp"}, 20*time.Millisecond, []probe.Probe{p}, 0, []byte("secret"), newProbeLimiter(0))
	if got.State != "open|filtered" || got.PacketsTX != 2 || len(got.ProbesAttempted) != 2 {
		t.Fatalf("got %+v", got)
	}
	select {
	case count := <-received:
		if count != 2 {
			t.Fatalf("server received %d probes", count)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive both retries")
	}
}

func TestUDPCampaignCapsCombinedRetries(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	p := probe.Probe{Name: "silent", Payload: []byte{1}, Matcher: "any", Retries: 5}
	got := probeUDPCampaign(context.Background(), task{target: netip.MustParseAddr("127.0.0.1"), port: uint16(server.LocalAddr().(*net.UDPAddr).Port), transport: "udp"},
		5*time.Millisecond, []probe.Probe{p}, 5, []byte("secret"), newProbeLimiter(0))
	if got.State != "open|filtered" || got.PacketsTX != 6 {
		t.Fatalf("got %+v", got)
	}
}

func TestChecksum(t *testing.T) {
	msg := []byte{8, 0, 0, 0, 0, 1, 0, 1}
	c := checksum(msg)
	msg[2], msg[3] = byte(c>>8), byte(c)
	if checksum(msg) != 0 {
		t.Fatalf("invalid checksum: %x", msg)
	}
}

func TestICMPv6Checksum(t *testing.T) {
	source := net.ParseIP("2001:db8::1")
	destination := net.ParseIP("2001:db8::2")
	message := []byte{128, 0, 0, 0, 0x12, 0x34, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8}
	binary.BigEndian.PutUint16(message[2:4], icmp6Checksum(source, destination, message))
	if got := icmp6Checksum(source, destination, message); got != 0 {
		t.Fatalf("ICMPv6 pseudoheader checksum failed: %04x", got)
	}
	message[15] ^= 1
	if got := icmp6Checksum(source, destination, message); got == 0 {
		t.Fatal("payload change was not detected")
	}
}

func TestEchoReplyRequiresMatchingToken(t *testing.T) {
	request := []byte{128, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	reply := append([]byte(nil), request...)
	reply[0] = 129
	if !matchesEchoReply(reply, 129, request) {
		t.Fatal("valid echo reply rejected")
	}
	withHeader := make([]byte, 40+len(reply))
	withHeader[0], withHeader[6] = 0x60, 58
	copy(withHeader[40:], reply)
	if !matchesEchoReply(withHeader, 129, request) {
		t.Fatal("IPv6 header reply rejected")
	}
	reply[15] ^= 1
	if matchesEchoReply(reply, 129, request) {
		t.Fatal("wrong token accepted")
	}
	if matchesEchoReply(reply[:15], 129, request) {
		t.Fatal("truncated reply accepted")
	}
}

func TestTargetPortsLimitConnectScan(t *testing.T) {
	a, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer a.Close()
	b, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	pa, pb := uint16(a.Addr().(*net.TCPAddr).Port), uint16(b.Addr().(*net.TCPAddr).Port)
	target := netip.MustParseAddr("127.0.0.1")
	r, err := config.Request{KnownOpen: true, Targets: []string{"127.0.0.1"}, Timeout: "1s"}.Resolve(config.ResolveOptions{
		KnownOpen: func() ([]config.KnownPort, error) {
			return []config.KnownPort{{Address: target, Transport: "tcp", Port: pa}}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := r.Config
	cfg.Ports = append(cfg.Ports, pb) // a port the restriction must skip
	var got []Observation
	if err := Run(context.Background(), cfg, func(o Observation) error { got = append(got, o); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Port != pa || got[0].State != "open" {
		t.Fatalf("got %+v, want only port %d", got, pa)
	}
}
