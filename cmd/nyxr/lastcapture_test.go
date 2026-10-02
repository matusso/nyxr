package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/packetio"
)

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

func (f *fakeCapture) drained() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.frames) == 0
}

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

func rawResolved(t *testing.T, target netip.Addr) config.Resolved {
	t.Helper()
	cfg, err := config.Build(config.Options{Targets: []string{target.String()}, Profile: "tcp-basic", Ports: "443"})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Interface = "fake0"
	return config.Resolved{Config: cfg}
}

func writeStaleLast(t *testing.T) string {
	t.Helper()
	path, err := lastCapturePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLastCaptureReplacesPreviousAndDecodes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writeStaleLast(t)
	src := &fakeCapture{frames: [][]byte{synFrame(t, scannerIP, targetIP, 50000, 443, false), synFrame(t, targetIP, scannerIP, 443, 50000, true)}}
	var warn bytes.Buffer
	lc := startLastCapture(rawResolved(t, targetIP), func(string) (packetio.PacketIO, error) { return src, nil }, &warn)
	if lc == nil {
		t.Fatalf("capture not started: %s", warn.String())
	}
	for !src.drained() {
		time.Sleep(time.Millisecond)
	}
	lc.finish()
	if warn.Len() != 0 {
		t.Fatalf("warnings: %s", warn.String())
	}
	var out bytes.Buffer
	if err := run([]string{"decode", "--no-color", "--last"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "last.pcapng") || !strings.Contains(out.String(), "443") {
		t.Fatalf("decode --last output:\n%s", out.String())
	}
}

func TestLastCaptureFailureWarnsAndLeavesNoFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := writeStaleLast(t)
	var warn bytes.Buffer
	lc := startLastCapture(rawResolved(t, targetIP), func(string) (packetio.PacketIO, error) { return nil, os.ErrPermission }, &warn)
	lc.finish()
	if lc != nil || !strings.Contains(warn.String(), "last.pcapng not recorded") {
		t.Fatalf("capture %v, warnings %q", lc, warn.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("stale last.pcapng kept: %v", err)
	}
}

func TestLastCaptureLinksExplicitPCAPNG(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	explicit := filepath.Join(t.TempDir(), "scan.pcapng")
	r := rawResolved(t, targetIP)
	r.PCAPNG = explicit
	lc := startLastCapture(r, func(string) (packetio.PacketIO, error) { t.Fatal("captured twice"); return nil, nil }, nil)
	if err := os.WriteFile(explicit, []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	lc.finish()
	path, _ := lastCapturePath()
	if b, err := os.ReadFile(path); err != nil || string(b) != "evidence" {
		t.Fatalf("last.pcapng %q, %v", b, err)
	}
	// The next scan replaces last.pcapng without touching the --pcapng file.
	startLastCapture(config.Resolved{}, nil, nil).finish()
	if b, err := os.ReadFile(explicit); err != nil || string(b) != "evidence" {
		t.Fatalf("explicit capture %q, %v", b, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("last.pcapng kept: %v", err)
	}
}

func TestScanReplacesLastPCAPNGUnlessDisabled(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	scanArgs := []string{"scan", "--profile", "tcp-basic", "--ports", fmt.Sprint(port), "--no-db", "--json", "127.0.0.1"}

	path := writeStaleLast(t)
	var out bytes.Buffer
	if err := run(append([]string{"scan", "--no-last-pcapng"}, scanArgs[1:]...), &out); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "stale" {
		t.Fatalf("--no-last-pcapng touched last.pcapng: %q, %v", b, err)
	}
	if err := run(scanArgs, &out); err != nil {
		t.Fatal(err)
	}
	// A connect scan has no interface to capture on, so it leaves no capture
	// rather than one from an older scan.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("stale last.pcapng kept: %v", err)
	}
}

func TestDecodeLastFlagAndLastFileDiffer(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var out bytes.Buffer
	if err := run([]string{"decode", "--last"}, &out); err == nil || !strings.Contains(err.Error(), "no capture of the last scan") {
		t.Fatalf("missing last capture: %v", err)
	}
	if err := run([]string{"decode", "--last", "x.pcapng"}, &out); err == nil || !strings.Contains(err.Error(), "takes no file") {
		t.Fatalf("--last with file: %v", err)
	}
	writeStaleLast(t)
	t.Chdir(t.TempDir())
	// "last" is a file in the working directory, not ~/.nyxr/last.pcapng.
	if err := run([]string{"decode", "last"}, &out); err == nil || !strings.Contains(err.Error(), "open last") {
		t.Fatalf("decode last: %v", err)
	}
}
