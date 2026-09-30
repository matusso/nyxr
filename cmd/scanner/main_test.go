package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"testing"
)

func TestScanCustomUDPPayload(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("loopback unavailable: %v", err)
	}
	defer server.Close()
	go func() {
		var buf [8]byte
		n, addr, err := server.ReadFromUDP(buf[:])
		if err == nil && n == 1 && buf[0] == 1 {
			_, _ = server.WriteToUDP([]byte{2}, addr)
		}
	}()
	port := server.LocalAddr().(*net.UDPAddr).Port
	var output bytes.Buffer
	err = runScan([]string{"--protocols", "udp", "--ports", fmt.Sprint(port), "--send-hex", "01", "--rate", "0", "--json", "127.0.0.1"}, &output)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		State     string `json:"state"`
		Probe     string `json:"probe"`
		PacketsRX int    `json:"packets_rx"`
	}
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.State != "open" || got.Probe != "custom-hex" || got.PacketsRX != 1 {
		t.Fatalf("got %+v", got)
	}
}
