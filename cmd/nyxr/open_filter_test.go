package main

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/ui"
)

func TestScanOpenFilter(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	openPort := listener.Addr().(*net.TCPAddr).Port
	ports := fmt.Sprintf("%d,%d", openPort, closedPort)

	for _, extra := range [][]string{nil, {"--service"}} {
		var output bytes.Buffer
		args := append([]string{"--protocols", "tcp", "--ports", ports, "--timeout", "500ms", "--rate", "0", "--open", "--json"}, extra...)
		if err := runScan(append(args, "127.0.0.1"), &output, ui.Plain(), progressOptions{}); err != nil {
			t.Fatal(err)
		}
		text := output.String()
		if !strings.Contains(text, fmt.Sprintf(`"port":%d`, openPort)) {
			t.Fatalf("%v: open port missing:\n%s", extra, text)
		}
		if strings.Contains(text, fmt.Sprintf(`"port":%d`, closedPort)) || strings.Contains(text, `"state":"closed"`) {
			t.Fatalf("%v: closed port shown:\n%s", extra, text)
		}
	}
}
