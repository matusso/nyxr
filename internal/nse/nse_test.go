package nse

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/observe"
)

func TestParseStructuredNmapXML(t *testing.T) {
	xml := `<nmaprun><host><address addr="127.0.0.1"/><ports>
<port protocol="tcp" portid="80"><script id="http-title" output="Welcome"><table key="page"><elem key="title">Welcome</elem></table></script>
<script id="unrequested" output="ignored"/></port>
<port protocol="tcp" portid="81"><script id="http-title" output="closed"/></port>
</ports><hostscript><script id="ssl-cert" output="host detail"/></hostscript></host>
<host><address addr="127.0.0.2"/><hostscript><script id="ssl-cert" output="wrong host"/></hostscript></host></nmaprun>`
	addr := netip.MustParseAddr("127.0.0.1")
	results, err := parseXML([]byte(xml), addr, map[Port]bool{{"tcp", 80}: true}, []string{"http-title", "ssl-cert"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Kind != observe.KindScript || results[0].Port != 80 || results[1].Transport != "host" || results[1].Port != 0 {
		t.Fatalf("unexpected results: %+v", results)
	}
	fields := results[0].NSE.Fields
	if len(fields) != 1 || fields[0].Kind != "table" || fields[0].Key != "page" || len(fields[0].Children) != 1 || fields[0].Children[0].Value != "Welcome" {
		t.Fatalf("structured fields lost: %+v", fields)
	}
	if _, err := parseXML([]byte(`<invalid/>`), addr, nil, nil); err == nil {
		t.Fatal("accepted a non-Nmap XML document")
	}
}

func TestRunnerWithLocalNmap(t *testing.T) {
	if testing.Short() {
		t.Skip("local Nmap integration")
	}
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("Nmap is not installed")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(conn, "NYXR-NSE-TEST\r\n")
			_ = conn.Close()
		}
	}()
	settings := config.NSE{Scripts: []string{"banner"}, Timeout: 10 * time.Second}
	runner := Runner{}
	if err := runner.Validate(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	results, err := runner.RunHost(context.Background(), settings, netip.MustParseAddr("127.0.0.1"), []Port{{"tcp", port}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].NSE.ID != "banner" || !strings.Contains(results[0].NSE.Output, "NYXR-NSE-TEST") {
		t.Fatalf("Nmap banner result missing: %+v", results)
	}
}

func TestSelectorRequiresSafeAndExcludesDangerousCategories(t *testing.T) {
	s := selector([]string{"http-title", "ssl-cert"})
	for _, part := range []string{"(http-title or ssl-cert)", "and safe", "not (intrusive or exploit or dos or external or fuzzer or brute)"} {
		if !strings.Contains(s, part) {
			t.Fatalf("selector %q missing %q", s, part)
		}
	}
}
