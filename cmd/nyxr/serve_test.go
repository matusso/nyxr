package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/api"
	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/storage"
)

// bannerServer accepts connections and sends an SSH banner.
func bannerServer(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.WriteString(c, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
				_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

func closedPort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	return p
}

// normalize drops per-run values (IDs, clocks, timings) and orders records
// so equivalent scans compare equal.
func normalize(t *testing.T, obs []observe.Observation) []string {
	t.Helper()
	var out []string
	for _, o := range obs {
		o.ScanID, o.Timestamp, o.RTT = "", time.Time{}, 0
		for i := range o.Evidence {
			o.Evidence[i].Started, o.Evidence[i].Duration = time.Time{}, 0
		}
		b, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(b))
	}
	sort.Strings(out)
	return out
}

func TestCLIAndAPIProduceEquivalentObservations(t *testing.T) {
	open, closed := bannerServer(t), closedPort(t)
	ports := fmt.Sprintf("%d,%d", open, closed)

	var cliOut bytes.Buffer
	if err := run([]string{"scan", "--json", "--ports", ports, "--protocols", "tcp", "--timeout", "1s",
		"--service", "--service-probes", "banner,ssh", "--service-fallback", "none", "--fingerprint", "127.0.0.1"}, &cliOut); err != nil {
		t.Fatal(err)
	}
	var cliObs []observe.Observation
	sc := bufio.NewScanner(&cliOut)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var o observe.Observation
		if err := json.Unmarshal(sc.Bytes(), &o); err != nil {
			t.Fatal(err)
		}
		if o.Kind != observe.KindScan {
			cliObs = append(cliObs, o)
		}
	}

	store, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	m, err := api.NewManager(api.ManagerConfig{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	srv := httptest.NewServer(api.Handler(api.ServerConfig{Manager: m, Store: store}))
	defer srv.Close()
	body := fmt.Sprintf(`{"targets":["127.0.0.1"],"ports":%q,"protocols":"tcp","timeout":"1s","service":true,
		"service_probes":"banner,ssh","service_fallback":"none","fingerprint":true}`, ports)
	res, err := http.Post(srv.URL+"/api/v1/scans", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var created observe.Scan
	_ = json.NewDecoder(res.Body).Decode(&created)
	res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d", res.StatusCode)
	}
	// The event stream ends after the final summary.
	res, err = http.Get(srv.URL + "/api/v1/scans/" + created.ID + "/events")
	if err != nil {
		t.Fatal(err)
	}
	stream, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !bytes.Contains(stream, []byte(`"status":"completed"`)) {
		t.Fatalf("scan did not complete: %s", stream)
	}
	res, err = http.Get(srv.URL + "/api/v1/scans/" + created.ID + "/observations")
	if err != nil {
		t.Fatal(err)
	}
	var apiObs []observe.Observation
	_ = json.NewDecoder(res.Body).Decode(&apiObs)
	res.Body.Close()

	a, b := normalize(t, cliObs), normalize(t, apiObs)
	if strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Fatalf("CLI and API observations differ:\nCLI:\n%s\nAPI:\n%s", strings.Join(a, "\n"), strings.Join(b, "\n"))
	}
	var services int
	for _, o := range apiObs {
		if o.Kind == observe.KindService && o.Service == "ssh" {
			services++
		}
	}
	if len(a) < 3 || services != 1 {
		t.Fatalf("expected open, closed and ssh service records, got:\n%s", strings.Join(b, "\n"))
	}
}

func TestServeRefusesUnsafeConfigurations(t *testing.T) {
	db := filepath.Join(t.TempDir(), "x.db")
	for name, args := range map[string][]string{
		"positional":       {"serve", "extra"},
		"remote, no token": {"serve", "--db", db, "--listen", "0.0.0.0:0"},
		"short token file": {"serve", "--db", db, "--token-file", writeTemp(t, "short")},
	} {
		if err := run(args, io.Discard); err == nil {
			t.Errorf("%s: serve started", name)
		}
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
