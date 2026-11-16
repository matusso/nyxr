package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/storage"
)

// TestMain points the default database at a throwaway home directory.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "nyxr-home")
	if err != nil {
		panic(err)
	}
	os.Setenv("HOME", home)
	os.Unsetenv("SUDO_UID")
	os.Unsetenv("SUDO_GID")
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}

func TestDBFlagsResolve(t *testing.T) {
	str := func(s string) *string { return &s }
	yes, no := true, false
	def := filepath.Join(os.Getenv("HOME"), ".nyxr", "nyxr.db")
	cases := []struct {
		name string
		f    dbFlags
		want string
		err  bool
	}{
		{"default", dbFlags{path: str("")}, def, false},
		{"default with no-db unset", dbFlags{path: str(""), off: &no}, def, false},
		{"explicit", dbFlags{path: str("x.db"), off: &no}, "x.db", false},
		{"disabled", dbFlags{path: str(""), off: &yes}, "", false},
		{"conflict", dbFlags{path: str("x.db"), off: &yes}, "", true},
	}
	for _, c := range cases {
		got, err := c.f.resolve()
		if (err != nil) != c.err || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}

func TestDefaultDBCreatesDirectory(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var out bytes.Buffer
	if err := run([]string{"history"}, &out); err != nil {
		t.Fatalf("history: %v\n%s", err, out.String())
	}
	fi, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".nyxr", "nyxr.db"))
	if err != nil || fi.IsDir() {
		t.Fatalf("default database not created: %v", err)
	}
}

func TestScanDryRunDefaultDB(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var out bytes.Buffer
	if err := run([]string{"scan", "--dry-run", "--json", "192.0.2.1"}, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte(filepath.Join(".nyxr", "nyxr.db"))) {
		t.Fatalf("plan without default db: %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".nyxr")); !os.IsNotExist(err) {
		t.Fatalf("dry run created the database directory: %v", err)
	}
	out.Reset()
	if err := run([]string{"scan", "--no-db", "--dry-run", "--json", "192.0.2.1"}, &out); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), []byte(`"db"`)) {
		t.Fatalf("--no-db plan still has a db: %s", out.String())
	}
	if err := run([]string{"scan", "--no-db", "--db", "x.db", "--dry-run", "192.0.2.1"}, &out); err == nil {
		t.Fatal("--db with --no-db accepted")
	}
}

// Each scan name is a network with its own database next to the default one,
// registered there with the file digest taken after its last scan.
func TestNamedScansUseOneDatabasePerNetwork(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := filepath.Join(os.Getenv("HOME"), ".nyxr")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	cli := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		if err := run(args, &out); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out.String())
		}
		return out.String()
	}
	scan := func(name string) {
		cli("scan", "--name", name, "--ports", port, "--no-progress", "--no-summary", "127.0.0.1")
	}
	scan("lan-a")
	scan("lan-a")
	scan("lan b/1")
	scan("nyxr") // must not take the registry's own file name
	for _, file := range []string{"lan-a.db", "lan-b-1.db"} {
		if _, err := os.Stat(filepath.Join(dir, file)); err != nil {
			t.Errorf("network database: %v", err)
		}
	}
	var networks []storage.Network
	dec := json.NewDecoder(strings.NewReader(cli("history", "--networks", "--json")))
	for dec.More() {
		var n storage.Network
		if err := dec.Decode(&n); err != nil {
			t.Fatal(err)
		}
		networks = append(networks, n)
	}
	if len(networks) != 3 || networks[1].Name != "lan-a" || networks[1].Scans != 2 || networks[1].LastScanID == "" ||
		networks[2].Path == filepath.Join(dir, "nyxr.db") {
		t.Fatalf("registry: %+v", networks)
	}
	for _, n := range networks {
		if n.Integrity != "unchanged" || len(n.SHA256) != 64 {
			t.Errorf("%s: integrity %q", n.Name, n.Integrity)
		}
	}
	// The default database holds the registry only; reads select a network.
	if strings.Contains(cli("history", "--json"), "scan_id") {
		t.Error("named scans leaked into the default database")
	}
	if got := strings.Count(cli("history", "--network", "lan-a", "--json"), `"name":"lan-a"`); got != 2 {
		t.Errorf("lan-a scans: %d", got)
	}
	if out := cli("history", "--diff", "lan-a"); !strings.Contains(out, "no changes") || strings.Contains(out, "limitation") {
		t.Errorf("network diff: %s", out)
	}
	if got := strings.Count(cli("history", "--networks", "--json"), `"integrity":"unchanged"`); got != 3 {
		t.Errorf("reading a network changed its file: %d unchanged", got)
	}
	var out bytes.Buffer
	if err := run([]string{"history", "--network", "missing"}, &out); err == nil {
		t.Error("unknown network accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "lan-a.db"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cli("history", "--networks", "--json"), `"integrity":"changed"`) {
		t.Error("modified file not reported")
	}
}
