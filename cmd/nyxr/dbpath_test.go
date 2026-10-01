package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
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
