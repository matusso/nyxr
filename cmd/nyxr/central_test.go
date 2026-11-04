package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/matusso/nyxr/internal/central"
	"github.com/matusso/nyxr/internal/storage"
)

func TestCentralCLIEndToEnd(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	// Two scanners in different sites see the same scoped cloud instance.
	var dbs []string
	for i, addr := range []string{"10.0.0.1", "172.16.0.1"} {
		path := filepath.Join(dir, "site"+strconv.Itoa(i)+".db")
		s, err := storage.Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.ImportExternalIdentifiers(ctx, []storage.ExternalIdentifier{{Address: netip.MustParseAddr(addr),
			Kind: "cloud.azure.vm_id", Scope: "sub-1", Value: "vm-1"}}); err != nil {
			t.Fatal(err)
		}
		s.Close()
		dbs = append(dbs, path)
	}
	cdb := filepath.Join(dir, "central.db")
	objects := filepath.Join(dir, "objects")
	dsnFile := filepath.Join(dir, "dsn")
	if err := os.WriteFile(dsnFile, []byte(cdb+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn := []string{"--central-dsn-file", dsnFile, "--objects", objects}
	cli := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		if err := run(append(append([]string{"central"}, args[0]), append(conn, args[1:]...)...), &out); err != nil {
			t.Fatalf("nyxr central %v: %v\n%s", args, err, out.String())
		}
		return out.String()
	}
	for i, db := range dbs {
		out := cli("push", "--db", db, "--label", "site"+strconv.Itoa(i), "--json")
		var res central.PushResult
		if err := json.Unmarshal([]byte(out), &res); err != nil || res.Ingested.Observations != 1 {
			t.Fatalf("push %d: %s", i, out)
		}
	}
	var entities []central.Entity
	if err := json.Unmarshal([]byte(cli("entities", "--json")), &entities); err != nil {
		t.Fatal(err)
	}
	if len(entities) != 1 || len(entities[0].Nodes) != 2 || entities[0].Link != "scoped_signal" {
		t.Fatalf("entities: %+v", entities)
	}
	e := entities[0]
	expect := e.ID + "@" + strconv.FormatInt(e.Revision, 10)
	out := cli("review", "--separate", "--node-a", e.Nodes[0].Key, "--node-b", e.Nodes[1].Key, "--note", "different tenants", "--expect", expect)
	if !strings.Contains(out, "1 node(s) moved") {
		t.Fatalf("review: %s", out)
	}
	var stale bytes.Buffer
	err := run(append([]string{"central", "review", "--join", "--node-a", e.Nodes[0].Key, "--node-b", e.Nodes[1].Key, "--note", "x", "--expect", expect}, conn...), &stale)
	if err == nil || !strings.Contains(err.Error(), "revision") {
		t.Fatalf("stale review: %v", err)
	}
	cli("revert", "--decision", "1", "--note", "same VM after all")
	if !strings.Contains(cli("history"), "revert:1") {
		t.Fatal("history lacks the revert")
	}

	report := filepath.Join(dir, "report.json")
	if err := os.WriteFile(report, []byte(`{"horizon":"run"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var a central.Artifact
	if err := json.Unmarshal([]byte(cli("put", "--kind", "horizon-report", "--json", report)), &a); err != nil || a.Access != central.AccessRestricted {
		t.Fatalf("put: %+v %v", a, err)
	}
	var denied bytes.Buffer
	if err := run(append([]string{"central", "get", a.ID}, conn...), &denied); err == nil {
		t.Fatal("restricted artifact read without --allow-restricted")
	}
	if got := cli("get", "--allow-restricted", a.ID); got != `{"horizon":"run"}` {
		t.Fatalf("get: %q", got)
	}

	export := filepath.Join(dir, "central.jsonl")
	cli("export", "--out", export)
	restored := filepath.Join(dir, "restored.db")
	var rout bytes.Buffer
	if err := run([]string{"central", "restore", "--central", restored, "--in", export}, &rout); err != nil {
		t.Fatal(err)
	}
	var after []central.Entity
	var aout bytes.Buffer
	if err := run([]string{"central", "entities", "--central", restored, "--json"}, &aout); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(aout.Bytes(), &after); err != nil || len(after) != 1 || after[0].GlobalID != e.GlobalID {
		t.Fatalf("restored entities keep their URN: %+v %v", after, err)
	}
}
