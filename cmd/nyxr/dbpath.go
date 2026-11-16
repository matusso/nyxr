package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/matusso/nyxr/internal/storage"
)

// dbFlags is the --db file and, for scan, the --no-db opt-out.
type dbFlags struct {
	path *string
	off  *bool
}

// resolve returns the database path, or "" when --no-db was given.
// Without --db it is ~/.nyxr/nyxr.db.
func (f dbFlags) resolve() (string, error) {
	if f.off != nil && *f.off {
		if *f.path != "" {
			return "", errors.New("--db and --no-db are mutually exclusive")
		}
		return "", nil
	}
	if *f.path != "" {
		return *f.path, nil
	}
	home, err := homeDir()
	if err != nil {
		return "", errors.New("cannot locate home directory for the default database; pass --db or --no-db")
	}
	return filepath.Join(home, ".nyxr", "nyxr.db"), nil
}

// homeDir is the invoking user's home: under sudo it is SUDO_USER's home,
// so a root scan and an unprivileged history or serve share one database.
func homeDir() (string, error) {
	if uid, ok := sudoID("SUDO_UID"); ok && os.Geteuid() == 0 {
		if u, err := user.LookupId(strconv.Itoa(uid)); err == nil && u.HomeDir != "" {
			return u.HomeDir, nil
		}
	}
	return os.UserHomeDir()
}

// prepareDB creates the database directory. Under sudo, the directory and
// database files are handed to the invoking user once the store exists.
func prepareDB(path string) (handoff func(), err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return func() { giveToInvoker(dir, path, path+"-wal", path+"-shm") }, nil
}

// giveToInvoker hands files nyxr created under sudo to the invoking user,
// and dir too when it is nyxr's own ~/.nyxr. Without sudo it does nothing.
func giveToInvoker(dir string, paths ...string) {
	uid, okU := sudoID("SUDO_UID")
	gid, okG := sudoID("SUDO_GID")
	if !okU || !okG || os.Geteuid() != 0 {
		return
	}
	if filepath.Base(dir) == ".nyxr" {
		_ = os.Chown(dir, uid, gid)
	}
	for _, p := range paths {
		_ = os.Lchown(p, uid, gid)
	}
}

// openStore opens the database at path, creating its directory first.
func openStore(ctx context.Context, path string) (*storage.Store, error) {
	handoff, err := prepareDB(path)
	if err != nil {
		return nil, err
	}
	store, err := storage.OpenNotify(ctx, path, func(from, to int) {
		fmt.Fprintf(os.Stderr, "nyxr: upgrading %s from schema %d to %d; this one-time step can take minutes on a large database, do not interrupt\n", path, from, to)
	})
	if err != nil {
		return nil, err
	}
	handoff()
	return store, nil
}

func sudoID(env string) (int, bool) {
	n, err := strconv.Atoi(os.Getenv(env))
	return n, err == nil && n > 0
}

// networkPath returns the database file registered for a named network in
// the registry database.
func networkPath(ctx context.Context, registry, name string) (string, bool, error) {
	store, err := openStore(ctx, registry)
	if err != nil {
		return "", false, err
	}
	defer store.Close()
	n, ok, err := store.Network(ctx, name)
	return n.Path, ok, err
}

// networkDB returns where a named network's scans are stored: its registered
// file, or for a new name a file next to the registry. A name that maps to a
// taken file name gets a digest suffix.
func networkDB(ctx context.Context, registry, name string) (string, error) {
	store, err := openStore(ctx, registry)
	if err != nil {
		return "", err
	}
	defer store.Close()
	if n, ok, err := store.Network(ctx, name); err != nil || ok {
		return n.Path, err
	}
	slug := strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == '.' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return '-'
	}, name)
	path := filepath.Join(filepath.Dir(registry), slug+".db")
	networks, err := store.Networks(ctx)
	if err != nil {
		return "", err
	}
	taken := path == registry || strings.HasPrefix(slug, ".")
	for _, n := range networks {
		taken = taken || n.Path == path
	}
	if _, err := os.Stat(path); err == nil {
		taken = true // an unregistered file is not ours to adopt
	}
	if taken {
		sum := sha256.Sum256([]byte(name))
		path = filepath.Join(filepath.Dir(registry), fmt.Sprintf("net-%s-%x.db", strings.Trim(slug, "."), sum[:4]))
	}
	return path, nil
}

// recordNetwork updates the registry after a scan of a named network: the
// newest scan, the scan count and the SHA-256 of the closed database file.
func recordNetwork(ctx context.Context, registry, name, path string) error {
	store, err := openStore(ctx, path)
	if err != nil {
		return err
	}
	network, err := networkState(ctx, store, name, path)
	// Closing checkpoints the WAL, so the main file holds everything hashed.
	if cerr := store.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if network.SHA256, err = fileSHA256(path); err != nil {
		return err
	}
	reg, err := openStore(ctx, registry)
	if err != nil {
		return err
	}
	defer reg.Close()
	return reg.SaveNetwork(ctx, network)
}

// networkState reads a network's newest scan and scan count from its store.
func networkState(ctx context.Context, store *storage.Store, name, path string) (storage.Network, error) {
	network := storage.Network{Name: name, Path: path}
	scans, err := store.Scans(ctx, 1)
	if err != nil {
		return network, err
	}
	if len(scans) > 0 {
		network.LastScanID, network.LastScan = scans[0].ID, scans[0].Started
	}
	network.Scans, err = store.ScanCount(ctx)
	return network, err
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
