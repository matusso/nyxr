package main

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

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
	uid, okU := sudoID("SUDO_UID")
	gid, okG := sudoID("SUDO_GID")
	if !okU || !okG || os.Geteuid() != 0 {
		return func() {}, nil
	}
	return func() {
		if filepath.Base(dir) == ".nyxr" {
			_ = os.Chown(dir, uid, gid)
		}
		for _, p := range []string{path, path + "-wal", path + "-shm"} {
			_ = os.Lchown(p, uid, gid)
		}
	}, nil
}

// openStore opens the database at path, creating its directory first.
func openStore(ctx context.Context, path string) (*storage.Store, error) {
	handoff, err := prepareDB(path)
	if err != nil {
		return nil, err
	}
	store, err := storage.Open(ctx, path)
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
