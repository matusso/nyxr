package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/matusso/nyxr/internal/api"
	"github.com/matusso/nyxr/internal/storage"
)

// networkCookie carries the browser's selected network. It selects a
// database, not an identity: every handler still checks the API token.
const networkCookie = "nyxr_network"

// networkRouter serves one API handler per named network and sends each
// request to the one its cookie selects. Network databases open on first use.
type networkRouter struct {
	ctx          context.Context
	registryPath string
	registry     *storage.Store // holds the networks table
	// registryAPI answers /api/v1/networks; fallback serves a browser that
	// selected no network (the default database, or --network).
	registryAPI, fallback http.Handler
	fallbackName          string
	fallbackStore         *storage.Store
	build                 func(store *storage.Store, network string) (http.Handler, *api.Manager, error)

	mu   sync.Mutex
	open map[string]*servedNetwork
}

type servedNetwork struct {
	handler http.Handler
	manager *api.Manager
	store   *storage.Store
}

func (r *networkRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/api/v1/networks" {
		r.registryAPI.ServeHTTP(w, req)
		return
	}
	name := ""
	if c, err := req.Cookie(networkCookie); err == nil {
		name, _ = url.QueryUnescape(c.Value)
	}
	handler := r.fallback
	if name != "" && name != r.fallbackName && strings.HasPrefix(req.URL.Path, "/api/") {
		// An unknown or unreadable network falls back rather than failing
		// the whole UI on a stale cookie.
		if n, err := r.network(name); err == nil && n != nil {
			handler = n.handler
		}
	}
	handler.ServeHTTP(w, req)
}

// network returns the served network for a registered name, opening its
// database on first use; nil when the name is not registered.
func (r *networkRouter) network(name string) (*servedNetwork, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n := r.open[name]; n != nil {
		return n, nil
	}
	row, ok, err := r.registry.Network(r.ctx, name)
	if err != nil || !ok {
		return nil, err
	}
	store, err := openStore(r.ctx, row.Path)
	if err != nil {
		return nil, err
	}
	handler, manager, err := r.build(store, name)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	n := &servedNetwork{handler, manager, store}
	r.open[name] = n
	return n, nil
}

// create registers a network for the API and returns its row.
func (r *networkRouter) create(ctx context.Context, name string) (storage.Network, error) {
	if row, ok, err := r.registry.Network(ctx, name); err != nil || ok {
		return row, err
	}
	path, err := networkDB(ctx, r.registryPath, name)
	if err != nil {
		return storage.Network{}, err
	}
	if err := recordNetwork(ctx, r.registryPath, name, path); err != nil {
		return storage.Network{}, err
	}
	row, _, err := r.registry.Network(ctx, name)
	return row, err
}

// finished updates the registry after a scan of a served network. The store
// stays open, so the WAL is checkpointed before the file is hashed.
func (r *networkRouter) finished(store *storage.Store, name string) {
	row, ok, err := r.registry.Network(r.ctx, name)
	if err != nil || !ok {
		return
	}
	ctx := context.WithoutCancel(r.ctx) // a scan may end because the server is stopping
	network, err := networkState(ctx, store, name, row.Path)
	if err != nil || store.Checkpoint(ctx) != nil {
		return
	}
	if network.SHA256, err = fileSHA256(row.Path); err == nil {
		_ = r.registry.SaveNetwork(ctx, network)
	}
}

// finishedStore is finished for a store whose network name the caller does
// not know, such as the fleet controller.
func (r *networkRouter) finishedStore(st *storage.Store) {
	name := ""
	r.mu.Lock()
	if st == r.fallbackStore {
		name = r.fallbackName
	}
	for n, served := range r.open {
		if served.store == st {
			name = n
		}
	}
	r.mu.Unlock()
	if name != "" {
		r.finished(st, name)
	}
}

// stores opens every registered network and returns its store, so work that
// must not depend on what a browser looks at (fleet jobs, central sync)
// covers them all. A network that fails to open is skipped.
func (r *networkRouter) stores() []*storage.Store {
	rows, err := r.registry.Networks(r.ctx)
	if err != nil {
		return nil
	}
	var out []*storage.Store
	for _, row := range rows {
		if row.Name == r.fallbackName {
			continue // already open as the server's own store
		}
		if n, err := r.network(row.Name); err == nil && n != nil {
			out = append(out, n.store)
		}
	}
	return out
}

// close stops the scans of every lazily opened network and closes its store.
func (r *networkRouter) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.open {
		n.manager.Close()
		_ = n.store.Close()
	}
}
