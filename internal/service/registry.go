package service

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry is an operator-owned source of validated protocol definitions.
// Each scan takes one immutable snapshot; Reload never publishes a partial set.
type Registry struct {
	paths []string
	mu    sync.Mutex
	value atomic.Pointer[RegistrySnapshot]
}

type RegistrySnapshot struct {
	Version     uint64
	Definitions []ProtocolDefinition
}

func NewRegistry(paths []string) (*Registry, error) {
	if len(paths) == 0 || len(paths) > 32 {
		return nil, errors.New("protocol registry requires 1..32 operator-selected paths")
	}
	r := &Registry{paths: append([]string(nil), paths...)}
	for _, path := range r.paths {
		if strings.TrimSpace(path) == "" {
			return nil, errors.New("empty protocol registry path")
		}
	}
	if _, err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Registry) Reload() (RegistrySnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	definitions, err := LoadProtocolRegistry(r.paths)
	if err != nil {
		return RegistrySnapshot{}, err
	}
	if len(definitions) == 0 {
		return RegistrySnapshot{}, errors.New("protocol registry has no definitions")
	}
	version := uint64(1)
	if previous := r.value.Load(); previous != nil {
		version = previous.Version + 1
	}
	snapshot := &RegistrySnapshot{Version: version, Definitions: definitions}
	r.value.Store(snapshot)
	return r.Snapshot(), nil
}

func (r *Registry) Snapshot() RegistrySnapshot {
	if r == nil {
		return RegistrySnapshot{}
	}
	p := r.value.Load()
	if p == nil {
		return RegistrySnapshot{}
	}
	definitions := make([]ProtocolDefinition, len(p.Definitions))
	for i, d := range p.Definitions {
		definitions[i] = d
		definitions[i].Ports = append([]uint16(nil), d.Ports...)
		definitions[i].steps = append([]protocolStep(nil), d.steps...)
	}
	return RegistrySnapshot{Version: p.Version, Definitions: definitions}
}
