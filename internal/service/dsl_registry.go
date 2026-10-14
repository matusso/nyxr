package service

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
)

// LoadProtocolRegistry validates a complete set of operator-selected files before
// returning any definitions. References are symbolic names within this set, never
// paths supplied by a definition or remote caller.
func LoadProtocolRegistry(paths []string) ([]ProtocolDefinition, error) {
	if len(paths) > 32 {
		return nil, errors.New("at most 32 protocol files are allowed")
	}
	type entry struct {
		name string
		doc  protocolDocument
	}
	entries := make([]entry, 0, len(paths))
	docs := make(map[string]protocolDocument, len(paths))
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("protocol definition %s: %w", path, err)
		}
		data, readErr := io.ReadAll(io.LimitReader(f, 1<<20+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil {
			return nil, fmt.Errorf("protocol definition %s: %w", path, errors.Join(readErr, closeErr))
		}
		if len(data) > 1<<20 {
			return nil, fmt.Errorf("protocol definition %s exceeds 1 MiB", path)
		}
		d, err := decodeProtocol(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("protocol definition %s: %w", path, err)
		}
		name := d.Protocol
		if d.Module != "" {
			if d.Protocol != "" || d.Schema != "nyxr/protocol/v2" || d.Transport != "" || len(d.Ports) != 0 || d.Timeout != "" || d.Extends != "" || len(d.Steps) == 0 || len(d.Steps) > 32 || len(d.Provenance) > 256 {
				return nil, fmt.Errorf("protocol module %s has invalid metadata", path)
			}
			name = d.Module
		}
		if !protocolNameRE.MatchString(name) || docs[name].Schema != "" {
			return nil, fmt.Errorf("invalid or duplicate protocol/module name %q", name)
		}
		docs[name] = d
		entries = append(entries, entry{name, d})
	}
	visiting := map[string]bool{}
	resolved := map[string]protocolDocument{}
	var expand func(string) (protocolDocument, error)
	expand = func(name string) (protocolDocument, error) {
		if d, ok := resolved[name]; ok {
			return d, nil
		}
		d, ok := docs[name]
		if !ok {
			return protocolDocument{}, fmt.Errorf("unknown protocol dependency %q", name)
		}
		if visiting[name] {
			return protocolDocument{}, fmt.Errorf("protocol dependency cycle at %q", name)
		}
		visiting[name] = true
		defer delete(visiting, name)
		if d.Extends != "" {
			base, err := expand(d.Extends)
			if err != nil {
				return protocolDocument{}, err
			}
			if base.Module != "" || base.Schema != "nyxr/protocol/v2" || d.Schema != base.Schema {
				return protocolDocument{}, fmt.Errorf("%s must extend a v2 protocol", name)
			}
			if d.Transport != "" && d.Transport != base.Transport {
				return protocolDocument{}, fmt.Errorf("%s changes inherited transport", name)
			}
			if d.Transport == "" {
				d.Transport = base.Transport
			}
			if len(d.Ports) == 0 {
				d.Ports = append([]uint16(nil), base.Ports...)
			}
			if d.Timeout == "" {
				d.Timeout = base.Timeout
			}
			if d.Provenance == "" {
				d.Provenance = base.Provenance
			}
			d.Steps = append(append([]protocolStep(nil), base.Steps...), d.Steps...)
			d.sourceHash = fmt.Sprintf("%x", sha256.Sum256([]byte(base.sourceHash+"\n"+d.sourceHash)))
		}
		var moduleSteps []protocolStep
		for _, moduleName := range d.Modules {
			module, err := expand(moduleName)
			if err != nil {
				return protocolDocument{}, err
			}
			if module.Module == "" || module.Schema != "nyxr/protocol/v2" || d.Schema != module.Schema {
				return protocolDocument{}, fmt.Errorf("%s references a non-v2 module %q", name, moduleName)
			}
			moduleSteps = append(moduleSteps, module.Steps...)
			d.sourceHash = fmt.Sprintf("%x", sha256.Sum256([]byte(module.sourceHash+"\n"+d.sourceHash)))
			if len(moduleSteps)+len(d.Steps) > 32 {
				return protocolDocument{}, fmt.Errorf("%s expands beyond 32 steps", name)
			}
		}
		d.Steps = append(moduleSteps, d.Steps...)
		if len(d.Steps) > 32 {
			return protocolDocument{}, fmt.Errorf("%s expands beyond 32 steps", name)
		}
		resolved[name] = d
		return d, nil
	}
	definitions := make([]ProtocolDefinition, 0, len(entries))
	for _, item := range entries {
		if item.doc.Module != "" {
			continue
		}
		d, err := expand(item.name)
		if err != nil {
			return nil, err
		}
		definition, err := compileProtocol(d)
		if err != nil {
			return nil, fmt.Errorf("protocol %s: %w", item.name, err)
		}
		definitions = append(definitions, definition)
	}
	for _, item := range entries {
		if item.doc.Module != "" && resolved[item.name].Schema == "" {
			return nil, fmt.Errorf("unused protocol module %q", item.name)
		}
	}
	return definitions, nil
}
