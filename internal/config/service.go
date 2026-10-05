package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/service"
)

// ServiceDefaults are a profile's deep-probe settings, in Options syntax.
type ServiceDefaults struct {
	Probes   string // comma list of service probe names
	Fallback string // probes for open ports with no banner and no port hint
	Timeout  string
	Workers  int
	Rate     int // new service connections per second
}

// ServiceOptions are caller overrides for the deep-probe stage. Enable nil
// keeps the profile default; false disables the stage.
type ServiceOptions struct {
	Enable              *bool
	Probes              string
	Fallback            string
	Timeout             string
	Workers             *int
	Rate                *int
	NmapProbes          string // path to an nmap-service-probes file; enables the nmap probe
	ProtocolDefinitions string // comma-separated local YAML protocol definitions
	BaseDir             string
}

// Service is the resolved deep-probe stage. Enabled false means discovery
// only.
type Service struct {
	Enabled  bool
	Probes   []string
	Fallback []string
	Timeout  time.Duration
	Workers  int
	Rate     int
	// NmapProbesFile is an optional nmap-service-probes file. The local CLI
	// compiles it into pipeline.Options.Nmap; it is empty unless the nmap
	// probe is in use. Remote requests may not set it.
	NmapProbesFile  string
	DefinitionFiles []string
	Definitions     []service.ProtocolDefinition
}

// ServicePlan summarizes the stage for --dry-run.
type ServicePlan struct {
	Probes              []string `json:"probes"`
	Fallback            []string `json:"fallback,omitempty"`
	Timeout             string   `json:"timeout"`
	Workers             int      `json:"workers"`
	Rate                int      `json:"rate"`
	NmapProbes          string   `json:"nmap_service_probes,omitempty"`
	ProtocolDefinitions []string `json:"protocol_definitions,omitempty"`
}

// Plan returns nil when the stage is disabled.
func (s Service) Plan() *ServicePlan {
	if !s.Enabled {
		return nil
	}
	return &ServicePlan{Probes: s.Probes, Fallback: s.Fallback, Timeout: s.Timeout.String(),
		Workers: s.Workers, Rate: s.Rate, NmapProbes: s.NmapProbesFile, ProtocolDefinitions: s.DefinitionFiles}
}

// Engine converts the stage into the service package configuration.
func (s Service) Engine() service.Config {
	return service.Config{Probes: s.Probes, Fallback: s.Fallback, Timeout: s.Timeout, Workers: s.Workers, Rate: s.Rate, Definitions: s.Definitions}
}

// defaultService applies when a profile without its own service settings is
// combined with an explicit request to enable the stage.
var defaultService = ServiceDefaults{Probes: "banner,ssh,tls,http,dns,socks", Fallback: "http", Timeout: "5s", Workers: 16, Rate: 50}

// BuildService resolves the deep-probe stage for an already validated
// discovery Config, using the same profile.
func BuildService(cfg Config, o ServiceOptions) (Service, error) {
	if cfg.Research != nil && (o.Enable != nil && *o.Enable || o.Probes != "" || o.Fallback != "" || o.Timeout != "" || o.Workers != nil || o.Rate != nil || o.ProtocolDefinitions != "") {
		return Service{}, errors.New("research packet experiments cannot run deep service probes")
	}
	profile, ok := LookupProfile(cfg.Profile)
	if !ok {
		return Service{}, fmt.Errorf("unknown profile %q", cfg.Profile)
	}
	enabled := profile.Service != nil
	if o.Enable != nil {
		enabled = *o.Enable
	}
	nmapFile := strings.TrimSpace(o.NmapProbes)
	overridden := o.Probes != "" || o.Fallback != "" || o.Timeout != "" || o.Workers != nil || o.Rate != nil || nmapFile != "" || o.ProtocolDefinitions != ""
	if !enabled {
		if overridden && o.Enable == nil {
			return Service{}, errors.New("service probe options require --service or a service profile")
		}
		return Service{}, nil
	}
	if !cfg.TCP && (!cfg.UDP || o.ProtocolDefinitions == "") {
		return Service{}, errors.New("deep service probes require the TCP protocol or UDP protocol definitions")
	}
	d := defaultService
	if profile.Service != nil {
		d = *profile.Service
	}
	var probes []string
	var err error
	if cfg.TCP {
		probes, err = serviceList(first(o.Probes, d.Probes))
		if err != nil {
			return Service{}, err
		}
	}
	var definitions []service.ProtocolDefinition
	var files []string
	if o.ProtocolDefinitions != "" {
		for _, path := range strings.Split(o.ProtocolDefinitions, ",") {
			if len(files) >= 32 {
				return Service{}, errors.New("at most 32 protocol definitions are allowed")
			}
			path = strings.TrimSpace(path)
			if path == "" {
				return Service{}, errors.New("empty protocol definition path")
			}
			if !filepath.IsAbs(path) {
				path = filepath.Join(o.BaseDir, path)
			}
			definition, err := service.LoadProtocolFile(path)
			if err != nil {
				return Service{}, fmt.Errorf("protocol definition %s: %w", path, err)
			}
			if definition.Transport == "tcp" && !cfg.TCP || definition.Transport == "udp" && !cfg.UDP {
				return Service{}, fmt.Errorf("protocol definition %s requires %s scanning", path, definition.Transport)
			}
			files = append(files, path)
			definitions = append(definitions, definition)
		}
	}
	// The nmap probe reads an nmap-service-probes file. Supplying the file
	// enables the probe; naming the probe without a file is an error.
	hasNmap := false
	for _, p := range probes {
		if p == service.ProbeNmap {
			hasNmap = true
		}
	}
	if nmapFile != "" && !hasNmap {
		probes = append(probes, service.ProbeNmap)
		hasNmap = true
	}
	if hasNmap && nmapFile == "" {
		return Service{}, errors.New("the nmap service probe requires --nmap-service-probes <file>")
	}
	var fallback []string
	if f := first(o.Fallback, d.Fallback); cfg.TCP && f != "" && f != "none" {
		if fallback, err = serviceList(f); err != nil {
			return Service{}, err
		}
	}
	timeout, err := time.ParseDuration(first(o.Timeout, d.Timeout))
	if err != nil {
		return Service{}, fmt.Errorf("service timeout: %w", err)
	}
	s := Service{Enabled: true, Probes: probes, Fallback: fallback, Timeout: timeout,
		Workers: valueOr(o.Workers, d.Workers), Rate: valueOr(o.Rate, d.Rate), NmapProbesFile: nmapFile, DefinitionFiles: files, Definitions: definitions}
	if err := s.ValidateFor(cfg); err != nil {
		return Service{}, err
	}
	return s, nil
}

// ValidateFor enforces scan policy even when a caller constructs a Service
// directly rather than using BuildService (for example, a future API).
func (s Service) ValidateFor(cfg Config) error {
	if !s.Enabled {
		return nil
	}
	if cfg.Research != nil {
		return errors.New("research packet experiments cannot run deep service probes")
	}
	if !cfg.TCP && !cfg.UDP {
		return errors.New("deep service probes require TCP or UDP")
	}
	if err := s.Engine().Validate(); err != nil {
		return err
	}
	if cfg.Profile == "ot-safe" {
		if len(s.Definitions) != 0 {
			return errors.New("ot-safe does not allow custom protocol definitions")
		}
		if len(s.Fallback) != 0 {
			return errors.New("ot-safe does not allow fallback service probes")
		}
		for _, name := range s.Probes {
			if name != service.ProbeModbus && name != service.ProbeEtherNetIP {
				return fmt.Errorf("ot-safe does not allow service probe %q", name)
			}
		}
		if s.Rate < 1 || s.Rate > cfg.Rate || s.Workers > cfg.Workers || s.Timeout < 3*time.Second {
			return errors.New("ot-safe service rate, workers and timeout must stay within scan policy")
		}
	}
	return nil
}

func serviceList(s string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(s, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "" {
			return nil, fmt.Errorf("empty service probe name in %q", s)
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out, nil
}
