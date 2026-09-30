package config

import (
	"errors"
	"fmt"
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
	Enable   *bool
	Probes   string
	Fallback string
	Timeout  string
	Workers  *int
	Rate     *int
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
}

// ServicePlan summarizes the stage for --dry-run.
type ServicePlan struct {
	Probes   []string `json:"probes"`
	Fallback []string `json:"fallback,omitempty"`
	Timeout  string   `json:"timeout"`
	Workers  int      `json:"workers"`
	Rate     int      `json:"rate"`
}

// Plan returns nil when the stage is disabled.
func (s Service) Plan() *ServicePlan {
	if !s.Enabled {
		return nil
	}
	return &ServicePlan{Probes: s.Probes, Fallback: s.Fallback, Timeout: s.Timeout.String(), Workers: s.Workers, Rate: s.Rate}
}

// Engine converts the stage into the service package configuration.
func (s Service) Engine() service.Config {
	return service.Config{Probes: s.Probes, Fallback: s.Fallback, Timeout: s.Timeout, Workers: s.Workers, Rate: s.Rate}
}

// defaultService applies when a profile without its own service settings is
// combined with an explicit request to enable the stage.
var defaultService = ServiceDefaults{Probes: "banner,ssh,tls,http,dns", Fallback: "http", Timeout: "5s", Workers: 16, Rate: 50}

// BuildService resolves the deep-probe stage for an already validated
// discovery Config, using the same profile.
func BuildService(cfg Config, o ServiceOptions) (Service, error) {
	profile, ok := LookupProfile(cfg.Profile)
	if !ok {
		return Service{}, fmt.Errorf("unknown profile %q", cfg.Profile)
	}
	enabled := profile.Service != nil
	if o.Enable != nil {
		enabled = *o.Enable
	}
	overridden := o.Probes != "" || o.Fallback != "" || o.Timeout != "" || o.Workers != nil || o.Rate != nil
	if !enabled {
		if overridden && o.Enable == nil {
			return Service{}, errors.New("service probe options require --service or a service profile")
		}
		return Service{}, nil
	}
	if profile.Enforce.ReadOnly {
		// Phase 4 reviews which handshakes are safe for OT targets.
		return Service{}, fmt.Errorf("%s profile does not allow deep service probes yet", cfg.Profile)
	}
	if !cfg.TCP {
		return Service{}, errors.New("deep service probes require the TCP protocol")
	}
	d := defaultService
	if profile.Service != nil {
		d = *profile.Service
	}
	probes, err := serviceList(first(o.Probes, d.Probes))
	if err != nil {
		return Service{}, err
	}
	var fallback []string
	if f := first(o.Fallback, d.Fallback); f != "" && f != "none" {
		if fallback, err = serviceList(f); err != nil {
			return Service{}, err
		}
	}
	timeout, err := time.ParseDuration(first(o.Timeout, d.Timeout))
	if err != nil {
		return Service{}, fmt.Errorf("service timeout: %w", err)
	}
	s := Service{Enabled: true, Probes: probes, Fallback: fallback, Timeout: timeout,
		Workers: valueOr(o.Workers, d.Workers), Rate: valueOr(o.Rate, d.Rate)}
	if err := s.Engine().Validate(); err != nil {
		return Service{}, err
	}
	return s, nil
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
