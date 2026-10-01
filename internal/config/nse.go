package config

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// NSE describes the local Nmap bridge. Names are deliberately limited to
// individual scripts; the runner also intersects them with Nmap's safe category.
type NSE struct {
	Scripts []string
	Timeout time.Duration // maximum time for each host's Nmap process
}

type NSEPlan struct {
	Scripts []string `json:"scripts"`
	Timeout string   `json:"timeout"`
	Safety  string   `json:"safety"`
}

func (n NSE) Enabled() bool { return len(n.Scripts) > 0 }

func (n NSE) Validate() error {
	if !n.Enabled() {
		return nil
	}
	if len(n.Scripts) > 16 || n.Timeout < time.Second || n.Timeout > 5*time.Minute {
		return errors.New("invalid NSE script count or timeout")
	}
	for _, name := range n.Scripts {
		if !nseName.MatchString(name) || nseCategory[name] {
			return fmt.Errorf("nse_scripts: %q is not an individual script name", name)
		}
	}
	return nil
}

func (n NSE) Plan() *NSEPlan {
	if !n.Enabled() {
		return nil
	}
	return &NSEPlan{Scripts: n.Scripts, Timeout: n.Timeout.String(), Safety: "safe"}
}

var nseName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
var nseCategory = map[string]bool{
	"safe": true, "all": true, "default": true, "discovery": true,
	"intrusive": true, "exploit": true, "dos": true, "external": true,
	"fuzzer": true, "brute": true, "auth": true, "malware": true,
	"version": true, "vuln": true, "broadcast": true,
}

func BuildNSE(cfg Config, names, timeoutText string) (NSE, error) {
	if names == "" {
		if timeoutText != "" {
			return NSE{}, errors.New("nse_timeout requires nse_scripts")
		}
		return NSE{}, nil
	}
	if cfg.Profile == "ot-safe" || cfg.Research != nil {
		return NSE{}, errors.New("NSE scripts are unavailable in ot-safe and research profiles")
	}
	if !cfg.TCP && !cfg.UDP {
		return NSE{}, errors.New("NSE scripts require TCP or UDP scanning")
	}
	var scripts []string
	seen := make(map[string]bool)
	for _, part := range strings.Split(names, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if !nseName.MatchString(name) || nseCategory[name] {
			return NSE{}, fmt.Errorf("nse_scripts: %q is not an individual script name", part)
		}
		if !seen[name] {
			seen[name] = true
			scripts = append(scripts, name)
		}
		if len(scripts) > 16 {
			return NSE{}, errors.New("nse_scripts accepts at most 16 scripts")
		}
	}
	timeout := 30 * time.Second
	if timeoutText != "" {
		var err error
		timeout, err = time.ParseDuration(timeoutText)
		if err != nil {
			return NSE{}, fmt.Errorf("nse_timeout: %w", err)
		}
	}
	if timeout < time.Second || timeout > 5*time.Minute {
		return NSE{}, errors.New("nse_timeout must be between 1s and 5m")
	}
	n := NSE{Scripts: scripts, Timeout: timeout}
	return n, n.Validate()
}
