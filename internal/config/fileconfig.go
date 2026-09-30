package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// FileConfig is the YAML representation of a scan request. It mirrors Options
// but uses value types suited to YAML and rejects unknown fields so typos are
// reported rather than ignored. The CLI overlays command-line flags on top of a
// parsed FileConfig; a future API can accept the same document over the wire.
type FileConfig struct {
	Targets      []string `yaml:"targets"`
	Ports        string   `yaml:"ports"`
	Protocols    string   `yaml:"protocols"`
	Timeout      string   `yaml:"timeout"`
	Rate         *int     `yaml:"rate"`
	Workers      *int     `yaml:"workers"`
	Profile      string   `yaml:"profile"`
	UDPRetries   *int     `yaml:"udp_retries"`
	UDPProbeFile string   `yaml:"udp_probe_file"`
	TCPMode      string   `yaml:"tcp_mode"`
	Interface    string   `yaml:"interface"`
	SourceIP     string   `yaml:"source_ip"`
	SourceMAC    string   `yaml:"source_mac"`
	NextHopMAC   string   `yaml:"next_hop_mac"`
}

// ParseFile reads and validates a YAML scan configuration. An empty path
// returns a zero FileConfig, which contributes no defaults.
func ParseFile(path string) (FileConfig, error) {
	var cfg FileConfig
	if path == "" {
		return cfg, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	decoder := yaml.NewDecoder(f)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}
