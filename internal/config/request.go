package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Request is the one scan request document shared by every interface: the CLI
// reads it from a YAML --config file and overlays flags, and the API accepts
// the same fields as JSON. Unknown fields are rejected in both encodings so
// typos are reported rather than ignored. Resolve turns a Request into the
// validated discovery Config and the stage settings around it.
type Request struct {
	Targets         []string `yaml:"targets" json:"targets"`
	AllowTargets    []string `yaml:"allow_targets" json:"allow_targets,omitempty"`
	Ports           string   `yaml:"ports" json:"ports,omitempty"`
	Protocols       string   `yaml:"protocols" json:"protocols,omitempty"`
	Timeout         string   `yaml:"timeout" json:"timeout,omitempty"`
	Rate            *int     `yaml:"rate" json:"rate,omitempty"`
	HostRate        *int     `yaml:"host_rate" json:"host_rate,omitempty"`
	SubnetRate      *int     `yaml:"subnet_rate" json:"subnet_rate,omitempty"`
	InterfaceRate   *int     `yaml:"interface_rate" json:"interface_rate,omitempty"`
	Workers         *int     `yaml:"workers" json:"workers,omitempty"`
	Profile         string   `yaml:"profile" json:"profile,omitempty"`
	UDPRetries      *int     `yaml:"udp_retries" json:"udp_retries,omitempty"`
	UDPProbeFile    string   `yaml:"udp_probe_file" json:"udp_probe_file,omitempty"`
	SendHex         string   `yaml:"send_hex" json:"send_hex,omitempty"`
	SendBase64      string   `yaml:"send_base64" json:"send_base64,omitempty"`
	PayloadFile     string   `yaml:"payload_file" json:"payload_file,omitempty"`
	TCPMode         string   `yaml:"tcp_mode" json:"tcp_mode,omitempty"`
	Interface       string   `yaml:"interface" json:"interface,omitempty"`
	SourceIP        string   `yaml:"source_ip" json:"source_ip,omitempty"`
	SourceMAC       string   `yaml:"source_mac" json:"source_mac,omitempty"`
	NextHopMAC      string   `yaml:"next_hop_mac" json:"next_hop_mac,omitempty"`
	ResearchKind    string   `yaml:"research_kind" json:"research_kind,omitempty"`
	IPProtocol      string   `yaml:"ip_protocol" json:"ip_protocol,omitempty"`
	TCPFlags        string   `yaml:"tcp_flags" json:"tcp_flags,omitempty"`
	FragmentSize    int      `yaml:"fragment_size" json:"fragment_size,omitempty"`
	BadChecksum     bool     `yaml:"bad_checksum" json:"bad_checksum,omitempty"`
	IPLength        int      `yaml:"ip_length" json:"ip_length,omitempty"`
	ForgePayloadHex string   `yaml:"forge_payload_hex" json:"forge_payload_hex,omitempty"`

	// Stage settings: deep service probes, device fingerprinting and packet
	// evidence. Service nil keeps the profile default.
	Service         *bool  `yaml:"service" json:"service,omitempty"`
	ServiceProbes   string `yaml:"service_probes" json:"service_probes,omitempty"`
	ServiceFallback string `yaml:"service_fallback" json:"service_fallback,omitempty"`
	ServiceTimeout  string `yaml:"service_timeout" json:"service_timeout,omitempty"`
	ServiceWorkers  *int   `yaml:"service_workers" json:"service_workers,omitempty"`
	ServiceRate     *int   `yaml:"service_rate" json:"service_rate,omitempty"`
	Fingerprint     bool   `yaml:"fingerprint" json:"fingerprint,omitempty"`
	PCAPNG          string `yaml:"pcapng" json:"pcapng,omitempty"`
	PCAPNGMaxMB     *int   `yaml:"pcapng_max_mb" json:"pcapng_max_mb,omitempty"`
}

// ParseFile reads and validates a YAML scan request. An empty path returns a
// zero Request, which contributes no defaults.
func ParseFile(path string) (Request, error) {
	var r Request
	if path == "" {
		return r, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return r, err
	}
	defer f.Close()
	decoder := yaml.NewDecoder(f)
	decoder.KnownFields(true)
	if err := decoder.Decode(&r); err != nil {
		return r, err
	}
	return r, nil
}

// ResolveOptions describe where a Request came from.
type ResolveOptions struct {
	// BaseDir resolves a relative UDPProbeFile (the --config file directory).
	BaseDir string
	// Remote marks a request received over the network. Remote requests may
	// not name files on the server, and PCAPNG must be a bare *.pcapng name
	// that the server places in its own evidence directory.
	Remote bool
}

// DefaultPCAPNGMaxMB is the capture size budget when a request sets none.
const DefaultPCAPNGMaxMB = 1024

// Resolved is a fully validated scan: discovery configuration plus stages.
type Resolved struct {
	Config      Config
	Service     Service
	Fingerprint bool
	// PCAPNG is the capture path as requested; for a remote request it is a
	// bare file name the caller must place in its evidence directory.
	PCAPNG         string
	PCAPNGMaxBytes int64
}

// UsesPipeline reports whether any stage beyond discovery is active.
func (r Resolved) UsesPipeline() bool {
	return r.Service.Enabled || r.Fingerprint || r.PCAPNG != ""
}

// StagePlan is the --dry-run and API plan: the discovery plan plus stages.
type StagePlan struct {
	Plan
	Service     *ServicePlan `json:"service,omitempty"`
	PCAPNG      string       `json:"pcapng,omitempty"`
	PCAPNGMaxMB int          `json:"pcapng_max_mb,omitempty"`
	DB          string       `json:"db,omitempty"`
	Fingerprint bool         `json:"fingerprint,omitempty"`
}

// Plan summarizes the resolved scan.
func (r Resolved) Plan() StagePlan {
	p := StagePlan{Plan: r.Config.Plan(), Service: r.Service.Plan(), PCAPNG: r.PCAPNG, Fingerprint: r.Fingerprint}
	if r.PCAPNG != "" {
		p.PCAPNGMaxMB = int(r.PCAPNGMaxBytes >> 20)
	}
	return p
}

// Resolve validates the request through the same Build and BuildService path
// for every interface.
func (r Request) Resolve(o ResolveOptions) (Resolved, error) {
	if o.Remote {
		if r.Profile == "research" {
			return Resolved{}, errors.New("research packet experiments require a local CLI request")
		}
		if r.UDPProbeFile != "" || r.PayloadFile != "" {
			return Resolved{}, errors.New("remote requests cannot read server files; use send_hex or send_base64")
		}
		if r.PCAPNG != "" && (filepath.Base(r.PCAPNG) != r.PCAPNG || strings.ContainsAny(r.PCAPNG, `/\`) ||
			strings.HasPrefix(r.PCAPNG, ".") || !strings.HasSuffix(r.PCAPNG, ".pcapng")) {
			return Resolved{}, errors.New("remote pcapng must be a plain file name ending in .pcapng")
		}
	}
	for _, v := range []*int{r.Rate, r.HostRate, r.SubnetRate, r.InterfaceRate, r.Workers, r.UDPRetries, r.ServiceWorkers, r.ServiceRate} {
		if v != nil && *v < 0 {
			return Resolved{}, errors.New("rates, workers and retries must be nonnegative")
		}
	}
	cfg, err := Build(Options{
		Targets: r.Targets, AllowTargets: r.AllowTargets, Profile: r.Profile, Ports: r.Ports, Protocols: r.Protocols,
		Timeout: r.Timeout, Rate: r.Rate, HostRate: r.HostRate, SubnetRate: r.SubnetRate, InterfaceRate: r.InterfaceRate,
		Workers: r.Workers, UDPRetries: r.UDPRetries,
		Payload: PayloadSource{ProbeFile: r.UDPProbeFile, SendHex: r.SendHex, SendBase64: r.SendBase64,
			PayloadFile: r.PayloadFile, BaseDir: o.BaseDir},
		TCPMode: r.TCPMode, Interface: r.Interface, SourceIP: r.SourceIP, SourceMAC: r.SourceMAC, NextHopMAC: r.NextHopMAC,
		Research: ResearchOptions{Kind: r.ResearchKind, IPProtocol: r.IPProtocol, TCPFlags: r.TCPFlags, FragmentSize: r.FragmentSize,
			BadChecksum: r.BadChecksum, IPLength: r.IPLength, PayloadHex: r.ForgePayloadHex},
	})
	if err != nil {
		return Resolved{}, err
	}
	svc, err := BuildService(cfg, ServiceOptions{Enable: r.Service, Probes: r.ServiceProbes, Fallback: r.ServiceFallback,
		Timeout: r.ServiceTimeout, Workers: r.ServiceWorkers, Rate: r.ServiceRate})
	if err != nil {
		return Resolved{}, err
	}
	res := Resolved{Config: cfg, Service: svc, PCAPNG: r.PCAPNG,
		Fingerprint: r.Fingerprint || cfg.Profile == "iot" || cfg.Profile == "ot-safe"}
	if r.PCAPNG != "" {
		mb := valueOr(r.PCAPNGMaxMB, DefaultPCAPNGMaxMB)
		if mb < 1 {
			return Resolved{}, fmt.Errorf("pcapng size budget must be at least 1 MiB")
		}
		res.PCAPNGMaxBytes = int64(mb) << 20
	} else if r.PCAPNGMaxMB != nil {
		return Resolved{}, errors.New("pcapng_max_mb requires pcapng")
	}
	return res, nil
}
