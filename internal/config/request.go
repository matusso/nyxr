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
	NmapUDPProbes   string   `yaml:"nmap_udp_probes" json:"nmap_udp_probes,omitempty"`
	UDPProbeFile    string   `yaml:"udp_probe_file" json:"udp_probe_file,omitempty"`
	SendHex         string   `yaml:"send_hex" json:"send_hex,omitempty"`
	SendBase64      string   `yaml:"send_base64" json:"send_base64,omitempty"`
	PayloadFile     string   `yaml:"payload_file" json:"payload_file,omitempty"`
	TCPMode         string   `yaml:"tcp_mode" json:"tcp_mode,omitempty"`
	Interface       string   `yaml:"interface" json:"interface,omitempty"`
	XDPPinDir       string   `yaml:"xdp_pin_dir" json:"xdp_pin_dir,omitempty"`
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
	Service             *bool  `yaml:"service" json:"service,omitempty"`
	ServiceProbes       string `yaml:"service_probes" json:"service_probes,omitempty"`
	ServiceFallback     string `yaml:"service_fallback" json:"service_fallback,omitempty"`
	ServiceTimeout      string `yaml:"service_timeout" json:"service_timeout,omitempty"`
	ServiceWorkers      *int   `yaml:"service_workers" json:"service_workers,omitempty"`
	ServiceRate         *int   `yaml:"service_rate" json:"service_rate,omitempty"`
	NmapServiceProbes   string `yaml:"nmap_service_probes" json:"nmap_service_probes,omitempty"`
	ProtocolDefinitions string `yaml:"protocol_definitions" json:"protocol_definitions,omitempty"`
	NSEScripts          string `yaml:"nse_scripts" json:"nse_scripts,omitempty"`
	NSETimeout          string `yaml:"nse_timeout" json:"nse_timeout,omitempty"`
	Fingerprint         bool   `yaml:"fingerprint" json:"fingerprint,omitempty"`
	PCAPNG              string `yaml:"pcapng" json:"pcapng,omitempty"`
	PCAPNGMaxMB         *int   `yaml:"pcapng_max_mb" json:"pcapng_max_mb,omitempty"`

	// KnownOpen rescans only the ports the database last saw open; Targets
	// then narrow the stored addresses (IPs, CIDRs or ranges).
	KnownOpen bool `yaml:"known_open" json:"known_open,omitempty"`
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
	// KnownOpen supplies stored open ports for a KnownOpen request.
	KnownOpen KnownPortSource
}

// DefaultPCAPNGMaxMB is the capture size budget when a request sets none.
const DefaultPCAPNGMaxMB = 1024

// Resolved is a fully validated scan: discovery configuration plus stages.
type Resolved struct {
	Config      Config
	Service     Service
	NSE         NSE
	Fingerprint bool
	// PCAPNG is the capture path as requested; for a remote request it is a
	// bare file name the caller must place in its evidence directory.
	PCAPNG         string
	PCAPNGMaxBytes int64
}

// UsesPipeline reports whether any stage beyond discovery is active.
func (r Resolved) UsesPipeline() bool {
	return r.Service.Enabled || r.NSE.Enabled() || r.Fingerprint || r.PCAPNG != ""
}

// StagePlan is the --dry-run and API plan: the discovery plan plus stages.
type StagePlan struct {
	Plan
	Service     *ServicePlan `json:"service,omitempty"`
	NSE         *NSEPlan     `json:"nse,omitempty"`
	PCAPNG      string       `json:"pcapng,omitempty"`
	PCAPNGMaxMB int          `json:"pcapng_max_mb,omitempty"`
	DB          string       `json:"db,omitempty"`
	Fingerprint bool         `json:"fingerprint,omitempty"`
}

// Plan summarizes the resolved scan.
func (r Resolved) Plan() StagePlan {
	p := StagePlan{Plan: r.Config.Plan(), Service: r.Service.Plan(), NSE: r.NSE.Plan(), PCAPNG: r.PCAPNG, Fingerprint: r.Fingerprint}
	if r.PCAPNG != "" {
		p.PCAPNGMaxMB = int(r.PCAPNGMaxBytes >> 20)
	}
	return p
}

// Resolve validates the request through the same Build and BuildService path
// for every interface.
func (r Request) Resolve(o ResolveOptions) (Resolved, error) {
	if o.Remote {
		if r.XDPPinDir != "" {
			return Resolved{}, errors.New("AF_XDP pin directory requires a local CLI request")
		}
		if r.Profile == "research" {
			return Resolved{}, errors.New("research packet experiments require a local CLI request")
		}
		if r.UDPProbeFile != "" || r.PayloadFile != "" || r.NmapUDPProbes != "" {
			return Resolved{}, errors.New("remote requests cannot read server files; use send_hex or send_base64")
		}
		if r.NmapServiceProbes != "" {
			return Resolved{}, errors.New("remote requests cannot read server files; nmap_service_probes is a local path")
		}
		if r.ProtocolDefinitions != "" {
			return Resolved{}, errors.New("remote requests cannot read server files; protocol_definitions is a local path")
		}
		if r.NSEScripts != "" || r.NSETimeout != "" {
			return Resolved{}, errors.New("NSE scripts require a local CLI request")
		}
		if r.PCAPNG != "" && (filepath.Base(r.PCAPNG) != r.PCAPNG || strings.ContainsAny(r.PCAPNG, `/\`) ||
			strings.HasPrefix(r.PCAPNG, ".") || !strings.HasSuffix(r.PCAPNG, ".pcapng")) {
			return Resolved{}, errors.New("remote pcapng must be a plain file name ending in .pcapng")
		}
	}
	var restrict TargetPorts
	if r.KnownOpen {
		var err error
		if restrict, err = r.applyKnownOpen(o.KnownOpen); err != nil {
			return Resolved{}, err
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
		Workers: r.Workers, UDPRetries: r.UDPRetries, NmapUDPProbes: r.NmapUDPProbes,
		Payload: PayloadSource{ProbeFile: r.UDPProbeFile, SendHex: r.SendHex, SendBase64: r.SendBase64,
			PayloadFile: r.PayloadFile, BaseDir: o.BaseDir},
		TCPMode: r.TCPMode, Interface: r.Interface, XDPPinDir: r.XDPPinDir, SourceIP: r.SourceIP, SourceMAC: r.SourceMAC, NextHopMAC: r.NextHopMAC,
		Research: ResearchOptions{Kind: r.ResearchKind, IPProtocol: r.IPProtocol, TCPFlags: r.TCPFlags, FragmentSize: r.FragmentSize,
			BadChecksum: r.BadChecksum, IPLength: r.IPLength, PayloadHex: r.ForgePayloadHex},
	})
	if err != nil {
		return Resolved{}, err
	}
	cfg.TargetPorts = restrict
	svc, err := BuildService(cfg, ServiceOptions{Enable: r.Service, Probes: r.ServiceProbes, Fallback: r.ServiceFallback,
		Timeout: r.ServiceTimeout, Workers: r.ServiceWorkers, Rate: r.ServiceRate, NmapProbes: r.NmapServiceProbes,
		ProtocolDefinitions: r.ProtocolDefinitions, BaseDir: o.BaseDir})
	if err != nil {
		return Resolved{}, err
	}
	nse, err := BuildNSE(cfg, r.NSEScripts, r.NSETimeout)
	if err != nil {
		return Resolved{}, err
	}
	res := Resolved{Config: cfg, Service: svc, NSE: nse, PCAPNG: r.PCAPNG,
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
