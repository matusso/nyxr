package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/nmapdb"
	"github.com/matusso/nyxr/internal/probe"
)

// Options are the interface-agnostic inputs to a scan. The CLI fills these from
// merged flags and file configuration; an API would fill them from a request.
// Build turns Options into a validated Config, so every interface shares one
// resolution and validation path.
type Options struct {
	Targets       []string
	AllowTargets  []string
	Profile       string
	Ports         string
	Protocols     string
	Timeout       string
	Rate          *int
	HostRate      *int
	SubnetRate    *int
	InterfaceRate *int
	Workers       *int
	UDPRetries    *int
	NmapUDPProbes string // local nmap-service-probes file for UDP payload selection
	Payload       PayloadSource
	TCPMode       string
	Interface     string
	SourceIP      string
	SourceMAC     string
	NextHopMAC    string
	Research      ResearchOptions
}

type ResearchOptions struct {
	Kind         string
	IPProtocol   string
	TCPFlags     string
	FragmentSize int
	BadChecksum  bool
	IPLength     int
	PayloadHex   string
}

// PayloadSource selects at most one custom UDP payload. When any field is set
// the payload replaces the built-in probes for the scan.
type PayloadSource struct {
	ProbeFile   string // native YAML probe definition
	SendHex     string
	SendBase64  string
	PayloadFile string // raw bytes
	// BaseDir resolves a relative ProbeFile. The CLI sets it to the scan
	// configuration file's directory when the probe path came from that file.
	BaseDir string
}

func (p PayloadSource) count() int {
	n := 0
	for _, v := range []string{p.ProbeFile, p.SendHex, p.SendBase64, p.PayloadFile} {
		if v != "" {
			n++
		}
	}
	return n
}

const maxUDPPayload = 65507

// load returns the custom probes described by the source. udp reports whether
// UDP is one of the scan protocols; a custom payload without UDP is rejected.
func (p PayloadSource) load(udp bool) ([]probe.Probe, error) {
	if p.count() == 0 {
		return nil, nil
	}
	if p.count() > 1 {
		return nil, errors.New("choose one custom UDP payload source")
	}
	if !udp {
		return nil, errors.New("custom UDP payload requires the UDP protocol")
	}
	if p.ProbeFile != "" {
		path := p.ProbeFile
		if p.BaseDir != "" && !filepath.IsAbs(path) {
			path = filepath.Join(p.BaseDir, path)
		}
		loaded, err := probe.LoadFile(path)
		if err != nil {
			return nil, err
		}
		return []probe.Probe{loaded}, nil
	}
	var (
		payload []byte
		name    string
		err     error
	)
	switch {
	case p.SendHex != "":
		payload, err = hex.DecodeString(strings.Join(strings.Fields(p.SendHex), ""))
		name = "custom-hex"
	case p.SendBase64 != "":
		payload, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(p.SendBase64), ""))
		name = "custom-base64"
	case p.PayloadFile != "":
		f, openErr := os.Open(p.PayloadFile)
		if openErr != nil {
			return nil, openErr
		}
		payload, err = io.ReadAll(io.LimitReader(f, maxUDPPayload+1))
		_ = f.Close()
		name = "custom-file"
	}
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || len(payload) > maxUDPPayload {
		return nil, fmt.Errorf("custom UDP payload must contain 1..%d bytes", maxUDPPayload)
	}
	return []probe.Probe{{Name: name, Payload: payload, Matcher: "any"}}, nil
}

// Build resolves Options against the selected profile and returns a validated
// Config. Explicit Options fields take precedence over profile defaults; a
// planned profile, an unknown profile, or a value that violates a profile's
// enforced limits is an error.
func Build(o Options) (Config, error) {
	name := strings.TrimSpace(o.Profile)
	if name == "" {
		name = DefaultProfile
	}
	profile, ok := LookupProfile(name)
	if !ok {
		return Config{}, fmt.Errorf("unknown profile %q (run: nyxr profiles)", name)
	}
	if profile.Availability == StatusPlanned {
		return Config{}, fmt.Errorf("profile %q is planned but not implemented yet: it needs %s", name, profile.Requires)
	}
	if name == "research" {
		return buildResearch(o, profile)
	}
	if o.Research != (ResearchOptions{}) {
		return Config{}, errors.New("research packet controls require --profile research")
	}
	custom := name == "custom"

	protocolsInput := first(o.Protocols, defaultUnless(custom, profile.Protocols))
	if protocolsInput == "" {
		return Config{}, fmt.Errorf("profile %q requires --protocols", name)
	}
	tcp, udp, icmp, arp, ndp, err := ParseProtocols(protocolsInput)
	if err != nil {
		return Config{}, err
	}

	var ports []uint16
	if tcp || udp {
		portsInput := first(o.Ports, defaultUnless(custom, profile.Ports))
		if portsInput == "" {
			return Config{}, fmt.Errorf("profile %q requires --ports", name)
		}
		ports, err = ResolvePorts(portsInput)
		if err != nil {
			return Config{}, err
		}
	}

	timeoutInput := first(o.Timeout, defaultUnless(custom, profile.Timeout))
	if timeoutInput == "" {
		return Config{}, fmt.Errorf("profile %q requires --timeout", name)
	}
	timeout, err := time.ParseDuration(timeoutInput)
	if err != nil {
		return Config{}, err
	}

	rate := valueOr(o.Rate, profile.Rate)
	workers := valueOr(o.Workers, profile.Workers)
	retries := valueOr(o.UDPRetries, profile.UDPRetries)
	udpMode := UDPCommon
	switch name {
	case "udp-basic":
		udpMode = UDPBasic
	case "udp-deep":
		udpMode = UDPDeep
	}
	if !udp {
		udpMode = ""
	}
	if udpMode == UDPBasic && (o.Payload.count() != 0 || o.NmapUDPProbes != "") {
		return Config{}, errors.New("udp-basic does not accept UDP payload files or custom payloads")
	}

	udpProbes, err := o.Payload.load(udp)
	if err != nil {
		return Config{}, err
	}
	var nmapUDPSHA string
	if o.NmapUDPProbes != "" {
		if !udp || len(udpProbes) != 0 {
			return Config{}, errors.New("Nmap UDP probes require UDP scanning without a custom payload")
		}
		db, err := nmapdb.LoadFile(o.NmapUDPProbes)
		if err != nil {
			return Config{}, fmt.Errorf("nmap UDP probes: %w", err)
		}
		nmapUDPSHA = db.SHA256
		udpProbes, err = probe.Builtins()
		if err != nil {
			return Config{}, err
		}
		imported, err := probe.FromNmapUDP(db, ports)
		if err != nil {
			return Config{}, err
		}
		udpProbes = append(udpProbes, imported...)
	}
	mode := first(o.TCPMode, "connect")
	var sourceIP netip.Addr
	if o.SourceIP != "" {
		sourceIP, err = netip.ParseAddr(o.SourceIP)
		if err != nil {
			return Config{}, fmt.Errorf("source IP: %w", err)
		}
	}
	var nextHopMAC net.HardwareAddr
	if o.NextHopMAC != "" {
		nextHopMAC, err = net.ParseMAC(o.NextHopMAC)
		if err != nil {
			return Config{}, fmt.Errorf("next-hop MAC: %w", err)
		}
	}
	var sourceMAC net.HardwareAddr
	if o.SourceMAC != "" {
		sourceMAC, err = net.ParseMAC(o.SourceMAC)
		if err != nil {
			return Config{}, fmt.Errorf("source MAC: %w", err)
		}
	}

	if err := profile.Enforce.check(name, tcp, udp, icmp, arp, ndp, rate, workers, timeout, len(udpProbes) > 0); err != nil {
		return Config{}, err
	}

	targets, err := ParseTargets(o.Targets)
	if err != nil {
		return Config{}, err
	}
	allowTargets, err := ParseAllowTargets(o.AllowTargets)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		Targets: targets, AllowTargets: allowTargets, Ports: ports, TCP: tcp, UDP: udp, ICMP: icmp, ARP: arp, NDP: ndp,
		Timeout: timeout, Rate: rate, HostRate: valueOr(o.HostRate, 0), SubnetRate: valueOr(o.SubnetRate, 0),
		InterfaceRate: valueOr(o.InterfaceRate, 0), Workers: workers, Profile: name,
		UDPProbes: udpProbes, UDPMode: udpMode, UDPRetries: retries, NmapUDPSource: o.NmapUDPProbes, NmapUDPSHA: nmapUDPSHA,
		TCPMode: mode, Interface: o.Interface, SourceIP: sourceIP, SourceMAC: sourceMAC, NextHopMAC: nextHopMAC,
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func first(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// defaultUnless returns "" for the custom profile so its fields stay empty and
// must be supplied explicitly; other profiles contribute their default.
func defaultUnless(custom bool, value string) string {
	if custom {
		return ""
	}
	return value
}

func valueOr(override *int, fallback int) int {
	if override != nil {
		return *override
	}
	return fallback
}
