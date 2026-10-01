package config

import (
	"fmt"
	"time"
)

// Availability records whether a profile can run against the engine that
// exists today. Planned profiles are recognized and listed so the CLI and a
// future API give one honest answer about what is implemented, but selecting
// one is a clear error rather than a silent downgrade to a weaker scan.
type Availability string

const (
	StatusAvailable Availability = "available"
	StatusPlanned   Availability = "planned"
)

// Enforcement expresses the hard limits a profile places on the resolved
// configuration. Empty fields impose no limit. ot-safe uses this to guarantee
// low-rate, read-only, TCP-only behavior no matter what flags are supplied.
type Enforcement struct {
	TCPOnly    bool
	ReadOnly   bool // reject custom UDP payloads
	MaxRate    int  // 0 = no cap; otherwise rate must be 1..MaxRate (unlimited is refused)
	MaxWorkers int  // 0 = no cap
	MinTimeout time.Duration
}

func (e Enforcement) check(name string, tcp, udp, icmp, arp, ndp bool, rate, workers int, timeout time.Duration, hasCustomPayload bool) error {
	if e.TCPOnly && (udp || icmp || arp || ndp) {
		return fmt.Errorf("%s profile is TCP connect only", name)
	}
	if e.ReadOnly && hasCustomPayload {
		return fmt.Errorf("%s profile does not allow custom payloads", name)
	}
	if e.MaxRate > 0 && (rate <= 0 || rate > e.MaxRate) {
		return fmt.Errorf("%s profile requires a rate of 1..%d probes/second", name, e.MaxRate)
	}
	if e.MaxWorkers > 0 && workers > e.MaxWorkers {
		return fmt.Errorf("%s profile requires workers <= %d", name, e.MaxWorkers)
	}
	if e.MinTimeout > 0 && timeout < e.MinTimeout {
		return fmt.Errorf("%s profile requires a timeout >= %s", name, e.MinTimeout)
	}
	return nil
}

// Profile is a named set of defaults plus optional enforced limits. The
// defaults fill any field the caller left empty; enforcement is applied after
// resolution and cannot be overridden.
type Profile struct {
	Name         string
	Description  string
	Availability Availability
	// Requires explains the prerequisite when Availability is planned.
	Requires string

	Ports      string
	Protocols  string
	Timeout    string
	Rate       int
	Workers    int
	UDPRetries int
	Enforce    Enforcement
	// Service enables the deep-probe stage by default when non-nil.
	Service *ServiceDefaults
}

// profiles is the ordered catalog. The order controls how `nyxr profiles`
// lists them. Every profile named in docs/architecture/design.md §18 appears
// here so the set is complete and self-documenting; ones whose engine does
// not exist yet are marked planned rather than omitted.
var profiles = []Profile{
	{
		Name: "discovery", Description: "Common TCP ports, unprivileged connect scan",
		Availability: StatusAvailable,
		Ports:        "22,80,443", Protocols: "tcp", Timeout: "1s", Rate: 100, Workers: 64,
	},
	{
		Name: "fast", Description: "Top 100 TCP ports at higher concurrency (connect scan)",
		Availability: StatusAvailable,
		Ports:        "top100", Protocols: "tcp", Timeout: "700ms", Rate: 1000, Workers: 256,
	},
	{
		Name: "tcp", Description: "TCP connect scan of common ports",
		Availability: StatusAvailable,
		Ports:        "22,80,443", Protocols: "tcp", Timeout: "1s", Rate: 100, Workers: 64,
	},
	{
		Name: "udp-basic", Description: "Empty UDP datagram with response and ICMP classification",
		Availability: StatusAvailable,
		Ports:        "53,123", Protocols: "udp", Timeout: "1500ms", Rate: 50, Workers: 32,
	},
	{
		Name: "udp-common", Description: "UDP payloads associated with each selected port",
		Availability: StatusAvailable,
		Ports:        "53,67,69,88,111,123,137,161,389,427,500,523,623,1604,1701,1812,1813,1900,2049,3478,5060,5353,5355,5683,9987,11211,23000,27015,27900,27960,28900,47808", Protocols: "udp", Timeout: "1500ms", Rate: 50, Workers: 32,
	},
	{
		Name: "udp", Description: "Compatibility profile using udp-common selection",
		Availability: StatusAvailable,
		Ports:        "53,123", Protocols: "udp", Timeout: "1500ms", Rate: 50, Workers: 32,
	},
	{
		Name: "udp-deep", Description: "Try every available UDP payload on each selected port",
		Availability: StatusAvailable,
		Ports:        "53,67,69,88,111,123,137,161,389,427,500,523,623,1604,1701,1812,1813,1900,2049,3478,5060,5353,5355,5683,9987,11211,23000,27015,27900,27960,28900,47808", Protocols: "udp", Timeout: "2s", Rate: 25, Workers: 16, UDPRetries: 1,
	},
	{
		Name: "ot-safe", Description: "Allowlisted, low-rate Modbus and EtherNet/IP identity reads",
		Availability: StatusAvailable,
		Ports:        "80,443,502,44818", Protocols: "tcp", Timeout: "3s", Rate: 5, Workers: 4,
		Enforce: Enforcement{TCPOnly: true, ReadOnly: true, MaxRate: 5, MaxWorkers: 4, MinTimeout: 3 * time.Second},
		Service: &ServiceDefaults{Probes: "modbus,ethernetip", Fallback: "none", Timeout: "3s", Workers: 4, Rate: 5},
	},
	{
		Name: "custom", Description: "Minimal profile; supply protocols, ports and timeout explicitly",
		Availability: StatusAvailable,
		// Ports/Protocols/Timeout are intentionally empty so the caller must
		// choose them; rate and workers keep usable defaults.
		Rate: 100, Workers: 64,
	},

	{
		Name: "service", Description: "Top 100 TCP ports, then banner/SSH/TLS/HTTP/DNS/SOCKS identification",
		Availability: StatusAvailable,
		Ports:        "top100", Protocols: "tcp", Timeout: "1s", Rate: 100, Workers: 64,
		Service: &ServiceDefaults{Probes: "banner,ssh,tls,http,dns,socks", Fallback: "http", Timeout: "5s", Workers: 16, Rate: 50},
	},
	{
		Name: "deep", Description: "Discovery plus TLS/HTTP/SSH/DNS interrogation, trying TLS and HTTP on every open port",
		Availability: StatusAvailable,
		Ports:        "top100", Protocols: "tcp", Timeout: "1s", Rate: 100, Workers: 64,
		Service: &ServiceDefaults{Probes: "banner,ssh,tls,http,dns,socks", Fallback: "tls,http", Timeout: "8s", Workers: 32, Rate: 50},
	},
	{
		Name: "web", Description: "HTTP/HTTPS/TLS focused service detection",
		Availability: StatusAvailable,
		Ports:        "80,443,3000,5000,8000,8008,8080,8081,8443,8888,9000,9443", Protocols: "tcp", Timeout: "1s", Rate: 100, Workers: 64,
		Service: &ServiceDefaults{Probes: "tls,http", Fallback: "tls,http", Timeout: "5s", Workers: 16, Rate: 50},
	},
	{
		Name: "full", Description: "All TCP ports plus full deep service detection",
		Availability: StatusAvailable,
		Ports:        "all", Protocols: "tcp", Timeout: "1s", Rate: 1000, Workers: 256,
		Service: &ServiceDefaults{Probes: "banner,ssh,tls,http,dns,socks", Fallback: "tls,http", Timeout: "8s", Workers: 32, Rate: 50},
	},

	{Name: "database", Description: "SQL, NoSQL, graph, search and cache service identification",
		Availability: StatusAvailable,
		Ports:        "database", Protocols: "tcp", Timeout: "1s", Rate: 100, Workers: 64,
		Service: &ServiceDefaults{Probes: "database", Fallback: "none", Timeout: "4s", Workers: 16, Rate: 50}},
	{Name: "iot", Description: "Device fingerprinting from safe service and discovery signals",
		Availability: StatusAvailable, Ports: "22,80,443,502,8080,8443,44818", Protocols: "tcp", Timeout: "2s", Rate: 20, Workers: 16,
		Service: &ServiceDefaults{Probes: "banner,ssh,tls,http,modbus,ethernetip", Fallback: "none", Timeout: "4s", Workers: 8, Rate: 20}},
	{Name: "research", Description: "Allowlisted, low-rate raw packet experiments",
		Availability: StatusAvailable, Ports: "80", Protocols: "tcp", Timeout: "1s", Rate: 5, Workers: 1},
}

// Profiles returns the catalog in display order. The slice is a copy so callers
// cannot mutate the registry.
func Profiles() []Profile {
	out := make([]Profile, len(profiles))
	copy(out, profiles)
	return out
}

// LookupProfile finds a profile by name.
func LookupProfile(name string) (Profile, bool) {
	for _, p := range profiles {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

// DefaultProfile is used when no profile is selected.
const DefaultProfile = "discovery"
