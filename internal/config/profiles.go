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
}

// profiles is the ordered catalog. The order controls how `nyxr profiles`
// lists them. Every profile named in INSTRUCTIONS.md §18 appears here so the
// set is complete and self-documenting; ones whose engine does not exist yet
// are marked planned rather than omitted.
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
		Name: "udp", Description: "Protocol-aware UDP probes (DNS, NTP)",
		Availability: StatusAvailable,
		Ports:        "53,123", Protocols: "udp", Timeout: "1500ms", Rate: 50, Workers: 32,
	},
	{
		Name: "udp-deep", Description: "UDP probes including SNMP, one extra retry each",
		Availability: StatusAvailable,
		Ports:        "53,123,161", Protocols: "udp", Timeout: "2s", Rate: 25, Workers: 16, UDPRetries: 1,
	},
	{
		Name: "ot-safe", Description: "Low-rate, read-only, TCP-only OT identification",
		Availability: StatusAvailable,
		Ports:        "80,443,502", Protocols: "tcp", Timeout: "3s", Rate: 5, Workers: 4,
		Enforce: Enforcement{TCPOnly: true, ReadOnly: true, MaxRate: 5, MaxWorkers: 4, MinTimeout: 3 * time.Second},
	},
	{
		Name: "custom", Description: "Minimal profile; supply protocols, ports and timeout explicitly",
		Availability: StatusAvailable,
		// Ports/Protocols/Timeout are intentionally empty so the caller must
		// choose them; rate and workers keep usable defaults.
		Rate: 100, Workers: 64,
	},

	// Planned profiles depend on engines that later roadmap phases deliver.
	{Name: "service", Description: "Service and version detection on discovered ports",
		Availability: StatusPlanned, Requires: "the deep service-probe engine (ROADMAP Phase 3)"},
	{Name: "deep", Description: "Discovery plus TLS/HTTP/SSH/DNS interrogation",
		Availability: StatusPlanned, Requires: "deep service probes and the TLS subsystem (ROADMAP Phase 3)"},
	{Name: "web", Description: "HTTP/HTTPS/TLS focused service detection",
		Availability: StatusPlanned, Requires: "HTTP and TLS service probes (ROADMAP Phase 3)"},
	{Name: "database", Description: "Database protocol handshakes (Redis, Mongo, SQL)",
		Availability: StatusPlanned, Requires: "database protocol probes (ROADMAP Phase 3)"},
	{Name: "iot", Description: "Device fingerprinting from mDNS/SSDP/SNMP/banners",
		Availability: StatusPlanned, Requires: "the device fingerprint engine (ROADMAP Phase 4)"},
	{Name: "full", Description: "Discovery plus full deep service detection",
		Availability: StatusPlanned, Requires: "the combined discovery and deep-probe pipeline (ROADMAP Phase 3+)"},
	{Name: "research", Description: "Packet-forge experiments with malformed packets",
		Availability: StatusPlanned, Requires: "the packet forge and research policy (ROADMAP Phase 5)"},
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
