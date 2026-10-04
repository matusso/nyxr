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

	Ports string
	// UDPPorts, when set, replaces Ports for UDP so a mixed profile can scan
	// every TCP port without sending UDP to all of them. An explicit --ports
	// applies to both protocols.
	UDPPorts   string
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
// lists them. The tcp-* and udp-* families grow in depth from basic (find
// open ports) through common (identify what answers on common ports) to full
// (every port or every payload); deep-scan combines both transports, windows
// targets the services a Windows host and domain propagate, and filesystem
// targets network file systems and object storage. Profiles whose engine does
// not exist yet are marked planned rather than omitted.
var profiles = []Profile{
	{
		Name: "tcp-basic", Description: "Top 100 TCP ports, connect scan, open ports only (the default)",
		Availability: StatusAvailable,
		Ports:        "top100", Protocols: "tcp", Timeout: "1s", Rate: 300, Workers: 128,
	},
	{
		Name: "tcp-common", Description: "Top 1000 TCP ports, then banner/SSH/TLS/HTTP/DNS/SOCKS identification",
		Availability: StatusAvailable,
		Ports:        "top1000", Protocols: "tcp", Timeout: "1s", Rate: 500, Workers: 256,
		Service: &ServiceDefaults{Probes: "banner,ssh,tls,http,dns,socks", Fallback: "tls,http", Timeout: "5s", Workers: 32, Rate: 50},
	},
	{
		Name: "tcp-full", Description: "All 65535 TCP ports, then full service identification",
		Availability: StatusAvailable,
		Ports:        "all", Protocols: "tcp", Timeout: "1s", Rate: 1000, Workers: 256,
		Service: &ServiceDefaults{Probes: "banner,ssh,tls,http,dns,socks,database", Fallback: "tls,http,database", Timeout: "8s", Workers: 32, Rate: 50},
	},
	{
		Name: "udp-basic", Description: "Empty UDP datagram per port with response and ICMP classification",
		Availability: StatusAvailable,
		Ports:        "udp", Protocols: "udp", Timeout: "1500ms", Rate: 50, Workers: 32,
	},
	{
		Name: "udp-common", Description: "UDP payloads associated with each selected port",
		Availability: StatusAvailable,
		Ports:        "udp", Protocols: "udp", Timeout: "1500ms", Rate: 50, Workers: 32,
	},
	{
		Name: "udp-full", Description: "Every available UDP payload on each selected port, one retry",
		Availability: StatusAvailable,
		Ports:        "udp", Protocols: "udp", Timeout: "2s", Rate: 25, Workers: 16, UDPRetries: 1,
	},
	{
		Name: "deep-scan", Description: "tcp-full plus udp-common: all TCP ports with service identification and common UDP ports",
		Availability: StatusAvailable,
		Ports:        "all", UDPPorts: "udp", Protocols: "tcp,udp", Timeout: "1500ms", Rate: 1000, Workers: 256,
		Service: &ServiceDefaults{Probes: "banner,ssh,tls,http,dns,socks,database", Fallback: "tls,http,database", Timeout: "8s", Workers: 32, Rate: 50},
	},
	{
		Name: "windows", Description: "Windows/Active Directory hosts: SMB, RDP, MSRPC, NetBIOS, WinRM, LDAP and Kerberos with deep identification",
		Availability: StatusAvailable,
		// UDP counterparts: Kerberos (88), Windows time (123), NetBIOS
		// name/datagram (137/138), SNMP (161), CLDAP domain locator (389),
		// SSDP (1900), mDNS (5353) and LLMNR (5355).
		Ports: "windows", UDPPorts: "88,123,137,138,161,389,1900,5353,5355", Protocols: "tcp,udp", Timeout: "1500ms", Rate: 300, Workers: 128,
		Service: &ServiceDefaults{Probes: "banner,smb,rdp,msrpc,ldap,kerberos,tls,http,ssh,database", Fallback: "tls,http", Timeout: "6s", Workers: 32, Rate: 50},
	},
	{
		Name: "filesystem", Description: "Network file systems and object storage: NFS, SMB/CIFS, Ceph, GlusterFS, iSCSI, MinIO and S3-compatible storage",
		Availability: StatusAvailable,
		Ports:        "filesystem", Protocols: "tcp", Timeout: "2s", Rate: 200, Workers: 64,
		Service: &ServiceDefaults{Probes: "banner,nfs,smb,ldap,http,tls,ssh", Fallback: "tls,http", Timeout: "6s", Workers: 32, Rate: 50},
	},
	{
		Name: "web", Description: "Common HTTP/HTTPS ports, trying TLS and HTTP on each open one",
		Availability: StatusAvailable,
		Ports:        "web", Protocols: "tcp", Timeout: "1s", Rate: 200, Workers: 64,
		Service: &ServiceDefaults{Probes: "tls,http", Fallback: "tls,http", Timeout: "5s", Workers: 16, Rate: 50},
	},
	{Name: "database", Description: "SQL, NoSQL, graph, search and cache service identification",
		Availability: StatusAvailable,
		Ports:        "database", Protocols: "tcp", Timeout: "1s", Rate: 100, Workers: 64,
		Service: &ServiceDefaults{Probes: "database", Fallback: "database", Timeout: "4s", Workers: 16, Rate: 50}},
	{Name: "iot", Description: "Device fingerprinting from safe service and discovery signals",
		Availability: StatusAvailable, Ports: "22,80,443,502,8080,8443,44818", Protocols: "tcp", Timeout: "2s", Rate: 20, Workers: 16,
		Service: &ServiceDefaults{Probes: "banner,ssh,tls,http,modbus,ethernetip", Fallback: "none", Timeout: "4s", Workers: 8, Rate: 20}},
	{
		Name: "ot-safe", Description: "Allowlisted, low-rate Modbus and EtherNet/IP identity reads",
		Availability: StatusAvailable,
		Ports:        "80,443,502,44818", Protocols: "tcp", Timeout: "3s", Rate: 5, Workers: 4,
		Enforce: Enforcement{TCPOnly: true, ReadOnly: true, MaxRate: 5, MaxWorkers: 4, MinTimeout: 3 * time.Second},
		Service: &ServiceDefaults{Probes: "modbus,ethernetip", Fallback: "none", Timeout: "3s", Workers: 4, Rate: 5},
	},
	{Name: "research", Description: "Allowlisted, low-rate raw packet experiments",
		Availability: StatusAvailable, Ports: "80", Protocols: "tcp", Timeout: "1s", Rate: 5, Workers: 1},
	{
		Name: "custom", Description: "Minimal profile; supply protocols, ports and timeout explicitly",
		Availability: StatusAvailable,
		// Ports/Protocols/Timeout are intentionally empty so the caller must
		// choose them; rate and workers keep usable defaults.
		Rate: 100, Workers: 64,
	},
}

// renamedProfiles maps names from the earlier catalog to their replacement so
// an old script or configuration file fails with a pointer, not a bare
// "unknown profile".
var renamedProfiles = map[string]string{
	"discovery": "tcp-basic",
	"fast":      "tcp-basic",
	"tcp":       "tcp-basic",
	"service":   "tcp-common",
	"deep":      "tcp-common",
	"udp":       "udp-common",
	"udp-deep":  "udp-full",
	"full":      "deep-scan",
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
const DefaultProfile = "tcp-basic"
