package probe

import (
	"fmt"

	"github.com/matusso/nyxr/internal/nmapdb"
)

// FromNmapUDP maps port-directed UDP requests from an operator-supplied
// nmap-service-probes database to the scan's selected ports. An arbitrary
// response confirms a UDP listener but does not confirm the probe's service.
func FromNmapUDP(db *nmapdb.Database, scanPorts []uint16) ([]Probe, error) {
	if db == nil {
		return nil, nil
	}
	probes := make([]Probe, 0)
	for _, source := range db.Probes {
		if source.Proto != "UDP" || len(source.Payload) == 0 || len(source.Ports) == 0 ||
			len(source.Payload) > 1400 {
			continue
		}
		var ports []uint16
		for _, port := range scanPorts {
			if excludedUDP(db.Exclude, port) {
				continue
			}
			for _, candidate := range source.Ports {
				if candidate.Contains(port) {
					ports = append(ports, port)
					break
				}
			}
		}
		if len(ports) > 0 {
			probes = append(probes, Probe{Name: "nmap-" + source.Name,
				Ports: ports, Payload: append([]byte(nil), source.Payload...), Matcher: "any"})
		}
		if len(probes) > 256 {
			return nil, fmt.Errorf("nmap-service-probes has more than 256 applicable UDP payloads")
		}
	}
	return probes, nil
}

func excludedUDP(ranges []nmapdb.PortRange, port uint16) bool {
	for _, r := range ranges {
		if r.UDP && r.Contains(port) {
			return true
		}
	}
	return false
}
