package probe

import "github.com/matusso/nyxr/internal/nmapdb"

// FromNmapUDP imports UDP requests from an operator-supplied database.
// Declared ports only prioritize requests on those ports; all requests are
// available on every selected scan port. An arbitrary response confirms a
// UDP listener but does not confirm the probe's service.
func FromNmapUDP(db *nmapdb.Database, scanPorts []uint16) ([]Probe, error) {
	if db == nil {
		return nil, nil
	}
	probes := make([]Probe, 0)
	for _, source := range db.Probes {
		if source.Proto != "UDP" || len(source.Payload) == 0 || len(source.Payload) > maxPayload {
			continue
		}
		var ports []uint16
		for _, port := range scanPorts {
			for _, candidate := range source.Ports {
				if candidate.Contains(port) {
					ports = append(ports, port)
					break
				}
			}
		}
		probes = append(probes, Probe{Name: "nmap-" + source.Name,
			Ports: ports, PortsDeclared: len(source.Ports) != 0,
			Payload: append([]byte(nil), source.Payload...), Matcher: "any"})
	}
	return probes, nil
}
