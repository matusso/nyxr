// Package device combines independent observations into cautious device
// classifications. It never infers a device type from an open port alone.
package device

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

type state struct {
	signals       []observe.DeviceSignal
	seen          map[string]bool
	verified      map[string]bool
	ports         map[uint16]bool
	stackOS       map[string]int
	applicationOS map[string]bool
}

type Collector struct{ devices map[netip.Addr]*state }

func New() *Collector { return &Collector{devices: make(map[netip.Addr]*state)} }

func (c *Collector) Add(o observe.Observation) {
	if o.Kind == observe.KindDevice || o.Target.IsValid() == false {
		return
	}
	s := c.devices[o.Target]
	if s == nil {
		s = &state{seen: map[string]bool{}, verified: map[string]bool{}, ports: map[uint16]bool{}, stackOS: map[string]int{}, applicationOS: map[string]bool{}}
		c.devices[o.Target] = s
	}
	if o.Kind == observe.KindPort && o.State == "open" && o.Transport == "tcp" {
		s.ports[o.Port] = true
	}
	if o.Kind == observe.KindPort && o.TCPStack != nil && o.TCPStack.Status == observe.FingerprintMatched {
		for _, candidate := range o.TCPStack.Candidates {
			s.stackOS[candidate.Family] = max(s.stackOS[candidate.Family], candidate.Confidence)
			c.add(s, "tcp-stack:"+candidate.Family, o, fmt.Sprintf("%s-like TCP stack (%d%%): %s", candidate.Family, candidate.Confidence, o.TCPStack.Signature))
		}
	}
	if o.MAC != "" {
		parts := strings.Split(strings.ToUpper(o.MAC), ":")
		if len(parts) >= 3 {
			c.add(s, "oui:"+strings.Join(parts[:3], ":"), o, "observed MAC OUI")
		}
	}
	if o.Kind == observe.KindService && o.Fingerprint == observe.FingerprintMatched && o.Service != "" {
		family := o.Service
		if family == "https" {
			family = "http"
		}
		c.add(s, "service:"+family, o, o.Reason)
		s.verified[family] = true
		if o.Service == "smb" && o.Attributes["smb.os_version"] != "" {
			s.applicationOS["Windows"] = true
		}
		if os := o.Attributes["nmap.os"]; o.Probe == "nmap" && os != "" {
			s.applicationOS[os] = true
		}
		if o.Service == "https" && o.TLS != nil && len(o.TLS.Certificates) > 0 {
			c.add(s, "tls:certificate", o, "presented certificate "+o.TLS.Certificates[0].SHA256)
		}
	}
	if o.Kind == observe.KindPort && o.Transport == "udp" && o.State == "open" && o.Service != "" && o.Confidence >= 80 {
		c.add(s, "udp:"+o.Service, o, o.Reason)
		s.verified[o.Service] = true
	}
}

func (c *Collector) add(s *state, source string, o observe.Observation, detail string) {
	if s.seen[source] || len(s.signals) >= 16 {
		return
	}
	s.seen[source] = true
	s.signals = append(s.signals, observe.DeviceSignal{Source: source, Transport: o.Transport, Port: o.Port, Detail: detail})
}

// Results emits a classification only with a protocol identity and another
// independently observed signal. A second open port is weaker corroboration.
func (c *Collector) Results() []observe.Observation {
	addresses := make([]netip.Addr, 0, len(c.devices))
	for addr := range c.devices {
		addresses = append(addresses, addr)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Compare(addresses[j]) < 0 })
	var results []observe.Observation
	for _, addr := range addresses {
		s := c.devices[addr]
		if len(s.verified) == 0 {
			continue
		}
		signals := append([]observe.DeviceSignal(nil), s.signals...)
		if s.verified["modbus"] || s.verified["ethernetip"] {
			for port, service := range map[uint16]string{502: "modbus", 44818: "ethernetip"} {
				if s.ports[port] && !s.verified[service] {
					signals = append(signals, observe.DeviceSignal{Source: fmt.Sprintf("port:tcp/%d", port), Transport: "tcp", Port: port, Detail: "open industrial protocol port"})
				}
			}
		}
		if len(signals) < 2 {
			continue
		}
		class := "networked device"
		switch {
		case s.verified["modbus"] || s.verified["ethernetip"]:
			class = "industrial device"
		case s.verified["bacnet"]:
			class = "building automation device"
		case s.verified["mdns"] || s.verified["ssdp"] || s.verified["coap"]:
			class = "IoT device"
		}
		confidence := 65
		if len(s.verified) >= 2 {
			confidence = 90
		}
		attrs := map[string]string{"device.class": class}
		if len(s.stackOS) == 1 {
			for family, score := range s.stackOS {
				conflict := false
				for appOS := range s.applicationOS {
					if !compatibleOS(appOS, family) {
						conflict = true
					}
				}
				if conflict {
					attrs["device.os_conflict"] = "TCP stack and application OS evidence disagree"
				} else {
					attrs["device.os_family"], attrs["device.os_confidence"] = family, strconv.Itoa(score)
				}
			}
		} else if len(s.stackOS) > 1 {
			attrs["device.os_conflict"] = "TCP stack families differ across ports"
		}
		sort.Slice(signals, func(i, j int) bool { return signals[i].Source < signals[j].Source })
		results = append(results, observe.Observation{Kind: observe.KindDevice, Timestamp: time.Now().UTC(), Target: addr,
			Transport: "device", State: "identified", Confidence: confidence, Reason: "classification supported by independent observations",
			Probe: "device-fingerprint", Fingerprint: observe.FingerprintMatched, Attributes: attrs, Signals: signals})
	}
	return results
}

func compatibleOS(application, family string) bool {
	application = strings.ToLower(application)
	if family == "BSD/macOS" {
		for _, name := range []string{"bsd", "macos", "mac os", "darwin"} {
			if strings.Contains(application, name) {
				return true
			}
		}
		return false
	}
	return strings.Contains(application, strings.ToLower(family))
}
