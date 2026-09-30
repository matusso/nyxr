package service

import (
	"fmt"

	"github.com/matusso/nyxr/internal/observe"
)

// nmapBanner matches a connect banner against the imported nmap-service-probes
// database (its NULL-probe rules) and fills the observation on success. It
// sends nothing: it only interprets bytes the banner probe already read. A
// softmatch is reported with lower confidence than a hard match, and the
// matching probe and rule line are kept as evidence attributes for provenance.
func (e *Engine) nmapBanner(o *observe.Observation, banner []byte) bool {
	if !e.enabled[ProbeNmap] || e.cfg.Nmap == nil {
		return false
	}
	res, ok := e.cfg.Nmap.MatchBanner(banner)
	if !ok {
		return false
	}
	o.Service = res.Service
	o.Product = res.Product
	o.Version = res.Version
	o.Probe = ProbeNmap
	o.Fingerprint = observe.FingerprintMatched
	if res.Soft {
		o.Confidence, o.Reason = 75, "nmap-service-probes softmatch on banner"
	} else {
		o.Confidence, o.Reason = 90, "nmap-service-probes match on banner"
	}
	attrs := map[string]string{
		"nmap.probe": res.Probe,
		"nmap.line":  fmt.Sprintf("%d", res.Line),
	}
	if res.Info != "" {
		attrs["nmap.info"] = res.Info
	}
	if res.Hostname != "" {
		attrs["nmap.hostname"] = res.Hostname
	}
	if res.OS != "" {
		attrs["nmap.os"] = res.OS
	}
	if res.Device != "" {
		attrs["nmap.device"] = res.Device
	}
	if len(res.CPE) > 0 {
		attrs["nmap.cpe"] = res.CPE[0]
	}
	o.Attributes = attrs
	return true
}
