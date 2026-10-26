package service

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/matusso/nyxr/internal/observe"
	"github.com/matusso/nyxr/internal/tlsrecord"
)

// TLS profile names accepted by Config.TLSProfiles.
const (
	TLSProfile13     = "tls13"  // TLS 1.3 only
	TLSProfile12     = "tls12"  // TLS 1.2 only, Go's secure cipher suites
	TLSProfileLegacy = "legacy" // TLS 1.0-1.1 with every suite
	TLSProfileNoSNI  = "no-sni" // the default offer without SNI; needs a hostname
	TLSProfileVHosts = "vhosts" // the default offer once per additional hostname
)

// TLSProfileNames lists the alternative ClientHello profiles in run order.
func TLSProfileNames() []string {
	return []string{TLSProfile13, TLSProfile12, TLSProfileLegacy, TLSProfileNoSNI, TLSProfileVHosts}
}

const (
	probeTLSProfile = "tls-profile/"
	// MaxTargetHostnames bounds the names kept per address. The first name
	// is the SNI of the default handshake; the vhosts profile tries the rest.
	MaxTargetHostnames = 4
)

type tlsProfile struct {
	name     string
	min, max uint16
	suites   []uint16
}

var (
	defaultTLSProfile = tlsProfile{name: "default", min: tls.VersionTLS10, max: tls.VersionTLS13, suites: clientCipherSuites}
	tlsProfiles       = map[string]tlsProfile{
		TLSProfile13:     {name: TLSProfile13, min: tls.VersionTLS13, max: tls.VersionTLS13},
		TLSProfile12:     {name: TLSProfile12, min: tls.VersionTLS12, max: tls.VersionTLS12, suites: secureCipherSuites()},
		TLSProfileLegacy: {name: TLSProfileLegacy, min: tls.VersionTLS10, max: tls.VersionTLS11, suites: clientCipherSuites},
	}
)

func secureCipherSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}

// serverName is the SNI for the default handshake: the first hostname the
// operator gave for this address, or none.
func (t Target) serverName() string {
	if len(t.Hostnames) == 0 {
		return ""
	}
	return t.Hostnames[0]
}

// collectTLSProfiles runs the enabled alternative ClientHello profiles after
// the default handshake identified TLS. Each is one bounded handshake with
// the probe's own deadline; nothing is sent after it completes.
func (e *Engine) collectTLSProfiles(ctx context.Context, t Target, alpn []string, o *observe.Observation) {
	if o.TLS == nil || len(e.cfg.TLSProfiles) == 0 {
		return
	}
	run := func(profile tlsProfile, label, serverName string) {
		profile.name = label
		if ctx.Err() != nil {
			return
		}
		tc, ev, ok := e.handshakeProfile(ctx, t, alpn, profile, serverName)
		o.Evidence = append(o.Evidence, ev)
		o.ProbesAttempted = append(o.ProbesAttempted, ev.Probe)
		idx := len(o.Evidence) - 1
		result := observe.TLSProfileResult{Profile: label, ServerName: serverName, Evidence: idx}
		if ok {
			state := tc.ConnectionState()
			_ = tc.Close()
			result.Outcome, result.Version = "negotiated", tls.VersionName(state.Version)
			result.CipherSuite, result.ALPN = tls.CipherSuiteName(state.CipherSuite), state.NegotiatedProtocol
			if len(state.PeerCertificates) > 0 {
				sum := sha256.Sum256(state.PeerCertificates[0].Raw)
				result.LeafSHA256 = hex.EncodeToString(sum[:])
			}
			recordTLSFingerprint(o, idx, label, serverName)
		} else {
			classifyTLSFailure(&result, ev)
		}
		o.TLS.Profiles = append(o.TLS.Profiles, result)
	}
	hostname := t.serverName()
	for _, name := range e.cfg.TLSProfiles {
		switch name {
		case TLSProfileNoSNI:
			if hostname != "" {
				run(defaultTLSProfile, TLSProfileNoSNI, "")
			}
		case TLSProfileVHosts:
			for _, h := range t.Hostnames[min(1, len(t.Hostnames)):min(len(t.Hostnames), MaxTargetHostnames)] {
				run(defaultTLSProfile, TLSProfileVHosts, h)
			}
		default:
			if p, ok := tlsProfiles[name]; ok {
				run(p, name, hostname)
			}
		}
	}
	recordTLSConflicts(o, hostname)
}

// classifyTLSFailure separates a TLS alert from a plaintext listener and from
// silence, so a refused profile is not mistaken for an absent service.
func classifyTLSFailure(r *observe.TLSProfileResult, ev observe.Evidence) {
	r.Error = ev.Error
	switch desc, alert := tlsrecord.Alert(ev.Response); {
	case alert:
		r.Outcome, r.Alert = "alert", tlsrecord.AlertName(desc)
	case len(ev.Response) > 0 && len(tlsrecord.Decode(ev.Response)) == 0:
		r.Outcome = "plaintext"
	case len(ev.Response) == 0 && (ev.Error == "" || ev.Error == "EOF" || isTimeout(ev.Error) || strings.Contains(ev.Error, "reset")):
		r.Outcome = "no-response"
	default:
		r.Outcome = "error"
	}
}

// recordTLSFingerprint derives the versioned ServerHello fingerprint from the
// bytes retained in evidence idx. A ServerHello cut off by the retention
// limit yields nothing rather than a guessed value.
func recordTLSFingerprint(o *observe.Observation, idx int, profile, serverName string) {
	ev := o.Evidence[idx]
	hello, ok := tlsrecord.ParseServerHello(ev.Response)
	if !ok {
		return
	}
	exts := make([]string, len(hello.Extensions))
	for i, x := range hello.Extensions {
		exts[i] = fmt.Sprintf("%04x", x)
	}
	normalized := fmt.Sprintf("%04x;%04x;%s", hello.Version, hello.CipherSuite, strings.Join(exts, ","))
	if hello.HelloRetry {
		normalized += ";hrr"
	}
	sum := sha256.Sum256([]byte(observe.FingerprintTLSServer + "|" + normalized))
	status := "observed"
	if ev.Truncated {
		status = "partial"
	}
	o.AppFingerprints = append(o.AppFingerprints, observe.AppFingerprint{
		Method: observe.FingerprintTLSServer, Value: hex.EncodeToString(sum[:]), Normalized: normalized,
		Profile: profile, ServerName: serverName, Evidence: idx, Status: status,
	})
}

// recordTLSConflicts keeps disagreement between the default handshake and
// profiles that sent the same SNI: a different leaf certificate for the same
// name suggests several backends or a middlebox, so both values stay.
func recordTLSConflicts(o *observe.Observation, hostname string) {
	if len(o.TLS.Certificates) == 0 {
		return
	}
	defaultLeaf := o.TLS.Certificates[0].SHA256
	defaultEvidence := -1
	for _, f := range o.AppFingerprints {
		if f.Method == observe.FingerprintTLSServer && f.Profile == defaultTLSProfile.name {
			defaultEvidence = f.Evidence
		}
	}
	values, evidence := []string{defaultLeaf}, []int{defaultEvidence}
	for _, r := range o.TLS.Profiles {
		if r.ServerName != hostname || r.LeafSHA256 == "" || slices.Contains(values, r.LeafSHA256) {
			continue
		}
		values, evidence = append(values, r.LeafSHA256), append(evidence, r.Evidence)
	}
	if len(values) > 1 {
		o.FingerprintConflicts = append(o.FingerprintConflicts, observe.FingerprintConflict{
			Field: "tls.leaf_sha256", Values: values, Evidence: evidence,
			Detail: "handshakes with the same server name presented different leaf certificates",
		})
	}
}
