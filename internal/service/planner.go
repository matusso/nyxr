package service

import (
	"bytes"
	"math"
	"sort"
	"strings"

	"github.com/matusso/nyxr/internal/observe"
)

// The planner's hypotheses are wire-protocol families, not products. A
// product/version claim still requires a protocol parser and its evidence.
var serviceFamilies = []string{
	ProbeTLS, ProbeHTTP, ProbeDNS, ProbeSOCKS, ProbeModbus,
	ProbeEtherNetIP, ProbeDatabase, ProbeSSH,
	ProbeSMB, ProbeRDP, ProbeMSRPC,
	ProbeLDAP, ProbeKerberos, ProbeNFS, "unknown",
}

// These likelihoods are conservative engineering estimates. They describe
// whether the current safe probe will produce a validated protocol response,
// not the probability that a port traditionally carries that protocol.
var probeModel = map[string]struct {
	match float64
	cost  float64
}{
	ProbeTLS:        {0.98, 1.30},
	ProbeHTTP:       {0.97, 1.00},
	ProbeDNS:        {0.96, 1.15},
	ProbeSOCKS:      {0.96, 1.15},
	ProbeModbus:     {0.96, 1.45},
	ProbeEtherNetIP: {0.96, 1.45},
	ProbeDatabase:   {0.90, 1.35},
	ProbeSMB:        {0.97, 1.40},
	ProbeRDP:        {0.97, 1.30},
	ProbeMSRPC:      {0.95, 1.30},
	ProbeLDAP:       {0.96, 1.35},
	ProbeKerberos:   {0.96, 1.30},
	ProbeNFS:        {0.95, 1.35},
	ProbeQUIC:       {0.98, 1.50},
	ProbeDTLS:       {0.96, 1.40},
}

const incidentalMatch = 0.001

type probePlanner struct {
	prob                 []float64
	families             []string
	transport            string
	candidates           map[string]bool
	attempted            map[string]bool
	redisHint            bool
	confirmedService     string
	confirmedProbability float64
}

func newProbePlanner(e *Engine, port uint16) *probePlanner {
	return newProbePlannerFor(e, port, "tcp")
}

func newProbePlannerFor(e *Engine, port uint16, transport string) *probePlanner {
	families := append([]string(nil), serviceFamilies...)
	if transport == "udp" {
		families = []string{ProbeQUIC, ProbeDTLS, "unknown"}
	}
	p := &probePlanner{candidates: map[string]bool{}, attempted: map[string]bool{}, families: families, transport: transport}
	for _, d := range e.cfg.Definitions {
		if d.Transport == transport {
			p.families = append(p.families, "dsl/"+d.Name)
		}
	}
	p.prob = make([]float64, len(p.families))
	for i := range p.prob {
		p.prob[i] = 1
	}
	p.prob[len(families)-1] = 3 // leave room for protocols we cannot probe
	index := len(families)
	for _, d := range e.cfg.Definitions {
		if d.Transport != transport {
			continue
		}
		for _, hinted := range d.Ports {
			if hinted == port {
				p.prob[index] *= 24
				p.candidates["dsl/"+d.Name] = true
				break
			}
		}
		index++
	}
	if transport == "tcp" {
		for _, name := range e.cfg.Fallback {
			p.add(e, name)
		}
		// Hints change priors and eligibility. Multiple hints may apply to one
		// port; none excludes a different protocol from a positive response.
		for _, hint := range []struct {
			ports map[uint16]bool
			name  string
			boost float64
		}{
			{tlsPorts, ProbeTLS, 24}, {httpPorts, ProbeHTTP, 20},
			{dnsPorts, ProbeDNS, 30}, {socksPorts, ProbeSOCKS, 30},
			{modbusPorts, ProbeModbus, 30}, {ethernetIPPorts, ProbeEtherNetIP, 30},
			{databasePorts, ProbeDatabase, 24},
			{smbPorts, ProbeSMB, 30}, {rdpPorts, ProbeRDP, 30}, {msrpcPorts, ProbeMSRPC, 30},
			{ldapPorts, ProbeLDAP, 30}, {kerberosPorts, ProbeKerberos, 30}, {nfsPorts, ProbeNFS, 30},
		} {
			if hint.ports[port] {
				p.prob[familyIndex(hint.name)] *= hint.boost
				p.add(e, hint.name)
			}
		}
		// A common web port should be tested both with and without TLS. The
		// posterior chooses the order and changes it after the first response.
		if tlsPorts[port] {
			p.add(e, ProbeHTTP)
		}
		if httpPorts[port] {
			p.add(e, ProbeTLS)
		}
		if port == 22 {
			p.prob[familyIndex(ProbeSSH)] *= 30
		}
	}
	if transport == "udp" && e.enabled[ProbeQUIC] {
		if QUICPort(port) {
			p.prob[0] *= 24
			p.candidates[ProbeQUIC] = true
		}
		for _, name := range e.cfg.Fallback {
			if name == ProbeQUIC {
				p.candidates[ProbeQUIC] = true
			}
		}
	}
	if transport == "udp" && e.enabled[ProbeDTLS] {
		if DTLSPort(port) {
			p.prob[1] *= 24
			p.candidates[ProbeDTLS] = true
		}
		for _, name := range e.cfg.Fallback {
			if name == ProbeDTLS {
				p.candidates[ProbeDTLS] = true
			}
		}
	}
	p.normalize()
	return p
}

// QUICPort is a conservative port hint. A fallback probe can test other UDP
// ports explicitly without sending a QUIC handshake to every common service.
func QUICPort(port uint16) bool { return port == 443 || port == 4433 || port == 8443 }

// DTLSPort covers common DTLS listeners without probing every UDP service.
func DTLSPort(port uint16) bool { return port == 5684 || port == 5349 }

func (p *probePlanner) add(e *Engine, name string) {
	if e.enabled[name] {
		if _, ok := probeModel[name]; ok {
			p.candidates[name] = true
		}
	}
}

func familyIndex(name string) int {
	for i, family := range serviceFamilies {
		if family == name {
			return i
		}
	}
	return len(serviceFamilies) - 1
}

func (p *probePlanner) normalize() {
	var sum float64
	for _, v := range p.prob {
		sum += v
	}
	if sum == 0 {
		return
	}
	for i := range p.prob {
		p.prob[i] /= sum
	}
}

func entropy(prob []float64) float64 {
	var h float64
	for _, v := range prob {
		if v > 0 {
			h -= v * math.Log2(v)
		}
	}
	return h
}

func likelihood(probe string, family string) float64 {
	if probe == family {
		if strings.HasPrefix(probe, "dsl/") {
			return 0.95
		}
		return probeModel[probe].match
	}
	return incidentalMatch
}

// informationGain calculates H(S) - E[H(S|response)] for a validated match
// versus every other response. Its calculation uses the same likelihoods as
// the posterior update, so the scheduler and inference cannot drift apart.
func (p *probePlanner) informationGain(probe string) float64 {
	matched, missed := make([]float64, len(p.prob)), make([]float64, len(p.prob))
	var matchProbability float64
	for i, family := range p.families {
		q := likelihood(probe, family)
		matched[i] = p.prob[i] * q
		missed[i] = p.prob[i] * (1 - q)
		matchProbability += matched[i]
	}
	if matchProbability <= 0 || matchProbability >= 1 {
		return 0
	}
	for i := range matched {
		matched[i] /= matchProbability
		missed[i] /= 1 - matchProbability
	}
	return entropy(p.prob) - matchProbability*entropy(matched) - (1-matchProbability)*entropy(missed)
}

func (p *probePlanner) next() (string, float64, float64) {
	best, bestGain, bestScore := "", 0.0, 0.0
	for name := range p.candidates {
		if p.attempted[name] {
			continue
		}
		gain := p.informationGain(name)
		cost := probeModel[name].cost
		if cost == 0 {
			cost = 1.3
		}
		score := gain / cost
		if score > bestScore || (score == bestScore && (best == "" || name < best)) {
			best, bestGain, bestScore = name, gain, score
		}
	}
	return best, bestGain, bestScore
}

// update applies Bayes' rule once per exchange. A recognizable, unmatched
// response shape is modeled conditional on the failed validation, avoiding a
// second independent claim from correlated bytes in the same response.
func (p *probePlanner) update(probe string, matched bool, response []byte, e *Engine) {
	p.attempted[probe] = true
	hint := responseHint(response)
	for i, family := range p.families {
		q := likelihood(probe, family)
		if matched {
			p.prob[i] *= q
		} else {
			p.prob[i] *= 1 - q
			if hint != "" {
				favored := ProbeDatabase
				if hint == "tls" {
					favored = ProbeTLS
				}
				if family == favored {
					p.prob[i] *= 0.80
				} else {
					p.prob[i] *= 0.005
				}
			}
		}
	}
	p.normalize()
	if p.transport != "tcp" {
		return
	}
	if hint == "redis" && !matched {
		p.redisHint = true
		p.add(e, ProbeDatabase)
	} else if hint == "tls" && !matched {
		p.add(e, ProbeTLS)
	}
}

func (p *probePlanner) observeBanner(response []byte, e *Engine) {
	if responseHint(response) != "redis" {
		return
	}
	for i, family := range p.families {
		if family == ProbeDatabase {
			p.prob[i] *= 0.80
		} else {
			p.prob[i] *= 0.005
		}
	}
	p.normalize()
	p.redisHint = true
	p.add(e, ProbeDatabase)
}

func (p *probePlanner) confirmPassive(family string) {
	for i, name := range p.families {
		if name == family {
			p.prob[i] *= 0.999
		} else {
			p.prob[i] *= 0.001
		}
	}
	p.normalize()
}

// Imported banner rules may identify families outside the native planner's
// fixed set. Keep that named result and its matcher confidence visible.
func (p *probePlanner) confirmNamed(service string, confidence float64) {
	p.confirmedService = service
	p.confirmedProbability = confidence
}

func responseHint(response []byte) string {
	if plaintextToTLSError(response) {
		return "tls"
	}
	// A RESP error is particularly useful after an HTTP request to Redis.
	// Require CRLF framing to avoid promoting arbitrary text banners.
	if len(response) >= 7 && bytes.HasPrefix(response, []byte("-ERR ")) && bytes.Contains(response, []byte("\r\n")) {
		return "redis"
	}
	return ""
}

// Some TLS listeners return a syntactically valid HTTP error when sent a
// plaintext request. That error describes the required transport rather than
// confirming a plaintext HTTP service.
func plaintextToTLSError(response []byte) bool {
	if !bytes.HasPrefix(response, []byte("HTTP/1.0 400 ")) &&
		!bytes.HasPrefix(response, []byte("HTTP/1.1 400 ")) {
		return false
	}
	lower := bytes.ToLower(response)
	return bytes.Contains(lower, []byte("http request to an https server")) ||
		bytes.Contains(lower, []byte("plain http request was sent to https port"))
}

func (p *probePlanner) probabilities() []observe.ServiceHypothesis {
	if p.confirmedService != "" {
		return []observe.ServiceHypothesis{
			{Family: p.confirmedService, Probability: p.confirmedProbability},
			{Family: "unknown", Probability: 1 - p.confirmedProbability},
		}
	}
	out := make([]observe.ServiceHypothesis, len(p.families))
	for i, family := range p.families {
		out[i] = observe.ServiceHypothesis{Family: family, Probability: p.prob[i]}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Probability == out[j].Probability {
			return out[i].Family < out[j].Family
		}
		return out[i].Probability > out[j].Probability
	})
	return out
}

func (p *probePlanner) confidence(family string) int {
	for i, name := range p.families {
		if name == family {
			return max(1, min(99, int(math.Round(100*p.prob[i]))))
		}
	}
	return 1
}
