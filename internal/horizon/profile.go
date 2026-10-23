package horizon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/horizon/model"
	"github.com/matusso/nyxr/internal/packet"
)

// MaxProfileTTL bounds how long any behavior profile may be trusted.
const MaxProfileTTL = 30 * 24 * time.Hour

// BuildProfile summarizes a resolved cross-port study from replayed reports.
// Every role must be resolved and agree on target, vantage and fingerprint;
// otherwise the evidence is not consistent enough to compress.
func BuildProfile(reports map[string]model.Report, class string, now time.Time, ttl time.Duration) (model.BehaviorProfile, error) {
	var p model.BehaviorProfile
	if class == "" || len(class) > 64 || strings.ContainsAny(class, " \t\r\n") {
		return p, errors.New("profile class must be a 1..64 character label without whitespace")
	}
	if ttl <= 0 || ttl > MaxProfileTTL || now.IsZero() {
		return p, fmt.Errorf("profile needs an explicit time and a TTL in (0, %s]", MaxProfileTTL)
	}
	study, err := AnalyzeCrossPort(reports)
	if err != nil {
		return p, err
	}
	if study.Classification == "unresolved" {
		return p, errors.New("an unresolved study cannot become a profile")
	}
	for _, r := range study.Roles {
		if r.Status != "inferred" {
			return p, fmt.Errorf("role %s is unresolved; profiles need every included role resolved", r.Role)
		}
	}
	vantage, fp, err := observedIdentity(reports)
	if err != nil {
		return p, err
	}
	var earliest, latest time.Time
	for _, r := range reports {
		if r.FinishedAt.After(latest) {
			latest = r.FinishedAt
		}
		if earliest.IsZero() || r.StartedAt.Before(earliest) {
			earliest = r.StartedAt
		}
	}
	if latest.After(now) {
		return p, errors.New("profile time precedes its evidence")
	}
	p = model.BehaviorProfile{APIVersion: model.ProfileVersion, Kind: "BehaviorProfile", Class: class, Target: study.Target, CreatedAt: latest.UTC(), EvidenceFrom: earliest.UTC(),
		ValidUntil: latest.UTC().Add(ttl), Vantage: vantage, Fingerprint: fp, Classification: study.Classification, Direction: "untested", Cooldown: "untested",
		Subjects: []string{}, Hypotheses: []model.Hypothesis{}, Evidence: []string{}}
	for _, r := range study.Roles {
		p.Evidence = append(p.Evidence, fmt.Sprintf("%s:%s:%s", r.Role, r.RunID, r.ExperimentHash))
		for _, port := range append(slices.Clone(r.PreconditionPorts), r.MeasurementPort) {
			p.Subjects = append(p.Subjects, fmt.Sprintf("tcp/%d", port))
		}
	}
	slices.Sort(p.Subjects)
	p.Subjects = slices.Compact(p.Subjects)
	if len(study.Candidates) > 0 {
		c := study.Candidates[0]
		p.Direction, p.Hypotheses = c.Direction, c.Hypotheses
		p.Cooldown = cooldownOf(study)
	}
	p.ID = profileID(p)
	return p, nil
}

func cooldownOf(s model.CrossPortStudy) string {
	for _, r := range s.Roles {
		if r.Role == RoleTimeSeparated && r.Status == "inferred" {
			if r.Significant {
				return "persistent"
			}
			return "cooldown"
		}
	}
	return "untested"
}

func profileID(p model.BehaviorProfile) string {
	p.ID = ""
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// LoadProfile strictly decodes a profile and checks its content ID.
func LoadProfile(r io.Reader) (model.BehaviorProfile, error) {
	var p model.BehaviorProfile
	b, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil {
		return p, err
	}
	if len(b) > 1<<20 {
		return p, errors.New("profile exceeds 1 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, err
	}
	if d.More() {
		return p, errors.New("profile has trailing data")
	}
	if p.APIVersion != model.ProfileVersion || p.Kind != "BehaviorProfile" {
		return p, errors.New("unsupported profile version/kind")
	}
	if p.ID != profileID(p) {
		return p, errors.New("profile integrity check failed")
	}
	if !validWindow(p) {
		return p, errors.New("profile validity window is invalid")
	}
	return p, nil
}

func validWindow(p model.BehaviorProfile) bool {
	return !p.EvidenceFrom.IsZero() && !p.EvidenceFrom.After(p.CreatedAt) && p.ValidUntil.After(p.CreatedAt) && p.ValidUntil.Sub(p.CreatedAt) <= MaxProfileTTL
}

// CanonicalChangeScope returns "network" or "host:<canonical address>".
// Anything else is an error, so a mistyped scope can never be ignored.
func CanonicalChangeScope(scope string) (string, error) {
	if scope == "network" {
		return scope, nil
	}
	if host, ok := strings.CutPrefix(scope, "host:"); ok {
		if a, err := netip.ParseAddr(host); err == nil && a.Zone() == "" {
			return "host:" + a.Unmap().String(), nil
		}
	}
	return "", fmt.Errorf("change scope %q must be network or host:<IP address>", scope)
}

// observedIdentity extracts the vantage (source address, backend,
// correlation version) and what the target replied with. Reports that
// disagree are rejected rather than averaged.
func observedIdentity(reports map[string]model.Report) (model.Vantage, model.Fingerprint, error) {
	var v model.Vantage
	fp := model.Fingerprint{ReplyTTLs: []int{}}
	decoder := packet.NewDecoder()
	first := true
	for _, role := range CrossPortRoles {
		r, ok := reports[role]
		if !ok {
			continue
		}
		rv := model.Vantage{Backend: r.Backend, CorrelationVersion: r.CorrelationVersion}
		for _, t := range r.Trials {
			if len(t.Evidence) > 0 && t.Evidence[0].Direction == "tx" {
				if s, ok := decoder.Decode(t.Evidence[0].Frame); ok {
					rv.SourceIP = s.Source.String()
					break
				}
			}
		}
		if first {
			v, first = rv, false
		} else if rv != v {
			return v, fp, errors.New("study roles were collected from different vantage points")
		}
		host := r.Experiment.Spec.Scope.Targets[0]
		for _, t := range r.Trials {
			if t.Features.ResponseClass != "syn-ack" || (t.Features.ResponseSource != "" && t.Features.ResponseSource != host) {
				continue
			}
			if !slices.Contains(fp.ReplyTTLs, int(t.Features.TTL)) {
				fp.ReplyTTLs = append(fp.ReplyTTLs, int(t.Features.TTL))
			}
			options := fmt.Sprintf("%x", withoutSACK(t.Features.TCPOptions))
			if fp.Options == "" {
				fp.Options = options
			} else if fp.Options != options {
				return v, fp, errors.New("target option layout differs within the study")
			}
		}
	}
	slices.Sort(fp.ReplyTTLs)
	return v, fp, nil
}

// CheckProfile decides whether a profile still describes the target. Any
// reason invalidates it: expiry, a declared change, a different vantage, a
// path change (reply TTL), a host change (option layout), behavior drift in
// any tested statement, or an unconfirmed classification.
func CheckProfile(p model.BehaviorProfile, reports map[string]model.Report, changes []model.ChangeEvent, now time.Time) model.ProfileCheck {
	c := model.ProfileCheck{ProfileID: p.ID, Reasons: []string{}}
	add := func(format string, a ...any) { c.Reasons = append(c.Reasons, fmt.Sprintf(format, a...)) }
	if p.ID != profileID(p) {
		add("profile integrity check failed")
	}
	if !validWindow(p) {
		add("profile validity window is invalid")
	}
	if now.IsZero() || now.After(p.ValidUntil) {
		add("expired at %s", p.ValidUntil.Format(time.RFC3339))
	}
	if now.Before(p.CreatedAt) {
		add("profile is dated after the evaluation time")
	}
	target, _ := CanonicalChangeScope("host:" + p.Target)
	for _, ch := range changes {
		scope, err := CanonicalChangeScope(ch.Scope)
		if err != nil {
			add("declared change rejected: %v", err)
			continue
		}
		// A change during or after the profile's evidence invalidates it.
		if (scope == "network" || scope == target) && ch.At.After(p.EvidenceFrom) && !ch.At.After(now) {
			add("declared %s change at %s: %s", scope, ch.At.UTC().Format(time.RFC3339), ch.Detail)
		}
	}
	study, err := AnalyzeCrossPort(reports)
	if err != nil {
		add("current evidence cannot be analyzed: %v", err)
		return c
	}
	if study.Target != p.Target {
		add("profile is for %s, evidence is for %s", p.Target, study.Target)
	}
	vantage, fp, err := observedIdentity(reports)
	switch {
	case err != nil:
		add("current evidence is inconsistent: %v", err)
	case vantage != p.Vantage:
		add("vantage changed: %+v, profile %+v", vantage, p.Vantage)
	}
	if err == nil && len(fp.ReplyTTLs) > 0 && len(p.Fingerprint.ReplyTTLs) > 0 {
		shared := false
		for _, ttl := range fp.ReplyTTLs {
			shared = shared || slices.Contains(p.Fingerprint.ReplyTTLs, ttl)
		}
		if !shared {
			add("path change: reply TTL %v, profile %v", fp.ReplyTTLs, p.Fingerprint.ReplyTTLs)
		}
		if fp.Options != "" && p.Fingerprint.Options != "" && fp.Options != p.Fingerprint.Options {
			add("host change: TCP option layout %s, profile %s", fp.Options, p.Fingerprint.Options)
		}
	}
	switch {
	case study.Classification == "unresolved":
		add("unconfirmed: current classification is unresolved")
	case study.Classification != p.Classification:
		add("behavior drift: classification %s, profile %s", study.Classification, p.Classification)
	}
	if len(study.Candidates) > 0 {
		if d := study.Candidates[0].Direction; d != "untested" && p.Direction != "untested" && d != p.Direction {
			add("behavior drift: direction %s, profile %s", d, p.Direction)
		}
	}
	if cd := cooldownOf(study); cd != "untested" && p.Cooldown != "untested" && cd != p.Cooldown {
		add("behavior drift: %s, profile %s", cd, p.Cooldown)
	}
	c.Valid = len(c.Reasons) == 0
	return c
}

func evidenceOf(reports map[string]model.Report, roles ...string) []string {
	out := []string{}
	for _, role := range roles {
		if r, ok := reports[role]; ok {
			out = append(out, role+":"+r.RunID)
		}
	}
	return out
}

func resolvedRole(s model.CrossPortStudy, role string) bool {
	for _, r := range s.Roles {
		if r.Role == role {
			return r.Status == "inferred"
		}
	}
	return false
}

// coverageStatements labels every reported statement tested (measured in this
// study), profile-inferred (only a valid profile supports it) or not-tested.
func coverageStatements(s model.CrossPortStudy, reports map[string]model.Report, p *model.BehaviorProfile, check *model.ProfileCheck) []model.CoverageStatement {
	valid := p != nil && check != nil && check.Valid
	out := []model.CoverageStatement{{Statement: "classification", Value: s.Classification, Coverage: "tested", Evidence: evidenceOf(reports, CrossPortRoles...)}}
	if s.Classification != "shared-state" {
		return out
	}
	c := s.Candidates[0]
	add := func(statement, tested, profile string, roles ...string) {
		st := model.CoverageStatement{Statement: statement, Value: "untested", Coverage: "not-tested", Evidence: []string{}}
		switch {
		case tested != "":
			st.Value, st.Coverage, st.Evidence = tested, "tested", evidenceOf(reports, roles...)
		case valid && profile != "untested":
			st.Value, st.Coverage, st.Evidence = profile, "profile-inferred", []string{"profile:" + p.ID}
		}
		out = append(out, st)
	}
	direction, cooldown := "", ""
	if resolvedRole(s, RoleReverse) {
		direction = c.Direction
	}
	if resolvedRole(s, RoleTimeSeparated) {
		cooldown = cooldownOf(s)
	}
	profileDirection, profileCooldown, profileLimiter := "untested", "untested", "untested"
	if p != nil {
		profileDirection, profileCooldown = p.Direction, p.Cooldown
		for _, h := range p.Hypotheses {
			// Without a tested cooldown the profile's limiter status only says
			// that no orthogonal signal was measured; it infers nothing.
			if h.Family == "rate-limiter" && p.Cooldown != "untested" {
				profileLimiter = h.Status
			}
		}
	}
	add("direction", direction, profileDirection, RoleMain, RoleReverse)
	add("cooldown", cooldown, profileCooldown, RoleMain, RoleTimeSeparated)
	limiter := ""
	if cooldown != "" {
		for _, h := range c.Hypotheses {
			if h.Family == "rate-limiter" {
				limiter = h.Status
			}
		}
	}
	add("rate-limiter", limiter, profileLimiter, RoleMain, RoleTimeSeparated)
	return out
}

// portCoverage reports each port named by any available role. A port probed
// only by unresolved roles is tested-unresolved: traffic was sent, but it
// supports no statement.
func portCoverage(experiments map[string]model.Experiment, reports map[string]model.Report, p *model.BehaviorProfile, check *model.ProfileCheck) []model.PortCoverage {
	resolved := map[string]bool{}
	for role, r := range reports {
		if outcome, err := outcomeOf(role, r); err == nil && outcome != "unresolved" {
			resolved[role] = true
		}
	}
	ports := map[string][]string{}
	for role, e := range experiments {
		for _, port := range e.Spec.Scope.TCPPorts {
			key := fmt.Sprintf("tcp/%d", port)
			if _, ok := ports[key]; !ok {
				ports[key] = []string{}
			}
			if _, ran := reports[role]; ran {
				ports[key] = append(ports[key], role)
			}
		}
	}
	out := []model.PortCoverage{}
	for port, roles := range ports {
		slices.Sort(roles)
		c := model.PortCoverage{Port: port, Coverage: "not-tested", Roles: roles}
		switch {
		case slices.ContainsFunc(roles, func(r string) bool { return resolved[r] }):
			c.Coverage = "tested"
		case len(roles) > 0:
			c.Coverage = "tested-unresolved"
		case p != nil && check != nil && check.Valid && slices.Contains(p.Subjects, port):
			c.Coverage = "profile-inferred"
		}
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b model.PortCoverage) int { return strings.Compare(a.Port, b.Port) })
	return out
}
