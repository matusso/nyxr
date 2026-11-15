package storage

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/config"
	"github.com/matusso/nyxr/internal/observe"
)

// DiffVersion names the change vocabulary and coverage rules of ScanDiff.
// A change to either gets a new version.
const DiffVersion = "nyxr-scan-diff/v1"

// diffMaxObservations bounds what one side of a diff loads. A larger scan is
// compared partially and treated as incomplete coverage.
const diffMaxObservations = 200000

// Change certainty. A change is observed when both scans hold a response
// that supports it; otherwise it is unverified and Reason says why.
const (
	DiffObserved   = "observed"
	DiffUnverified = "unverified"
)

// ScanDiff explains what differs between two stored scans. Silence, a
// failed scan or an untested endpoint never yields a "removed" claim.
type ScanDiff struct {
	Version string       `json:"version"`
	Before  observe.Scan `json:"before"`
	After   observe.Scan `json:"after"`
	Changes []DiffChange `json:"changes"`
	// Summary counts changes by kind.
	Summary map[string]int `json:"summary"`
	// Limitations lists what the comparison could not establish.
	Limitations []string `json:"limitations"`
}

// DiffChange is one difference. Kind is asset_presence, address_membership,
// address_reassignment, identity_manual, identity_correlation, service,
// tls_certificate, tls_configuration, ssh_host_key, ssh_configuration,
// http_title, snmp_identity, os, firmware or device_class. Change is added,
// removed, changed or not_observed.
type DiffChange struct {
	Kind   string `json:"kind"`
	Change string `json:"change"`
	Status string `json:"status"`
	// Reason explains an unverified change: not_tested, scan_incomplete,
	// silent or truncated_evidence. Identity changes carry the recorded cause.
	Reason    string     `json:"reason,omitempty"`
	Asset     string     `json:"asset,omitempty"` // persistent identity ID
	Address   netip.Addr `json:"address"`
	Transport string     `json:"transport,omitempty"`
	Port      uint16     `json:"port,omitempty"`
	Field     string     `json:"field,omitempty"`
	Before    string     `json:"before,omitempty"`
	After     string     `json:"after,omitempty"`
	// Observation IDs resolve with `nyxr evidence show`.
	BeforeObservation string `json:"before_observation,omitempty"`
	AfterObservation  string `json:"after_observation,omitempty"`
}

type diffKey struct {
	transport string
	port      uint16
}

type diffHost struct {
	responded bool
	ports     map[diffKey]observe.Observation // discovery state
	claims    map[diffKey]observe.Observation // service identity
	device    *observe.Observation
}

type diffSide struct {
	scan       observe.Scan
	hosts      map[netip.Addr]*diffHost
	identity   map[netip.Addr]string
	cutoff     time.Time
	incomplete bool
	// Planned coverage from the stored scan scope; hasScope is false for
	// imports and scans stored before scope was recorded.
	hasScope bool
	targets  config.Scope
	ports    map[string]map[uint16]bool
}

// diffSilent reports a state that is the absence of an answer.
func diffSilent(state string) bool {
	switch state {
	case "", "filtered", "open|filtered", "unknown", "error", "down":
		return true
	}
	return false
}

func diffPositive(state string) bool { return !diffSilent(state) && state != "closed" }

// diffAttributes are the protocol fields compared on an endpoint that both
// scans identified. A field missing on either side is not compared.
var diffAttributes = []struct{ kind, key string }{
	{"ssh_host_key", "ssh.host_key_sha256"},
	{"http_title", "http.title"},
	{"snmp_identity", "snmp.engine_id"},
	{"os", "smb.os_version"},
	{"os", "nmap.os"},
	{"os", "device.os_family"},
	{"firmware", "s7.firmware"},
	{"firmware", "bacnet.firmware"},
	{"device_class", "device.class"},
}

func (s *Store) diffSide(ctx context.Context, scan observe.Scan, events []IdentityMembershipEvent) (diffSide, error) {
	side := diffSide{scan: scan, hosts: map[netip.Addr]*diffHost{}, identity: map[netip.Addr]string{},
		incomplete: scan.Status != "completed", cutoff: scan.Finished}
	if sc := scan.Scope; sc != nil && len(sc.Targets) > 0 {
		if targets, err := config.ParseScope(sc.Targets); err == nil {
			side.hasScope, side.targets, side.ports = true, targets, map[string]map[uint16]bool{}
			for transport, list := range sc.Ports {
				if ports, err := config.ParsePorts(list); err == nil && !sc.PerTargetPorts {
					side.ports[transport] = map[uint16]bool{}
					for _, p := range ports {
						side.ports[transport][p] = true
					}
				}
			}
		}
	}
	obs, err := s.Observations(ctx, Filter{ScanID: scan.ID, Limit: diffMaxObservations + 1})
	if err != nil {
		return side, err
	}
	if len(obs) > diffMaxObservations {
		obs, side.incomplete = obs[:diffMaxObservations], true
	}
	if side.cutoff.IsZero() {
		side.cutoff = scan.Started
		if len(obs) > 0 {
			side.cutoff = obs[len(obs)-1].Timestamp
		}
	}
	for _, o := range obs { // oldest first, so the newest result of a retry wins
		if !o.Target.IsValid() {
			continue
		}
		host := side.hosts[o.Target]
		if host == nil {
			host = &diffHost{ports: map[diffKey]observe.Observation{}, claims: map[diffKey]observe.Observation{}}
			side.hosts[o.Target] = host
		}
		key := diffKey{o.Transport, o.Port}
		switch o.Kind {
		case observe.KindHost:
		case observe.KindPort:
			host.ports[key] = o
		case observe.KindService:
			host.claims[key] = o
		case observe.KindDevice:
			host.device = &o
			continue
		default:
			continue
		}
		host.responded = host.responded || !diffSilent(o.State)
	}
	for _, e := range events {
		if !e.ObservedAt.After(side.cutoff) {
			side.identity[e.Address] = e.ToIdentity
		}
	}
	return side, nil
}

func (s diffSide) responded(addr netip.Addr) bool {
	h := s.hosts[addr]
	return h != nil && h.responded
}

// planned reports whether the stored scope includes the address (port 0) or
// endpoint. It is false when the scope is unknown.
func (s diffSide) planned(addr netip.Addr, k diffKey) bool {
	return s.hasScope && s.targets.Contains(addr) && (k.port == 0 || s.ports[k.transport][k.port])
}

// covered reports whether a missing answer means silence: a result was
// stored, or the scan completed with the endpoint in its scope.
func (s diffSide) covered(tested, planned bool) bool { return tested || (planned && !s.incomplete) }

// absent explains why this side holds no answer for a host or endpoint.
func (s diffSide) absent(tested, planned bool) string {
	switch {
	case s.covered(tested, planned):
		return "silent"
	case s.incomplete:
		return "scan_incomplete"
	}
	return "not_tested"
}

func (h *diffHost) state(k diffKey) (string, observe.Observation, bool) {
	if h == nil {
		return "", observe.Observation{}, false
	}
	if o, ok := h.ports[k]; ok {
		return o.State, o, true
	}
	o, ok := h.claims[k]
	return o.State, o, ok
}

func diffService(o observe.Observation) string {
	return strings.Join(strings.Fields(o.Service+" "+o.Product+" "+o.Version), " ")
}

func diffTruncated(o observe.Observation) bool {
	if o.EvidenceTruncated || (o.SSH != nil && o.SSH.Truncated) {
		return true
	}
	for _, ev := range o.Evidence {
		if ev.Truncated {
			return true
		}
	}
	return false
}

// diffFingerprint returns the value of one fingerprint method, scoped to the
// client offer that produced it: values of different offers are not comparable.
func diffFingerprint(o observe.Observation, method string) (scope, value string) {
	for _, f := range o.AppFingerprints {
		if f.Method == method && f.Status == "observed" {
			return f.Profile + "|" + f.ServerName, f.Value
		}
	}
	return "", ""
}

// DiffNetwork compares the two most recent finished scans that share a name:
// what changed on that network since the scan before the latest one.
func (s *Store) DiffNetwork(ctx context.Context, name string) (ScanDiff, bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM scans WHERE name = ? AND status <> 'running' ORDER BY started_at DESC, id DESC LIMIT 2`, name)
	if err != nil {
		return ScanDiff{}, false, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return ScanDiff{}, false, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return ScanDiff{}, false, err
	}
	switch len(ids) {
	case 0:
		return ScanDiff{}, false, nil
	case 1:
		return ScanDiff{}, false, fmt.Errorf("only one finished scan is named %q; a diff needs two", name)
	}
	return s.DiffScans(ctx, ids[1], ids[0])
}

// DiffScans compares two stored scans by persistent asset identity. ok is
// false when either scan is unknown.
func (s *Store) DiffScans(ctx context.Context, beforeID, afterID string) (ScanDiff, bool, error) {
	diff := ScanDiff{Version: DiffVersion, Changes: []DiffChange{}, Summary: map[string]int{}, Limitations: []string{}}
	if beforeID == afterID {
		return diff, false, errors.New("diff needs two different scans")
	}
	var ok bool
	var err error
	if diff.Before, ok, err = s.Scan(ctx, beforeID); err != nil || !ok {
		return diff, false, err
	}
	if diff.After, ok, err = s.Scan(ctx, afterID); err != nil || !ok {
		return diff, false, err
	}
	if diff.After.Started.Before(diff.Before.Started) {
		return diff, false, errors.New("the after scan started before the before scan; swap them")
	}
	events, err := s.IdentityHistory(ctx, netip.Addr{})
	if err != nil {
		return diff, false, err
	}
	before, err := s.diffSide(ctx, diff.Before, events)
	if err != nil {
		return diff, false, err
	}
	after, err := s.diffSide(ctx, diff.After, events)
	if err != nil {
		return diff, false, err
	}
	for name, side := range map[string]diffSide{"before": before, "after": after} {
		if side.incomplete {
			diff.Limitations = append(diff.Limitations, fmt.Sprintf("%s scan is %s or exceeds %d observations: a missing result is not evidence of absence", name, side.scan.Status, diffMaxObservations))
		}
		if c := side.scan.Capture; c != nil && c.DroppedQueue+c.DroppedLimit+c.BackendDrops > 0 {
			diff.Limitations = append(diff.Limitations, fmt.Sprintf("%s scan capture dropped %d frames", name, c.DroppedQueue+c.DroppedLimit+c.BackendDrops))
		}
	}
	if diff.Before.Name != diff.After.Name {
		diff.Limitations = append(diff.Limitations, fmt.Sprintf("scan names differ (%s, %s): a name identifies a network, so these may be different networks", diff.Before.Name, diff.After.Name))
	}
	if diff.Before.Profile != diff.After.Profile {
		diff.Limitations = append(diff.Limitations, fmt.Sprintf("profiles differ (%s, %s): the scans may not cover the same ports and probes", diff.Before.Profile, diff.After.Profile))
	}

	add := func(c DiffChange) {
		if c.Status == "" {
			c.Status = DiffObserved
		}
		if c.Asset == "" {
			if c.Asset = after.identity[c.Address]; c.Asset == "" {
				c.Asset = before.identity[c.Address]
			}
		}
		diff.Changes = append(diff.Changes, c)
		diff.Summary[c.Kind]++
	}

	// One asset answering on one old and one new address moved; its
	// endpoints are compared across the move instead of removed and added.
	moved, movedTo := map[netip.Addr]netip.Addr{}, map[netip.Addr]bool{}
	gone, came := map[string][]netip.Addr{}, map[string][]netip.Addr{}
	for addr := range before.hosts {
		// Both sides use the identity as of the after scan, which a merge may have renamed.
		if id := after.identity[addr]; id != "" && before.responded(addr) && !after.responded(addr) {
			gone[id] = append(gone[id], addr)
		}
	}
	for addr := range after.hosts {
		if id := after.identity[addr]; id != "" && after.responded(addr) && !before.responded(addr) {
			came[id] = append(came[id], addr)
		}
	}
	for id, from := range gone {
		if to := came[id]; len(from) == 1 && len(to) == 1 {
			moved[from[0]], movedTo[to[0]] = to[0], true
		}
	}

	seen := map[netip.Addr]bool{}
	var addrs []netip.Addr
	for _, side := range []diffSide{before, after} {
		for addr := range side.hosts {
			if !seen[addr] {
				seen[addr] = true
				addrs = append(addrs, addr)
			}
		}
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })

	unprobed := 0
	for _, addr := range addrs {
		if movedTo[addr] {
			continue // reported at its old address
		}
		if to, ok := moved[addr]; ok {
			add(DiffChange{Kind: "address_membership", Change: "changed", Address: addr,
				Before: addr.String(), After: to.String()})
			unprobed += diffEndpoints(add, before, after, addr, to)
			continue
		}
		if b, a := before.identity[addr], after.identity[addr]; b != "" && a != "" && b != a {
			cause := ""
			for _, e := range events {
				if e.Address == addr && e.ObservedAt.After(before.cutoff) && !e.ObservedAt.After(after.cutoff) {
					cause = e.Cause
				}
			}
			kind := "identity_correlation"
			switch {
			case strings.HasPrefix(cause, "manual_"):
				kind = "identity_manual"
			case strings.HasPrefix(cause, "signal_changed:"):
				kind = "address_reassignment" // a different device now answers here
			}
			add(DiffChange{Kind: kind, Change: "changed", Reason: cause, Address: addr, Before: b, After: a})
		}
		hb, ha := before.hosts[addr], after.hosts[addr]
		switch b, a := before.responded(addr), after.responded(addr); {
		case b && !a:
			add(DiffChange{Kind: "asset_presence", Change: "not_observed", Status: DiffUnverified,
				Reason: after.absent(ha != nil, after.planned(addr, diffKey{})), Address: addr})
			continue // per-endpoint silence would repeat the same uncertainty
		case !b && a:
			c := DiffChange{Kind: "asset_presence", Change: "added", Address: addr}
			if !before.covered(hb != nil, before.planned(addr, diffKey{})) {
				c.Status, c.Reason = DiffUnverified, before.absent(false, false)
			}
			add(c)
		case !b:
			continue
		}
		unprobed += diffEndpoints(add, before, after, addr, addr)
	}
	if unprobed > 0 {
		diff.Limitations = append(diff.Limitations, fmt.Sprintf("service identity not compared on %d open endpoint(s) identified in only one scan", unprobed))
	}
	sort.Strings(diff.Limitations)
	return diff, true, nil
}

// diffEndpoints compares one asset's endpoints, at address from in the
// before scan and to in the after scan. It returns how many endpoints open
// in both scans carry a service claim in only one of them.
func diffEndpoints(add func(DiffChange), before, after diffSide, from, to netip.Addr) (unprobed int) {
	hb, ha := before.hosts[from], after.hosts[to]
	set := map[diffKey]bool{}
	for _, h := range []*diffHost{hb, ha} {
		if h == nil {
			continue
		}
		for k := range h.ports {
			set[k] = true
		}
		for k := range h.claims {
			set[k] = true
		}
	}
	keys := make([]diffKey, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].transport != keys[j].transport {
			return keys[i].transport < keys[j].transport
		}
		return keys[i].port < keys[j].port
	})
	describe := func(h *diffHost, k diffKey, state string) string {
		if o, ok := h.claims[k]; ok && diffService(o) != "" {
			return state + " " + diffService(o)
		}
		return state
	}
	for _, k := range keys {
		sb, ob, testedB := hb.state(k)
		sa, oa, testedA := ha.state(k)
		c := DiffChange{Kind: "service", Address: to, Transport: k.transport, Port: k.port}
		switch pb, pa := diffPositive(sb), diffPositive(sa); {
		case pb && !pa:
			c.Before, c.BeforeObservation, c.After, c.AfterObservation = describe(hb, k, sb), ob.ID, sa, oa.ID
			if c.Change = "removed"; sa != "closed" {
				c.Change, c.Status, c.Reason = "not_observed", DiffUnverified, after.absent(testedA, after.planned(to, k))
			}
			add(c)
		case !pb && pa:
			c.Change, c.Before, c.BeforeObservation, c.After, c.AfterObservation = "added", sb, ob.ID, describe(ha, k, sa), oa.ID
			if !before.covered(testedB, before.planned(from, k)) {
				c.Status, c.Reason = DiffUnverified, before.absent(false, false)
			}
			add(c)
		case pb && pa:
			cb, okB := hb.claims[k]
			ca, okA := ha.claims[k]
			if okB != okA {
				unprobed++
			}
			if okB && okA {
				diffClaims(add, c, cb, ca)
			}
		}
	}
	if hb != nil && ha != nil && hb.device != nil && ha.device != nil {
		diffClaims(add, DiffChange{Address: to, Transport: "device"}, *hb.device, *ha.device)
	}
	return unprobed
}

// diffClaims compares two identifications of the same endpoint.
func diffClaims(add func(DiffChange), base DiffChange, b, a observe.Observation) {
	base.Change, base.BeforeObservation, base.AfterObservation = "changed", b.ID, a.ID
	if diffTruncated(b) || diffTruncated(a) {
		base.Status, base.Reason = DiffUnverified, "truncated_evidence"
	}
	emit := func(kind, field, before, after string) {
		if before != "" && after != "" && before != after {
			c := base
			c.Kind, c.Field, c.Before, c.After = kind, field, before, after
			add(c)
		}
	}
	if b.Kind == observe.KindService {
		emit("service", "", diffService(b), diffService(a))
	}
	if b.TLS != nil && a.TLS != nil {
		if len(b.TLS.Certificates) > 0 && len(a.TLS.Certificates) > 0 && b.TLS.ServerName == a.TLS.ServerName {
			x, y := b.TLS.Certificates[0], a.TLS.Certificates[0]
			emit("tls_certificate", "leaf", x.SHA256+" "+x.Subject, y.SHA256+" "+y.Subject)
		}
		if b.TLS.Profile == a.TLS.Profile && b.TLS.ServerName == a.TLS.ServerName {
			emit("tls_configuration", "negotiated", strings.TrimSpace(b.TLS.Version+" "+b.TLS.CipherSuite+" "+b.TLS.ALPN),
				strings.TrimSpace(a.TLS.Version+" "+a.TLS.CipherSuite+" "+a.TLS.ALPN))
		}
	}
	for _, f := range [][2]string{{"tls_configuration", observe.FingerprintTLSServer}, {"ssh_configuration", observe.FingerprintSSHServer}} {
		scopeB, valueB := diffFingerprint(b, f[1])
		if scopeA, valueA := diffFingerprint(a, f[1]); scopeB == scopeA {
			emit(f[0], f[1], valueB, valueA)
		}
	}
	for _, attr := range diffAttributes {
		emit(attr.kind, attr.key, b.Attributes[attr.key], a.Attributes[attr.key])
	}
}
