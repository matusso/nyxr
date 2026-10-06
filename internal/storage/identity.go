package storage

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// Identity IDs are database-local and never derived from an address or a
// service banner. The oldest entity keeps its ID when two entities join.
func identityName(id int64) string { return fmt.Sprintf("NYXR-%012X", id) }

type identityValue struct{ kind, value string }

// Only device-scoped, response-validated values may join two addresses.
// Certificates, names, OUIs, software and HTTP headers can be shared by
// unrelated hosts, so they must not become automatic merge keys.
func strongIdentityValues(o observe.Observation) []identityValue {
	var out []identityValue
	if o.State == "observed" && (o.Probe == "inventory-import" || o.Probe == "kubernetes-api") && o.Confidence == 100 {
		if value, ok := externalIdentityValue(o.Fields["external.kind"], o.Fields["external.scope"], o.Fields["external.value"]); ok {
			out = append(out, value)
		}
	}
	if o.State == "responsive" && (o.Probe == "arp-solicitation" || o.Probe == "ndp-solicitation") {
		if mac, err := net.ParseMAC(o.MAC); err == nil && len(mac) == 6 && mac[0]&1 == 0 && !isZeroHardwareAddr(mac) {
			out = append(out, identityValue{"mac", mac.String()})
		}
	}
	if o.State == "open" && o.Confidence >= 85 {
		if raw := o.Fields["snmp.engine_id"]; raw != "" {
			b, err := hex.DecodeString(strings.ReplaceAll(raw, ":", ""))
			if err == nil && len(b) >= 5 && len(b) <= 32 && !allZero(b) {
				out = append(out, identityValue{"snmp.engine_id", hex.EncodeToString(b)})
			}
		}
		if o.Kind == observe.KindService && o.Service == "smb" {
			raw := strings.ToLower(strings.ReplaceAll(o.Attributes["smb.server_guid"], "-", ""))
			b, err := hex.DecodeString(raw)
			if err == nil && len(b) == 16 && !allZero(b) {
				out = append(out, identityValue{"smb.server_guid", hex.EncodeToString(b)})
			}
		}
		if o.Kind == observe.KindService && o.Service == "ssh" && o.Probe == "ssh" && o.Attributes["ssh.host_key_type"] != "" {
			raw := strings.ToLower(o.Attributes["ssh.host_key_sha256"])
			if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 && !allZero(b) {
				out = append(out, identityValue{"ssh.host_key_sha256", raw})
			}
		}
	}
	return out
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func isZeroHardwareAddr(mac net.HardwareAddr) bool { return allZero(mac) }

func recordIdentityEvent(ctx context.Context, tx *sql.Tx, assetID, from, to int64, cause string, seen time.Time, scanID string) error {
	var address string
	if err := tx.QueryRowContext(ctx, `SELECT address FROM assets WHERE id = ?`, assetID).Scan(&address); err != nil {
		return err
	}
	fromName, toName := "", ""
	if from != 0 {
		fromName = identityName(from)
	}
	if to != 0 {
		toName = identityName(to)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO identity_membership_events
		(address, from_identity, to_identity, cause, observed_at, recorded_at, scan_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, address, fromName, toName, cause, ts(seen), ts(time.Now()), scanID)
	return err
}

func moveIdentityMember(ctx context.Context, tx *sql.Tx, assetID, to int64, cause string, seen time.Time, scanID string) error {
	var from int64
	if err := tx.QueryRowContext(ctx, `SELECT identity_id FROM identity_members WHERE asset_id = ?`, assetID).Scan(&from); err != nil {
		return err
	}
	if from == to {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE identity_members SET identity_id = ? WHERE asset_id = ?`, to, assetID); err != nil {
		return err
	}
	return recordIdentityEvent(ctx, tx, assetID, from, to, cause, seen, scanID)
}

// IdentityMembershipEvent records a change in an address's current identity.
// Events survive observation retention and preserve IDs after a merged identity
// row is removed. Migration baselines begin the audit for existing databases.
type IdentityMembershipEvent struct {
	Address      netip.Addr `json:"address"`
	FromIdentity string     `json:"from_identity,omitempty"`
	ToIdentity   string     `json:"to_identity,omitempty"`
	Cause        string     `json:"cause"`
	ObservedAt   time.Time  `json:"observed_at"`
	RecordedAt   time.Time  `json:"recorded_at"`
	ScanID       string     `json:"scan_id,omitempty"`
}

// IdentityHistory returns the durable membership audit for one address, or
// all addresses when address is invalid, in the order changes were recorded.
func (s *Store) IdentityHistory(ctx context.Context, address netip.Addr) ([]IdentityMembershipEvent, error) {
	query := `SELECT address, from_identity, to_identity, cause, observed_at, recorded_at, scan_id
		FROM identity_membership_events`
	var args []any
	if address.IsValid() {
		query += ` WHERE address = ?`
		args = append(args, address.String())
	}
	query += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IdentityMembershipEvent{}
	for rows.Next() {
		var event IdentityMembershipEvent
		var rawAddress, observed, recorded string
		if err := rows.Scan(&rawAddress, &event.FromIdentity, &event.ToIdentity, &event.Cause,
			&observed, &recorded, &event.ScanID); err != nil {
			return nil, err
		}
		event.Address, _ = netip.ParseAddr(rawAddress)
		event.ObservedAt, event.RecordedAt = parseTS(observed), parseTS(recorded)
		out = append(out, event)
	}
	return out, rows.Err()
}

func backfillIdentity(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, asset_id, record FROM observations ORDER BY observed_at, id`)
	if err != nil {
		return err
	}
	type prior struct {
		observationID, assetID int64
		record                 string
	}
	var records []prior
	for rows.Next() {
		var p prior
		if err := rows.Scan(&p.observationID, &p.assetID, &p.record); err != nil {
			rows.Close()
			return err
		}
		records = append(records, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, p := range records {
		var o observe.Observation
		if err := json.Unmarshal([]byte(p.record), &o); err != nil {
			return fmt.Errorf("observation %d: %w", p.observationID, err)
		}
		if err := resolveIdentity(ctx, tx, p.observationID, p.assetID, o); err != nil {
			return err
		}
	}
	return nil
}

func resolveIdentity(ctx context.Context, tx *sql.Tx, observationID, assetID int64, o observe.Observation) error {
	for _, signal := range strongIdentityValues(o) {
		manualJoin, err := hasManualJoin(ctx, tx, assetID)
		if err != nil {
			return err
		}
		if manualJoin {
			if _, err := tx.ExecContext(ctx, `UPDATE identity_signals SET active = 0 WHERE asset_id = ? AND kind = ? AND value <> ?`,
				assetID, signal.kind, signal.value); err != nil {
				return err
			}
		} else {
			if err := separateChangedIdentity(ctx, tx, assetID, signal, o.Timestamp, o.ScanID); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO identity_signals(observation_id, asset_id, kind, value, observed_at) VALUES (?, ?, ?, ?, ?)`,
			observationID, assetID, signal.kind, signal.value, ts(o.Timestamp)); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT DISTINCT m.identity_id FROM identity_signals s
			JOIN identity_members m ON m.asset_id = s.asset_id WHERE s.active = 1 AND s.kind = ? AND s.value = ? ORDER BY m.identity_id`, signal.kind, signal.value)
		if err != nil {
			return err
		}
		var ids []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		var current int64
		if err := tx.QueryRowContext(ctx, `SELECT identity_id FROM identity_members WHERE asset_id = ?`, assetID).Scan(&current); err != nil {
			return err
		}
		removed := make(map[int64]bool)
		for _, other := range ids {
			if other == current || removed[other] {
				continue
			}
			conflict, err := identityConflict(ctx, tx, current, other)
			if err != nil {
				return err
			}
			if conflict {
				continue
			}
			blocked, err := manualSeparationConflict(ctx, tx, current, other)
			if err != nil {
				return err
			}
			if blocked {
				continue
			}
			keep, drop := current, other
			if drop < keep {
				keep, drop = drop, keep
			}
			members, err := tx.QueryContext(ctx, `SELECT asset_id FROM identity_members WHERE identity_id = ?`, drop)
			if err != nil {
				return err
			}
			var moved []int64
			for members.Next() {
				var id int64
				if err := members.Scan(&id); err != nil {
					members.Close()
					return err
				}
				moved = append(moved, id)
			}
			err = members.Err()
			members.Close()
			if err != nil {
				return err
			}
			for _, id := range moved {
				if err := moveIdentityMember(ctx, tx, id, keep, "signal_merge:"+signal.kind, o.Timestamp, o.ScanID); err != nil {
					return err
				}
			}
			if _, err := tx.ExecContext(ctx, `UPDATE identity_assets SET first_seen = min(first_seen,
				(SELECT first_seen FROM identity_assets WHERE id = ?)) WHERE id = ?`, drop, keep); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM identity_assets WHERE id = ?`, drop); err != nil {
				return err
			}
			removed[drop] = true
			current = keep
		}
	}
	return nil
}

// A changed device ID retires this address's old merge evidence. Keep those
// observations for audit, while assigning current observations a fresh ID.
func separateChangedIdentity(ctx context.Context, tx *sql.Tx, assetID int64, signal identityValue, seen time.Time, scanID string) error {
	var changed int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_signals
		WHERE asset_id = ? AND kind = ? AND value <> ? AND active = 1`, assetID, signal.kind, signal.value).Scan(&changed); err != nil {
		return err
	}
	if changed == 0 {
		return nil
	}
	if signal.kind == "mac" {
		var stable int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_signals WHERE asset_id = ?
			AND kind IN ('smb.server_guid', 'snmp.engine_id', 'ssh.host_key_sha256',
			'kubernetes.node_uid', 'cloud.aws.instance_id', 'cloud.azure.vm_id', 'cloud.gcp.instance_id') AND active = 1`, assetID).Scan(&stable); err != nil {
			return err
		}
		if stable > 0 {
			_, err := tx.ExecContext(ctx, `UPDATE identity_signals SET active = 0 WHERE asset_id = ? AND kind = 'mac' AND value <> ?`, assetID, signal.value)
			return err
		}
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO identity_assets(first_seen) VALUES (?)`, ts(seen))
	if err != nil {
		return err
	}
	newID, err := res.LastInsertId()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE identity_signals SET active = 0 WHERE asset_id = ?`, assetID); err != nil {
		return err
	}
	if err := moveIdentityMember(ctx, tx, assetID, newID, "signal_changed:"+signal.kind, seen, scanID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM identity_assets WHERE id NOT IN (SELECT identity_id FROM identity_members)`)
	return err
}

// Two different device-scoped values of the same kind prevent a join. A
// device can have several interfaces, so differing MACs alone do not conflict.
func identityConflict(ctx context.Context, tx *sql.Tx, left, right int64) (bool, error) {
	for _, kind := range []string{"smb.server_guid", "snmp.engine_id", "ssh.host_key_sha256",
		"kubernetes.node_uid", "cloud.aws.instance_id", "cloud.azure.vm_id", "cloud.gcp.instance_id"} {
		var count int
		err := tx.QueryRowContext(ctx, `SELECT COUNT(DISTINCT s.value) FROM identity_signals s
			JOIN identity_members m ON m.asset_id = s.asset_id
			WHERE m.identity_id IN (?, ?) AND s.kind = ? AND s.active = 1`, left, right, kind).Scan(&count)
		if err != nil {
			return false, err
		}
		if count > 1 {
			return true, nil
		}
	}
	return false, nil
}

// Pruning can delete the only observation that connected two addresses.
// Recompute connected components within each existing identity, retaining the
// old ID for its lowest address row and assigning new IDs to detached parts.
func splitPrunedIdentities(ctx context.Context, tx *sql.Tx, at time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT m.identity_id, m.asset_id, a.first_seen
		FROM identity_members m JOIN assets a ON a.id = m.asset_id ORDER BY m.identity_id, m.asset_id`)
	if err != nil {
		return err
	}
	members := make(map[int64][]int64)
	firstSeen := make(map[int64]string)
	for rows.Next() {
		var identityID, assetID int64
		var first string
		if err := rows.Scan(&identityID, &assetID, &first); err != nil {
			rows.Close()
			return err
		}
		members[identityID] = append(members[identityID], assetID)
		firstSeen[assetID] = first
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, `SELECT m.identity_id, s.asset_id, s.kind, s.value FROM identity_signals s
		JOIN identity_members m ON m.asset_id = s.asset_id WHERE s.active = 1 ORDER BY m.identity_id, s.kind, s.value`)
	if err != nil {
		return err
	}
	links := make(map[int64]map[identityValue][]int64)
	for rows.Next() {
		var identityID, assetID int64
		var v identityValue
		if err := rows.Scan(&identityID, &assetID, &v.kind, &v.value); err != nil {
			rows.Close()
			return err
		}
		if links[identityID] == nil {
			links[identityID] = make(map[identityValue][]int64)
		}
		links[identityID][v] = append(links[identityID][v], assetID)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, `SELECT r.id, ma.identity_id, a.id, b.id FROM identity_reviews r
		JOIN assets a ON a.address = r.address_a JOIN identity_members ma ON ma.asset_id = a.id
		JOIN assets b ON b.address = r.address_b JOIN identity_members mb ON mb.asset_id = b.id
		WHERE r.decision = 'join' AND ma.identity_id = mb.identity_id AND r.id = (
			SELECT MAX(latest.id) FROM identity_reviews latest WHERE latest.address_a = r.address_a AND latest.address_b = r.address_b)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var reviewID, identityID, a, b int64
		if err := rows.Scan(&reviewID, &identityID, &a, &b); err != nil {
			rows.Close()
			return err
		}
		if links[identityID] == nil {
			links[identityID] = make(map[identityValue][]int64)
		}
		links[identityID][identityValue{"manual", fmt.Sprint(reviewID)}] = []int64{a, b}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for identityID, ids := range members {
		if len(ids) < 2 {
			continue
		}
		parent := make(map[int64]int64, len(ids))
		for _, id := range ids {
			parent[id] = id
		}
		var find func(int64) int64
		find = func(id int64) int64 {
			if parent[id] != id {
				parent[id] = find(parent[id])
			}
			return parent[id]
		}
		for _, linked := range links[identityID] {
			for _, id := range linked[1:] {
				parent[find(id)] = find(linked[0])
			}
		}
		components := make(map[int64][]int64)
		for _, id := range ids {
			root := find(id)
			components[root] = append(components[root], id)
		}
		keepRoot := find(ids[0])
		var roots []int64
		for root := range components {
			roots = append(roots, root)
		}
		sort.Slice(roots, func(i, j int) bool { return roots[i] < roots[j] })
		for _, root := range roots {
			if root == keepRoot {
				continue
			}
			part := components[root]
			first := firstSeen[part[0]]
			for _, id := range part[1:] {
				if firstSeen[id] < first {
					first = firstSeen[id]
				}
			}
			res, err := tx.ExecContext(ctx, `INSERT INTO identity_assets(first_seen) VALUES (?)`, first)
			if err != nil {
				return err
			}
			newID, err := res.LastInsertId()
			if err != nil {
				return err
			}
			for _, id := range part {
				if err := moveIdentityMember(ctx, tx, id, newID, "evidence_pruned", at, ""); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// IdentitySignal records the observation that supports an identity link.
type IdentitySignal struct {
	Kind       string     `json:"kind"`
	Value      string     `json:"value"`
	ScanID     string     `json:"scan_id"`
	Address    netip.Addr `json:"address"`
	ObservedAt time.Time  `json:"observed_at"`
	Active     bool       `json:"active"`
}

// IdentityAsset groups address inventory under one persistent asset ID.
type IdentityAsset struct {
	ID             string               `json:"id"`
	GlobalID       string               `json:"global_id"`
	PortableIDs    []string             `json:"portable_ids"`
	LinkConfidence int                  `json:"link_confidence"`
	Hypotheses     []IdentityHypothesis `json:"hypotheses"`
	Profile        IdentityProfile      `json:"profile"`
	FirstSeen      time.Time            `json:"first_seen"`
	LastSeen       time.Time            `json:"last_seen"`
	Addresses      []Asset              `json:"addresses"`
	Signals        []IdentitySignal     `json:"signals"`
	Clues          []IdentityClue       `json:"clues"`
	Topology       []PassiveLink        `json:"topology"`
}

// IdentityGraph returns the current address membership and the exact stored
// observations that caused correlations. Per-address ports retain their own
// history rather than being treated as one host's port state.
func (s *Store) IdentityGraph(ctx context.Context) ([]IdentityAsset, error) {
	var namespace string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM identity_namespace WHERE id = 1`).Scan(&namespace); err != nil {
		return nil, err
	}
	assets, err := s.Assets(ctx)
	if err != nil {
		return nil, err
	}
	identityRows, err := s.db.QueryContext(ctx, `SELECT id, first_seen FROM identity_assets`)
	if err != nil {
		return nil, err
	}
	identityFirstSeen := make(map[string]time.Time)
	for identityRows.Next() {
		var id int64
		var first string
		if err := identityRows.Scan(&id, &first); err != nil {
			identityRows.Close()
			return nil, err
		}
		identityFirstSeen[identityName(id)] = parseTS(first)
	}
	err = identityRows.Err()
	identityRows.Close()
	if err != nil {
		return nil, err
	}
	graph := make([]IdentityAsset, 0)
	byID := make(map[string]int)
	for _, a := range assets {
		i, ok := byID[a.IdentityID]
		if !ok {
			i = len(graph)
			byID[a.IdentityID] = i
			graph = append(graph, IdentityAsset{ID: a.IdentityID, GlobalID: "urn:nyxr:" + namespace + ":" + a.IdentityID,
				FirstSeen: identityFirstSeen[a.IdentityID], LastSeen: a.LastSeen,
				Addresses: []Asset{}, Signals: []IdentitySignal{}, Clues: []IdentityClue{}, PortableIDs: []string{}, Topology: []PassiveLink{}})
		}
		g := &graph[i]
		g.Addresses = append(g.Addresses, a)
		if a.LastSeen.After(g.LastSeen) {
			g.LastSeen = a.LastSeen
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT m.identity_id, s.kind, s.value, o.scan_id, a.address, s.observed_at, s.active
		FROM identity_signals s JOIN identity_members m ON m.asset_id = s.asset_id
		JOIN assets a ON a.id = s.asset_id JOIN observations o ON o.id = s.observation_id
		ORDER BY m.identity_id, s.kind, s.value, s.observed_at, s.observation_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var address, observed string
		var signal IdentitySignal
		if err := rows.Scan(&id, &signal.Kind, &signal.Value, &signal.ScanID, &address, &observed, &signal.Active); err != nil {
			return nil, err
		}
		signal.Address, _ = netip.ParseAddr(address)
		signal.ObservedAt = parseTS(observed)
		if i, ok := byID[identityName(id)]; ok {
			graph[i].Signals = append(graph[i].Signals, signal)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range graph {
		seen := map[string]bool{}
		for _, signal := range graph[i].Signals {
			if !signal.Active || !externalKinds[signal.Kind] {
				continue
			}
			id := portableIdentityID(identityValue{signal.Kind, signal.Value})
			if !seen[id] {
				graph[i].PortableIDs = append(graph[i].PortableIDs, id)
				seen[id] = true
			}
		}
		sort.Strings(graph[i].PortableIDs)
	}
	clues, err := s.db.QueryContext(ctx, `SELECT m.identity_id, c.kind, c.value, o.scan_id, a.address, c.observed_at
		FROM identity_clues c JOIN identity_members m ON m.asset_id = c.asset_id
		JOIN assets a ON a.id = c.asset_id JOIN observations o ON o.id = c.observation_id
		ORDER BY m.identity_id, c.kind, c.value, c.observed_at, c.observation_id`)
	if err != nil {
		return nil, err
	}
	for clues.Next() {
		var id int64
		var address, observed string
		var clue IdentityClue
		if err := clues.Scan(&id, &clue.Kind, &clue.Value, &clue.ScanID, &address, &observed); err != nil {
			clues.Close()
			return nil, err
		}
		clue.Address, _ = netip.ParseAddr(address)
		clue.ObservedAt = parseTS(observed)
		if i, ok := byID[identityName(id)]; ok {
			graph[i].Clues = append(graph[i].Clues, clue)
		}
	}
	err = clues.Err()
	clues.Close()
	if err != nil {
		return nil, err
	}
	if err := enrichIdentityHypotheses(ctx, s, graph); err != nil {
		return nil, err
	}
	if err := s.enrichIdentityProfiles(ctx, graph); err != nil {
		return nil, err
	}
	links, err := s.PassiveLinks(ctx)
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		if i, ok := byID[link.IdentityID]; ok {
			graph[i].Topology = append(graph[i].Topology, link)
		}
	}
	sort.Slice(graph, func(i, j int) bool { return graph[i].ID < graph[j].ID })
	return graph, nil
}
