package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

const TopologySchema = "nyxr/topology/v1alpha1"

// TopologyClaim is evidence that an address used an interface at one instant.
// A packet or neighbor response does not prove continuous ownership. VLAN
// membership is only asserted when a tagged source packet was retained.
type TopologyClaim struct {
	ID          int64             `json:"id"`
	Kind        string            `json:"kind"`
	InterfaceID string            `json:"interface_id"`
	Address     string            `json:"address"`
	VLANID      uint16            `json:"vlan_id,omitempty"`
	IdentityID  string            `json:"identity_id,omitempty"`
	ValidFrom   time.Time         `json:"valid_from"`
	ValidUntil  time.Time         `json:"valid_until"`
	Validity    string            `json:"validity"`
	SourceKind  string            `json:"source_kind"`
	Source      observe.SourceRef `json:"source"`
	Conflict    bool              `json:"conflict,omitempty"`
	Overridden  bool              `json:"overridden,omitempty"`
}

// TemporalTopology carries observed claims and their limits. Unknown history
// is explicit because neither missing packets nor a migration baseline prove
// who owned an interface earlier.
type TemporalTopology struct {
	Schema        string           `json:"schema"`
	HistoryBefore string           `json:"history_before_first_evidence"`
	Claims        []TopologyClaim  `json:"claims"`
	Adjacencies   []PassiveLink    `json:"adjacencies"`
	Reviews       []TopologyReview `json:"reviews"`
	Truncated     bool             `json:"truncated"`
}

func topologySourceKind(o observe.Observation) string {
	if o.Probe == "pcap-passive" && o.State == "observed" && o.Kind == observe.KindHost {
		return "passive_packet"
	}
	if (o.Probe == "arp-solicitation" || o.Probe == "ndp-solicitation") && o.State == "responsive" && o.Kind == observe.KindHost {
		return "neighbor_response"
	}
	return ""
}

func storeTopologyClaim(ctx context.Context, tx *sql.Tx, observationID int64, o observe.Observation) error {
	kind := topologySourceKind(o)
	if kind == "" || !o.Target.IsValid() || o.Source == nil || o.Source.ArtifactID == "" {
		return nil
	}
	mac, err := net.ParseMAC(o.MAC)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || isZeroHardwareAddr(mac) {
		return nil
	}
	var vlan int
	if raw := o.Fields["vlan.id"]; raw != "" && kind == "passive_packet" {
		vlan, err = strconv.Atoi(raw)
		if err != nil || vlan < 1 || vlan > 4094 {
			vlan = 0
		}
	}
	// Scope the MAC to the reviewed identity known at observation time. Passive
	// reuse of one MAC on two unrelated addresses must not create one interface.
	var owner string
	err = tx.QueryRowContext(ctx, `SELECT to_identity FROM identity_membership_events
		WHERE address = ? AND observed_at <= ? ORDER BY observed_at DESC, id DESC LIMIT 1`,
		o.Target.String(), ts(o.Timestamp)).Scan(&owner)
	if err == sql.ErrNoRows {
		owner, err = "address:"+o.Target.String(), nil
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO topology_claims
		(observation_id, scan_id, observed_at, interface_id, address, vlan_id, source_artifact_id, source_kind)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		observationID, o.ScanID, ts(o.Timestamp), owner+"/mac:"+mac.String(), o.Target.String(), vlan, o.Source.ArtifactID, kind)
	return err
}

// backfillTopologyClaims uses only retained observations and their immutable
// source artifacts. In particular it does not invent pre-migration intervals.
func backfillTopologyClaims(ctx context.Context, tx *sql.Tx) error {
	var after int64
	for {
		rows, err := tx.QueryContext(ctx, `SELECT o.id, o.scan_id, o.record, s.artifact_id
			FROM observations o JOIN observation_sources s ON s.observation_id = o.id
			WHERE o.id > ? ORDER BY o.id LIMIT 256`, after)
		if err != nil {
			return err
		}
		type item struct {
			id       int64
			scanID   string
			record   string
			artifact string
		}
		batch := make([]item, 0, 256)
		for rows.Next() {
			var v item
			if err := rows.Scan(&v.id, &v.scanID, &v.record, &v.artifact); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, v)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		for _, v := range batch {
			var o observe.Observation
			if err := json.Unmarshal([]byte(v.record), &o); err != nil {
				return fmt.Errorf("observation %d: %w", v.id, err)
			}
			o.Source = &observe.SourceRef{ArtifactID: v.artifact}
			o.ScanID = v.scanID
			if err := storeTopologyClaim(ctx, tx, v.id, o); err != nil {
				return err
			}
		}
		after = batch[len(batch)-1].id
	}
}

func (s *Store) identityAt(ctx context.Context, address string, at time.Time) (string, error) {
	if address == "" {
		return "", nil
	}
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT to_identity FROM identity_membership_events
		WHERE address = ? AND observed_at <= ? ORDER BY observed_at DESC, id DESC LIMIT 1`,
		address, ts(at)).Scan(&id)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return id, err
}

// TopologyTimeline lists at most limit recent address/interface claims and
// LLDP adjacencies. An optional time is a strict valid-time lookup: point
// claims match only their observation instant, and LLDP expires at its TTL.
func (s *Store) TopologyTimeline(ctx context.Context, limit int, at time.Time) (TemporalTopology, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	out := TemporalTopology{Schema: TopologySchema, HistoryBefore: "unknown", Claims: []TopologyClaim{},
		Adjacencies: []PassiveLink{}, Reviews: []TopologyReview{}}
	query := `SELECT c.observation_id, c.scan_id, c.observed_at, c.interface_id, c.address, c.vlan_id,
		c.source_artifact_id, c.source_kind,
		(EXISTS(SELECT 1 FROM topology_claims other
			WHERE other.address = c.address AND other.observed_at = c.observed_at
			AND other.interface_id <> c.interface_id)
		 OR EXISTS(SELECT 1 FROM topology_reviews review
			WHERE review.address = c.address AND review.decision = 'join'
			AND review.valid_from <= c.observed_at AND review.valid_until > c.observed_at
			AND review.interface_id <> c.interface_id)),
		EXISTS(SELECT 1 FROM topology_reviews review
			WHERE review.address = c.address AND review.decision = 'separate'
			AND review.valid_from <= c.observed_at AND review.valid_until > c.observed_at
			AND review.interface_id = c.interface_id)
		FROM topology_claims c`
	var args []any
	if !at.IsZero() {
		query += ` WHERE c.observed_at = ?`
		args = append(args, ts(at))
	}
	query += ` ORDER BY c.observed_at DESC, c.observation_id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var claim TopologyClaim
		var scanID, observed, artifact string
		if err := rows.Scan(&claim.ID, &scanID, &observed, &claim.InterfaceID, &claim.Address,
			&claim.VLANID, &artifact, &claim.SourceKind, &claim.Conflict, &claim.Overridden); err != nil {
			rows.Close()
			return out, err
		}
		if len(out.Claims) == limit {
			out.Truncated = true
			break
		}
		claim.Kind = "address_ownership"
		claim.ValidFrom, claim.ValidUntil = parseTS(observed), parseTS(observed)
		claim.Validity = "point"
		claim.Source = observe.SourceRef{Owner: "next-gen", SourceSchema: observe.SchemaVersion,
			ArtifactID: artifact, RunID: scanID}
		out.Claims = append(out.Claims, claim)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	for i := range out.Claims {
		id, err := s.identityAt(ctx, out.Claims[i].Address, out.Claims[i].ValidFrom)
		if err != nil {
			return out, err
		}
		out.Claims[i].IdentityID = id
	}
	links, extra, err := s.passiveLinks(ctx, limit, at)
	if err != nil {
		return out, err
	}
	out.Adjacencies = links
	out.Truncated = out.Truncated || extra
	markAdjacencyConflicts(out.Adjacencies)
	reviews, extra, err := s.topologyReviews(ctx, limit, at)
	if err != nil {
		return out, err
	}
	out.Reviews = reviews
	out.Truncated = out.Truncated || extra
	markTopologyConflicts(out.Claims, out.Reviews)
	return out, nil
}

func markAdjacencyConflicts(links []PassiveLink) {
	for i := range links {
		for j := i + 1; j < len(links); j++ {
			a, b := &links[i], &links[j]
			if a.ChassisID != b.ChassisID || a.PortID != b.PortID ||
				(a.LocalInterface == b.LocalInterface && a.SourceMAC == b.SourceMAC && a.ManagementAddress == b.ManagementAddress) {
				continue
			}
			aEnd, bEnd := a.ValidUntil, b.ValidUntil
			if !aEnd.After(a.ObservedAt) {
				aEnd = a.ObservedAt.Add(time.Nanosecond)
			}
			if !bEnd.After(b.ObservedAt) {
				bEnd = b.ObservedAt.Add(time.Nanosecond)
			}
			if intervalsOverlap(a.ObservedAt, aEnd, b.ObservedAt, bEnd) {
				a.Conflict, b.Conflict = true, true
			}
		}
	}
}
