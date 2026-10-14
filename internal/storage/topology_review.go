package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

const topologyReviewSchema = "nyxr/topology-review/v1"

// TopologyReviewInput is an explicit operator assertion with a finite valid
// interval. It does not change device identity membership or erase sightings.
type TopologyReviewInput struct {
	Address     string    `json:"address"`
	InterfaceID string    `json:"interface_id"`
	VLANID      uint16    `json:"vlan_id,omitempty"`
	Decision    string    `json:"decision"`
	ValidFrom   time.Time `json:"valid_from"`
	ValidUntil  time.Time `json:"valid_until"`
	Note        string    `json:"note"`
}

type TopologyReview struct {
	ID          int64             `json:"id"`
	Address     string            `json:"address"`
	InterfaceID string            `json:"interface_id"`
	VLANID      uint16            `json:"vlan_id,omitempty"`
	Decision    string            `json:"decision"`
	ValidFrom   time.Time         `json:"valid_from"`
	ValidUntil  time.Time         `json:"valid_until"`
	Note        string            `json:"note"`
	DecidedAt   time.Time         `json:"decided_at"`
	Source      observe.SourceRef `json:"source"`
	Conflict    bool              `json:"conflict,omitempty"`
}

// ReviewTopology records an operator join/separate assertion for an already
// observed interface. The source artifact is the immutable review payload.
func (s *Store) ReviewTopology(ctx context.Context, input TopologyReviewInput) (TopologyReview, error) {
	address, err := netip.ParseAddr(input.Address)
	if err != nil || !address.IsValid() || address.IsMulticast() || address.IsUnspecified() {
		return TopologyReview{}, errors.New("valid unicast address is required")
	}
	if len(input.InterfaceID) == 0 || len(input.InterfaceID) > 256 ||
		strings.TrimSpace(input.InterfaceID) != input.InterfaceID {
		return TopologyReview{}, errors.New("observed interface ID is required")
	}
	if input.Decision != "join" && input.Decision != "separate" {
		return TopologyReview{}, errors.New("decision must be join or separate")
	}
	if input.VLANID > 4094 {
		return TopologyReview{}, errors.New("VLAN ID must be 0..4094")
	}
	if input.ValidFrom.IsZero() || !input.ValidUntil.After(input.ValidFrom) ||
		input.ValidUntil.Sub(input.ValidFrom) > 10*366*24*time.Hour {
		return TopologyReview{}, errors.New("finite valid interval up to ten years is required")
	}
	input.Note = strings.TrimSpace(input.Note)
	if len(input.Note) == 0 || len(input.Note) > 500 {
		return TopologyReview{}, errors.New("review reason must be 1..500 bytes")
	}
	var known int
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM topology_claims WHERE interface_id = ?)`, input.InterfaceID).Scan(&known); err != nil {
		return TopologyReview{}, err
	}
	if known == 0 {
		return TopologyReview{}, errors.New("interface ID has no retained observation")
	}
	input.Address = address.String()
	input.ValidFrom, input.ValidUntil = input.ValidFrom.UTC(), input.ValidUntil.UTC()
	review := TopologyReview{Address: input.Address, InterfaceID: input.InterfaceID,
		VLANID: input.VLANID, Decision: input.Decision, ValidFrom: input.ValidFrom,
		ValidUntil: input.ValidUntil, Note: input.Note, DecidedAt: time.Now().UTC()}
	source, err := json.Marshal(struct {
		Schema string `json:"schema"`
		TopologyReviewInput
		DecidedAt time.Time `json:"decided_at"`
	}{topologyReviewSchema, input, review.DecidedAt})
	if err != nil {
		return TopologyReview{}, err
	}
	review.Source = observe.SourceRef{Owner: "next-gen", SourceSchema: topologyReviewSchema,
		ArtifactID: observe.ArtifactID(source)}
	res, err := s.db.ExecContext(ctx, `INSERT INTO topology_reviews
		(address, interface_id, vlan_id, decision, valid_from, valid_until, note, decided_at, source_artifact_id, source)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		review.Address, review.InterfaceID, review.VLANID, review.Decision, ts(review.ValidFrom),
		ts(review.ValidUntil), review.Note, ts(review.DecidedAt), review.Source.ArtifactID, source)
	if err != nil {
		return TopologyReview{}, err
	}
	review.ID, err = res.LastInsertId()
	return review, err
}

func (s *Store) topologyReviews(ctx context.Context, limit int, at time.Time) ([]TopologyReview, bool, error) {
	query := `SELECT review.id, review.address, review.interface_id, review.vlan_id, review.decision,
		review.valid_from, review.valid_until, review.note, review.decided_at, review.source_artifact_id,
		(EXISTS(SELECT 1 FROM topology_reviews other
			WHERE other.id <> review.id AND other.address = review.address
			AND other.valid_from < review.valid_until AND review.valid_from < other.valid_until
			AND (other.interface_id <> review.interface_id OR other.decision <> review.decision
				OR (other.vlan_id <> 0 AND review.vlan_id <> 0 AND other.vlan_id <> review.vlan_id)))
		 OR (review.decision = 'join' AND EXISTS(SELECT 1 FROM topology_claims claim
			WHERE claim.address = review.address AND claim.observed_at >= review.valid_from
			AND claim.observed_at < review.valid_until AND claim.interface_id <> review.interface_id)))
		FROM topology_reviews review`
	args := []any{}
	if !at.IsZero() {
		query += ` WHERE review.valid_from <= ? AND review.valid_until > ?`
		args = append(args, ts(at), ts(at))
	}
	query += ` ORDER BY review.valid_from DESC, review.id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, err
	}
	out := []TopologyReview{}
	truncated := false
	for rows.Next() {
		var review TopologyReview
		var from, until, decided, artifact string
		if err := rows.Scan(&review.ID, &review.Address, &review.InterfaceID, &review.VLANID,
			&review.Decision, &from, &until, &review.Note, &decided, &artifact, &review.Conflict); err != nil {
			rows.Close()
			return nil, false, err
		}
		if len(out) == limit {
			truncated = true
			break
		}
		review.ValidFrom, review.ValidUntil, review.DecidedAt = parseTS(from), parseTS(until), parseTS(decided)
		review.Source = observe.SourceRef{Owner: "next-gen", SourceSchema: topologyReviewSchema, ArtifactID: artifact}
		out = append(out, review)
	}
	err = rows.Err()
	rows.Close()
	return out, truncated, err
}

func intervalsOverlap(aStart, aEnd, bStart, bEnd time.Time) bool {
	return aStart.Before(bEnd) && bStart.Before(aEnd)
}

func markTopologyConflicts(claims []TopologyClaim, reviews []TopologyReview) {
	for i := range reviews {
		for j := i + 1; j < len(reviews); j++ {
			a, b := &reviews[i], &reviews[j]
			if a.Address == b.Address && intervalsOverlap(a.ValidFrom, a.ValidUntil, b.ValidFrom, b.ValidUntil) &&
				(a.InterfaceID != b.InterfaceID || a.Decision != b.Decision || (a.VLANID != 0 && b.VLANID != 0 && a.VLANID != b.VLANID)) {
				a.Conflict, b.Conflict = true, true
			}
		}
		for j := range claims {
			claim := &claims[j]
			if claim.Address != reviews[i].Address ||
				claim.ValidFrom.Before(reviews[i].ValidFrom) || !claim.ValidFrom.Before(reviews[i].ValidUntil) {
				continue
			}
			if reviews[i].Decision == "separate" && claim.InterfaceID == reviews[i].InterfaceID {
				claim.Overridden = true
			}
			if reviews[i].Decision == "join" && claim.InterfaceID != reviews[i].InterfaceID {
				claim.Conflict, reviews[i].Conflict = true, true
			}
		}
	}
}

func (s *Store) resolveTopologyReview(ctx context.Context, ref observe.SourceRef) (SourceResult, error) {
	r := SourceResult{Reference: ref, Status: "unavailable"}
	if ref.RunID != "" {
		r.Reason = "review source has no run provenance"
		return r, nil
	}
	var source []byte
	err := s.db.QueryRowContext(ctx, `SELECT source FROM topology_reviews WHERE source_artifact_id = ? LIMIT 1`, ref.ArtifactID).Scan(&source)
	if errors.Is(err, sql.ErrNoRows) {
		r.Reason = "topology review source is unavailable"
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if _, err := observe.ResolveSource(source, ref); err != nil {
		r.Reason = fmt.Sprintf("review source: %v", err)
		return r, nil
	}
	r.Status, r.Artifact = "available", source
	return r, nil
}
