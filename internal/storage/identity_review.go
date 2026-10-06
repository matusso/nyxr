package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type IdentityReview struct {
	AddressA  netip.Addr `json:"address_a"`
	AddressB  netip.Addr `json:"address_b"`
	Decision  string     `json:"decision"`
	Note      string     `json:"note"`
	DecidedAt time.Time  `json:"decided_at"`
}

func orderedAddresses(a, b netip.Addr) (netip.Addr, netip.Addr) {
	if a.Compare(b) > 0 {
		return b, a
	}
	return a, b
}

// ReviewIdentityPair records an operator decision and applies it atomically.
// A separation blocks future automatic joins of the two groups; a join is an
// explicit graph edge that survives evidence retention. Clear removes the
// latest decision, leaving subsequent observations to reconcile the pair.
func (s *Store) ReviewIdentityPair(ctx context.Context, a, b netip.Addr, decision, note string) error {
	if !a.IsValid() || !b.IsValid() || a == b {
		return errors.New("two distinct IP addresses are required")
	}
	if decision != "join" && decision != "separate" && decision != "clear" {
		return errors.New("decision must be join, separate, or clear")
	}
	note = strings.TrimSpace(note)
	if len(note) == 0 || len(note) > 500 {
		return errors.New("review note must be 1 to 500 characters")
	}
	a, b = orderedAddresses(a, b)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var assetA, assetB, idA, idB int64
	if err := tx.QueryRowContext(ctx, `SELECT a.id, m.identity_id FROM assets a JOIN identity_members m ON m.asset_id = a.id WHERE a.address = ?`, a.String()).Scan(&assetA, &idA); err != nil {
		return fmt.Errorf("first address: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT a.id, m.identity_id FROM assets a JOIN identity_members m ON m.asset_id = a.id WHERE a.address = ?`, b.String()).Scan(&assetB, &idB); err != nil {
		return fmt.Errorf("second address: %w", err)
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `INSERT INTO identity_reviews(address_a, address_b, decision, note, decided_at) VALUES (?, ?, ?, ?, ?)`,
		a.String(), b.String(), decision, note, ts(now)); err != nil {
		return err
	}
	switch decision {
	case "join":
		if idA != idB {
			blocked, err := manualSeparationConflict(ctx, tx, idA, idB)
			if err != nil {
				return err
			}
			if blocked {
				return errors.New("another active separation review conflicts with this join")
			}
			keep, drop := idA, idB
			if drop < keep {
				keep, drop = drop, keep
			}
			rows, err := tx.QueryContext(ctx, `SELECT asset_id FROM identity_members WHERE identity_id = ?`, drop)
			if err != nil {
				return err
			}
			var moved []int64
			for rows.Next() {
				var id int64
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				moved = append(moved, id)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			for _, id := range moved {
				if err := moveIdentityMember(ctx, tx, id, keep, "manual_join", now, ""); err != nil {
					return err
				}
			}
			if _, err := tx.ExecContext(ctx, `UPDATE identity_assets SET first_seen = min(first_seen, (SELECT first_seen FROM identity_assets WHERE id = ?)) WHERE id = ?`, drop, keep); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM identity_assets WHERE id = ?`, drop); err != nil {
				return err
			}
		}
	case "separate":
		if idA == idB {
			component, err := manualJoinComponent(ctx, tx, assetB, idA)
			if err != nil {
				return err
			}
			for _, id := range component {
				if id == assetA {
					return errors.New("another active manual join still connects these addresses")
				}
			}
			res, err := tx.ExecContext(ctx, `INSERT INTO identity_assets(first_seen) SELECT first_seen FROM assets WHERE id = ?`, assetB)
			if err != nil {
				return err
			}
			newID, err := res.LastInsertId()
			if err != nil {
				return err
			}
			for _, id := range component {
				if err := moveIdentityMember(ctx, tx, id, newID, "manual_separate", now, ""); err != nil {
					return err
				}
			}
		}
	case "clear":
		if err := splitPrunedIdentities(ctx, tx, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func manualJoinComponent(ctx context.Context, tx *sql.Tx, start, identityID int64) ([]int64, error) {
	rows, err := tx.QueryContext(ctx, `SELECT a.id, b.id FROM identity_reviews r
		JOIN assets a ON a.address = r.address_a JOIN identity_members ma ON ma.asset_id = a.id
		JOIN assets b ON b.address = r.address_b JOIN identity_members mb ON mb.asset_id = b.id
		WHERE ma.identity_id = ? AND mb.identity_id = ? AND r.decision = 'join' AND r.id = (
			SELECT MAX(latest.id) FROM identity_reviews latest WHERE latest.address_a = r.address_a AND latest.address_b = r.address_b)`, identityID, identityID)
	if err != nil {
		return nil, err
	}
	adjacent := map[int64][]int64{}
	for rows.Next() {
		var a, b int64
		if err := rows.Scan(&a, &b); err != nil {
			rows.Close()
			return nil, err
		}
		adjacent[a] = append(adjacent[a], b)
		adjacent[b] = append(adjacent[b], a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	component := []int64{start}
	seen := map[int64]bool{start: true}
	for i := 0; i < len(component); i++ {
		for _, peer := range adjacent[component[i]] {
			if !seen[peer] {
				seen[peer] = true
				component = append(component, peer)
			}
		}
	}
	return component, nil
}

func manualSeparationConflict(ctx context.Context, tx *sql.Tx, left, right int64) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_reviews r
		JOIN assets a ON a.address = r.address_a JOIN identity_members ma ON ma.asset_id = a.id
		JOIN assets b ON b.address = r.address_b JOIN identity_members mb ON mb.asset_id = b.id
		WHERE r.decision = 'separate' AND r.id = (
			SELECT MAX(latest.id) FROM identity_reviews latest WHERE latest.address_a = r.address_a AND latest.address_b = r.address_b)
		AND ((ma.identity_id = ? AND mb.identity_id = ?) OR (ma.identity_id = ? AND mb.identity_id = ?))`,
		left, right, right, left).Scan(&n)
	return n > 0, err
}

func hasManualJoin(ctx context.Context, tx *sql.Tx, assetID int64) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_reviews r
		JOIN assets a ON a.address = r.address_a JOIN assets b ON b.address = r.address_b
		WHERE r.decision = 'join' AND (a.id = ? OR b.id = ?) AND r.id = (
			SELECT MAX(latest.id) FROM identity_reviews latest WHERE latest.address_a = r.address_a AND latest.address_b = r.address_b)`, assetID, assetID).Scan(&n)
	return n > 0, err
}

func (s *Store) IdentityReviews(ctx context.Context) ([]IdentityReview, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT address_a, address_b, decision, note, decided_at FROM identity_reviews ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IdentityReview{}
	for rows.Next() {
		var a, b, at string
		var review IdentityReview
		if err := rows.Scan(&a, &b, &review.Decision, &review.Note, &at); err != nil {
			return nil, err
		}
		review.AddressA, _ = netip.ParseAddr(a)
		review.AddressB, _ = netip.ParseAddr(b)
		review.DecidedAt = parseTS(at)
		out = append(out, review)
	}
	return out, rows.Err()
}
