package storage

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

type IdentityClaim struct {
	Kind       string     `json:"kind"`
	Value      string     `json:"value"`
	Address    netip.Addr `json:"address"`
	ScanID     string     `json:"scan_id"`
	Probe      string     `json:"probe"`
	Confidence int        `json:"confidence"`
	ObservedAt time.Time  `json:"observed_at"`
}

type IdentityProfile struct {
	Class  string          `json:"class,omitempty"`
	Model  string          `json:"model,omitempty"`
	OS     string          `json:"os,omitempty"`
	Claims []IdentityClaim `json:"claims"`
}

func profileClaims(o observe.Observation) []IdentityClaim {
	var out []IdentityClaim
	add := func(kind, value string) {
		value = strings.TrimSpace(value)
		if value != "" && len(value) <= 256 {
			out = append(out, IdentityClaim{Kind: kind, Value: value, Address: o.Target,
				ScanID: o.ScanID, Probe: o.Probe, Confidence: o.Confidence, ObservedAt: o.Timestamp})
		}
	}
	if o.Kind == observe.KindDevice && o.Confidence >= 65 {
		add("class", o.Attributes["device.class"])
	}
	if o.Kind == observe.KindService && o.State == "open" && o.Confidence >= 85 {
		if o.Service == "modbus" || o.Service == "ethernetip" {
			add("model", o.Product)
		}
		if o.Service == "smb" && o.Attributes["smb.os_version"] != "" {
			add("os", "Windows "+o.Attributes["smb.os_version"])
		}
		if o.Probe == "nmap" && o.Confidence >= 90 {
			add("os", o.Attributes["nmap.os"])
			add("class", o.Attributes["nmap.device"])
		}
	}
	return out
}

func (s *Store) enrichIdentityProfiles(ctx context.Context, graph []IdentityAsset) error {
	byID := map[string]int{}
	for i := range graph {
		byID[graph[i].ID] = i
		graph[i].Profile.Claims = []IdentityClaim{}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT m.identity_id, o.record, o.scan_id, o.observed_at, a.address
		FROM observations o JOIN identity_members m ON m.asset_id = o.asset_id
		JOIN assets a ON a.id = o.asset_id
		WHERE o.kind IN ('service', 'device') AND o.confidence >= 65
		AND o.observed_at >= COALESCE((SELECT MAX(e.observed_at) FROM identity_membership_events e
			WHERE e.address = a.address AND e.cause LIKE 'signal_changed:%'), '')
		ORDER BY o.observed_at DESC, o.id DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var identityID int64
		var record, scanID, observed, address string
		if err := rows.Scan(&identityID, &record, &scanID, &observed, &address); err != nil {
			return err
		}
		i, ok := byID[identityName(identityID)]
		if !ok {
			continue
		}
		var o observe.Observation
		if err := json.Unmarshal([]byte(record), &o); err != nil {
			return err
		}
		for _, claim := range profileClaims(o) {
			key := graph[i].ID + "|" + address + "|" + claim.Kind
			if seen[key] {
				continue
			}
			seen[key] = true
			claim.ScanID, claim.ObservedAt = scanID, parseTS(observed)
			graph[i].Profile.Claims = append(graph[i].Profile.Claims, claim)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range graph {
		values := map[string]map[string]bool{}
		for _, claim := range graph[i].Profile.Claims {
			if values[claim.Kind] == nil {
				values[claim.Kind] = map[string]bool{}
			}
			values[claim.Kind][claim.Value] = true
		}
		for kind, set := range values {
			if len(set) != 1 {
				continue
			}
			var value string
			for value = range set {
				break
			}
			switch kind {
			case "class":
				graph[i].Profile.Class = value
			case "model":
				graph[i].Profile.Model = value
			case "os":
				graph[i].Profile.OS = value
			}
		}
		sort.Slice(graph[i].Profile.Claims, func(a, b int) bool {
			x, y := graph[i].Profile.Claims[a], graph[i].Profile.Claims[b]
			if x.Kind != y.Kind {
				return x.Kind < y.Kind
			}
			if !x.ObservedAt.Equal(y.ObservedAt) {
				return x.ObservedAt.After(y.ObservedAt)
			}
			return x.Address.Less(y.Address)
		})
	}
	return nil
}
