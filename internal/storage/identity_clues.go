package storage

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

type IdentityClue struct {
	Kind       string     `json:"kind"`
	Value      string     `json:"value"`
	ScanID     string     `json:"scan_id"`
	Address    netip.Addr `json:"address"`
	ObservedAt time.Time  `json:"observed_at"`
}

// IdentityRelation is a shared weak clue. It never changes membership.
type IdentityRelation struct {
	LeftID  string `json:"left_id"`
	RightID string `json:"right_id"`
	Kind    string `json:"kind"`
	Value   string `json:"value"`
}

func identityClues(o observe.Observation) []identityValue {
	var clues []identityValue
	seen := map[identityValue]bool{}
	add := func(kind, value string) {
		clue := identityValue{kind, value}
		if value != "" && !seen[clue] {
			clues = append(clues, clue)
			seen[clue] = true
		}
	}
	if o.State == "open" && o.Confidence >= 85 {
		if o.Service == "ssdp" {
			if uuid := strings.ToLower(o.Fields["ssdp.uuid"]); validUUID(uuid) {
				add("upnp_uuid", uuid)
			}
		}
		for _, key := range []string{"smb.dns_computer", "nmap.hostname", "rdp.hostname", "smtp.hostname"} {
			if name := normalizedHostname(o.Attributes[key]); name != "" {
				add("hostname", name)
			}
		}
		if o.TLS != nil && len(o.TLS.Certificates) > 0 {
			leaf := o.TLS.Certificates[0]
			fingerprint := strings.ToLower(strings.ReplaceAll(leaf.SHA256, ":", ""))
			if raw, err := hex.DecodeString(fingerprint); err == nil && len(raw) == 32 && !allZero(raw) {
				add("certificate_sha256", fingerprint)
			}
			for _, name := range leaf.DNSNames {
				if normalized := normalizedHostname(name); normalized != "" {
					add("certificate_dns_name", normalized)
				}
			}
		}
	}
	if o.State == "responsive" && (o.Probe == "arp-solicitation" || o.Probe == "ndp-solicitation") {
		if mac, err := net.ParseMAC(o.MAC); err == nil && len(mac) == 6 && mac[0]&1 == 0 && !allZero(mac) {
			add("mac_oui", hex.EncodeToString(mac[:3]))
		}
	}
	if o.State == "observed" && (o.Probe == "pcap-passive" || o.Probe == "lldp-passive") {
		if name := strings.TrimSpace(o.Fields["capture.interface"]); len(name) > 0 && len(name) <= 64 {
			add("capture_interface", name)
		}
		if vlan := o.Fields["vlan.id"]; validVLAN(vlan) {
			add("vlan_id", vlan)
		}
		if o.Probe == "lldp-passive" {
			if chassis := o.Fields["lldp.chassis_id"]; len(chassis) > 2 && len(chassis) <= 520 {
				add("lldp_chassis_id", chassis)
			}
			if port := o.Fields["lldp.port_id"]; len(port) > 2 && len(port) <= 520 {
				add("lldp_port_id", port)
			}
		}
	}
	return clues
}

func validVLAN(value string) bool {
	if value == "" || len(value) > 4 {
		return false
	}
	n := 0
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n >= 1 && n <= 4094
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func normalizedHostname(raw string) string {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if len(name) == 0 || len(name) > 253 || strings.ContainsAny(name, "*/\\:@ ") {
		return ""
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return ""
	}
	for _, part := range strings.Split(name, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return ""
		}
		for _, c := range part {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return ""
			}
		}
	}
	return name
}

func storeIdentityClues(ctx context.Context, tx *sql.Tx, observationID, assetID int64, o observe.Observation) error {
	for _, clue := range identityClues(o) {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO identity_clues(observation_id, asset_id, kind, value, observed_at)
			VALUES (?, ?, ?, ?, ?)`, observationID, assetID, clue.kind, clue.value, ts(o.Timestamp)); err != nil {
			return err
		}
	}
	return nil
}

func backfillIdentityClues(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, asset_id, record FROM observations ORDER BY id`)
	if err != nil {
		return err
	}
	type prior struct {
		id, assetID int64
		record      string
	}
	var records []prior
	for rows.Next() {
		var p prior
		if err := rows.Scan(&p.id, &p.assetID, &p.record); err != nil {
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
			return err
		}
		if err := storeIdentityClues(ctx, tx, p.id, p.assetID, o); err != nil {
			return err
		}
	}
	return nil
}

// IdentityRelations reports clues shared by different current identities.
func (s *Store) IdentityRelations(ctx context.Context) ([]IdentityRelation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT c.kind, c.value, m.identity_id
		FROM identity_clues c JOIN identity_members m ON m.asset_id = c.asset_id
		WHERE c.kind IN ('hostname', 'certificate_sha256', 'certificate_dns_name', 'upnp_uuid', 'lldp_chassis_id')
		ORDER BY c.kind, c.value, m.identity_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IdentityRelation{}
	var kind, value string
	var ids []int64
	flush := func() {
		// A fleet-wide certificate or name is too broad for a useful candidate.
		if len(ids) < 2 || len(ids) > 16 {
			return
		}
		for i := 0; i < len(ids); i++ {
			for j := i + 1; j < len(ids); j++ {
				out = append(out, IdentityRelation{LeftID: identityName(ids[i]), RightID: identityName(ids[j]), Kind: kind, Value: value})
			}
		}
	}
	for rows.Next() {
		var nextKind, nextValue string
		var id int64
		if err := rows.Scan(&nextKind, &nextValue, &id); err != nil {
			return nil, err
		}
		if kind != nextKind || value != nextValue {
			flush()
			kind, value, ids = nextKind, nextValue, ids[:0]
		}
		if len(ids) <= 16 {
			ids = append(ids, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	flush()
	sort.Slice(out, func(i, j int) bool {
		if out[i].LeftID != out[j].LeftID {
			return out[i].LeftID < out[j].LeftID
		}
		if out[i].RightID != out[j].RightID {
			return out[i].RightID < out[j].RightID
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	return out, nil
}
