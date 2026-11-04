package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

// CloudInventorySchema versions the collected snapshot and reconciliation.
const CloudInventorySchema = "nyxr/cloud-inventory/v1alpha1"

const cloudInventoryProbe = "cloud-inventory"

var cloudProviderKinds = map[string]string{
	"aws":   "cloud.aws.instance_id",
	"azure": "cloud.azure.vm_id",
	"gcp":   "cloud.gcp.instance_id",
}

// CloudRecord is one address the provider API attached to one resource.
type CloudRecord struct {
	Address     netip.Addr `json:"address"`
	AddressRole string     `json:"address_role"` // private or public
	ResourceID  string     `json:"resource_id"`  // instance ID, vmId, or numeric instance ID
	Resource    string     `json:"resource"`     // ARN, ARM ID, or selfLink
	Location    string     `json:"location,omitempty"`
	Owner       string     `json:"owner,omitempty"` // provider-reported owning account/subscription/project
}

// CloudConflict is an address the provider attached to more than one
// resource in one snapshot. Assets are keyed by address, so the address is
// left out instead of guessed.
type CloudConflict struct {
	Address     netip.Addr `json:"address"`
	ResourceIDs []string   `json:"resource_ids"`
}

// CloudInventory is a read-only snapshot of one provider scope. Complete is
// false when any page, location, or resource type could not be read.
type CloudInventory struct {
	Provider  string          `json:"provider"`
	Scope     string          `json:"scope"`
	Region    string          `json:"region"`
	Collector string          `json:"collector"`
	Finished  time.Time       `json:"finished"`
	Complete  bool            `json:"complete"`
	Pages     int             `json:"pages"`
	Retries   int             `json:"retries"`
	Records   []CloudRecord   `json:"records"`
	Conflicts []CloudConflict `json:"conflicts,omitempty"`
	Notes     []string        `json:"notes,omitempty"`
}

// ScopeKey names the snapshot boundary used for reconciliation.
func (inv CloudInventory) ScopeKey() string {
	region := inv.Region
	if region == "" {
		region = "global"
	}
	return strings.ToLower(inv.Provider + "/" + inv.Scope + "/" + region)
}

// CloudChange is one reconciliation claim against the previous complete
// snapshot of the same scope key.
type CloudChange struct {
	Change     string     `json:"change"` // reassigned or absent
	Claim      string     `json:"claim"`  // observed or inferred
	Address    netip.Addr `json:"address"`
	ResourceID string     `json:"resource_id"`
	Previous   string     `json:"previous_resource_id,omitempty"`
}

// CloudReconciliation compares a snapshot with the previous complete one.
// Absence is inferred, never treated as deletion: identity evidence stays.
type CloudReconciliation struct {
	ScopeKey     string        `json:"scope_key"`
	PreviousScan string        `json:"previous_scan,omitempty"`
	Status       string        `json:"status"` // baseline, compared, partial_not_compared
	Changes      []CloudChange `json:"changes,omitempty"`
}

// CloudInventorySummary omits per-record rows from command output.
type CloudInventorySummary struct {
	Provider  string          `json:"provider"`
	Scope     string          `json:"scope"`
	Region    string          `json:"region,omitempty"`
	Collector string          `json:"collector"`
	Complete  bool            `json:"complete"`
	Pages     int             `json:"pages"`
	Retries   int             `json:"retries"`
	Records   int             `json:"records"`
	Conflicts []CloudConflict `json:"conflicts,omitempty"`
	Notes     []string        `json:"notes,omitempty"`
}

// CloudImport is the versioned result of one cloud inventory collection.
type CloudImport struct {
	Schema         string                `json:"schema"`
	Scan           observe.Scan          `json:"scan"`
	Inventory      CloudInventorySummary `json:"inventory"`
	Reconciliation CloudReconciliation   `json:"reconciliation"`
	// Authorizes is always false: inventory never widens scan scope.
	Authorizes bool `json:"authorizes_scanning"`
}

// ImportCloudInventory records a provider snapshot as an auditable scan that
// feeds the same scoped-identifier resolver as --import-identifiers.
func (s *Store) ImportCloudInventory(ctx context.Context, inv CloudInventory) (CloudImport, error) {
	kind, ok := cloudProviderKinds[inv.Provider]
	if !ok {
		return CloudImport{}, fmt.Errorf("unsupported cloud provider %q", inv.Provider)
	}
	inv.Scope = strings.ToLower(strings.TrimSpace(inv.Scope))
	inv.Region = strings.ToLower(strings.TrimSpace(inv.Region))
	if !safeExternalToken(inv.Scope, 128) || (inv.Region != "" && !safeExternalToken(inv.Region, 64)) {
		return CloudImport{}, errors.New("invalid cloud scope or region")
	}
	if len(inv.Records) == 0 || len(inv.Records) > 100_000 {
		return CloudImport{}, errors.New("cloud inventory must contain 1 to 100000 addresses")
	}
	result := CloudImport{Schema: CloudInventorySchema, Inventory: CloudInventorySummary{
		Provider: inv.Provider, Scope: inv.Scope, Region: inv.Region, Collector: inv.Collector, Complete: inv.Complete,
		Pages: inv.Pages, Retries: inv.Retries, Records: len(inv.Records), Conflicts: inv.Conflicts, Notes: inv.Notes}}
	current := map[netip.Addr]string{}
	for i, record := range inv.Records {
		if !record.Address.IsValid() || record.Address.IsMulticast() || record.Address.IsUnspecified() {
			return result, fmt.Errorf("record %d: valid unicast address required", i+1)
		}
		if _, ok := externalIdentityValue(kind, inv.Scope, record.ResourceID); !ok {
			return result, fmt.Errorf("record %d: invalid resource ID", i+1)
		}
		if record.AddressRole != "private" && record.AddressRole != "public" {
			return result, fmt.Errorf("record %d: address role must be private or public", i+1)
		}
		id := strings.ToLower(strings.TrimSpace(record.ResourceID))
		if previous, ok := current[record.Address]; ok && previous != id {
			return result, fmt.Errorf("record %d: address %s has conflicting resources", i+1, record.Address)
		}
		current[record.Address] = id
	}
	reconciliation, err := s.reconcileCloudInventory(ctx, inv, current)
	if err != nil {
		return result, err
	}
	result.Reconciliation = reconciliation

	now := time.Now().UTC()
	collected := inv.Finished.UTC()
	if inv.Finished.IsZero() || collected.After(now) {
		collected = now
	}
	scan := observe.Scan{ID: observe.NewScanID(now), Profile: cloudInventoryProbe, Started: now, Status: "running"}
	batch := make([]observe.Observation, 0, len(inv.Records))
	for _, record := range inv.Records {
		o := observe.Observation{Kind: observe.KindHost, Target: record.Address, Timestamp: collected,
			Transport: "inventory", State: "observed", Confidence: 100,
			Reason: "scoped " + inv.Provider + " identifier from provider inventory API", Probe: cloudInventoryProbe,
			Fields: map[string]string{
				"external.kind":        kind,
				"external.scope":       inv.Scope,
				"external.value":       strings.ToLower(strings.TrimSpace(record.ResourceID)),
				"cloud.provider":       inv.Provider,
				"cloud.region":         inv.Region,
				"cloud.location":       boundedField(record.Location),
				"cloud.resource":       boundedField(record.Resource),
				"cloud.owner":          boundedField(record.Owner),
				"cloud.address_role":   record.AddressRole,
				"inventory.schema":     CloudInventorySchema,
				"inventory.scope_key":  inv.ScopeKey(),
				"inventory.collector":  boundedField(inv.Collector),
				"inventory.complete":   strconv.FormatBool(inv.Complete),
				"inventory.claim":      "observed",
				"inventory.authorizes": "false",
			}}
		o.Stamp(scan.ID)
		batch = append(batch, o)
	}
	scan.Targets, scan.Observations = len(current), len(batch)
	if err := s.BeginScan(ctx, scan); err != nil {
		return result, err
	}
	for len(batch) > 0 {
		n := min(len(batch), 256)
		if err := s.AddObservations(ctx, batch[:n]); err != nil {
			scan.Status, scan.Error, scan.Finished = "failed", err.Error(), time.Now().UTC()
			_ = s.FinishScan(ctx, scan)
			result.Scan = scan
			return result, err
		}
		batch = batch[n:]
	}
	scan.Status, scan.Finished = "completed", time.Now().UTC()
	result.Scan = scan
	return result, s.FinishScan(ctx, scan)
}

func boundedField(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 512 {
		return value[:512]
	}
	return value
}

// reconcileCloudInventory compares with the latest complete snapshot of the
// same provider/scope/region. A partial snapshot cannot prove absence, and
// absence never deactivates identity evidence.
func (s *Store) reconcileCloudInventory(ctx context.Context, inv CloudInventory, current map[netip.Addr]string) (CloudReconciliation, error) {
	out := CloudReconciliation{ScopeKey: inv.ScopeKey(), Status: "baseline"}
	if !inv.Complete {
		out.Status = "partial_not_compared"
	}
	var previousScan string
	err := s.db.QueryRowContext(ctx, `SELECT o.scan_id FROM observations o JOIN scans sc ON sc.id = o.scan_id
		WHERE o.probe = ? AND sc.status = 'completed'
		AND json_extract(o.record, '$.fields."inventory.scope_key"') = ?
		AND json_extract(o.record, '$.fields."inventory.complete"') = 'true'
		ORDER BY o.id DESC LIMIT 1`, cloudInventoryProbe, inv.ScopeKey()).Scan(&previousScan)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.PreviousScan = previousScan
	rows, err := s.db.QueryContext(ctx, `SELECT record FROM observations WHERE scan_id = ? AND probe = ?`, previousScan, cloudInventoryProbe)
	if err != nil {
		return out, err
	}
	previous := map[netip.Addr]string{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return out, err
		}
		var o observe.Observation
		if json.Unmarshal([]byte(raw), &o) == nil && o.Target.IsValid() {
			previous[o.Target] = o.Fields["external.value"]
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	present := map[string]bool{}
	for _, id := range current {
		present[id] = true
	}
	for addr, id := range current {
		if before, ok := previous[addr]; ok && before != id {
			out.Changes = append(out.Changes, CloudChange{Change: "reassigned", Claim: "observed", Address: addr, ResourceID: id, Previous: before})
		}
	}
	if inv.Complete {
		out.Status = "compared"
		for addr, id := range previous {
			if _, still := current[addr]; !still && !present[id] {
				out.Changes = append(out.Changes, CloudChange{Change: "absent", Claim: "inferred", Address: addr, ResourceID: id})
			}
		}
	}
	sort.Slice(out.Changes, func(i, j int) bool {
		if out.Changes[i].Change != out.Changes[j].Change {
			return out.Changes[i].Change > out.Changes[j].Change
		}
		return out.Changes[i].Address.Less(out.Changes[j].Address)
	})
	return out, nil
}
