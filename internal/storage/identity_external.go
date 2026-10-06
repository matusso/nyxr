package storage

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

func portableIdentityID(signal identityValue) string {
	digest := sha256.Sum256([]byte(signal.kind + "\x00" + signal.value))
	return fmt.Sprintf("urn:nyxr:external:%x", digest)
}

// ExternalIdentifier is an operator-supplied, scoped inventory claim. Scope
// must identify the owning account, subscription, project, or cluster.
type ExternalIdentifier struct {
	Address netip.Addr `json:"address"`
	Kind    string     `json:"kind"`
	Scope   string     `json:"scope"`
	Value   string     `json:"value"`
}

var externalKinds = map[string]bool{
	"kubernetes.node_uid":   true,
	"cloud.aws.instance_id": true,
	"cloud.azure.vm_id":     true,
	"cloud.gcp.instance_id": true,
}

func externalIdentityValue(kind, scope, value string) (identityValue, bool) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	scope = strings.ToLower(strings.TrimSpace(scope))
	value = strings.ToLower(strings.TrimSpace(value))
	if !externalKinds[kind] || !safeExternalToken(scope, 128) || !safeExternalToken(value, 256) {
		return identityValue{}, false
	}
	encoded, _ := json.Marshal([]string{scope, value})
	return identityValue{kind, string(encoded)}, true
}

func safeExternalToken(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for _, c := range value {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' && c != ':' && c != '/' {
			return false
		}
	}
	return true
}

// ImportExternalIdentifiers creates an auditable inventory scan. The caller
// supplies and verifies the scope; nyxr never contacts cloud metadata APIs.
func (s *Store) ImportExternalIdentifiers(ctx context.Context, ids []ExternalIdentifier) (observe.Scan, error) {
	return s.importExternalIdentifiers(ctx, ids, "inventory-import")
}

// ImportKubernetesNodes records node UIDs fetched from a Kubernetes API.
func (s *Store) ImportKubernetesNodes(ctx context.Context, ids []ExternalIdentifier) (observe.Scan, error) {
	for _, id := range ids {
		if id.Kind != "kubernetes.node_uid" {
			return observe.Scan{}, errors.New("Kubernetes import requires node UIDs")
		}
	}
	return s.importExternalIdentifiers(ctx, ids, "kubernetes-api")
}

func (s *Store) importExternalIdentifiers(ctx context.Context, ids []ExternalIdentifier, source string) (observe.Scan, error) {
	if len(ids) == 0 || len(ids) > 100_000 {
		return observe.Scan{}, errors.New("provide 1 to 100000 identifiers")
	}
	now := time.Now().UTC()
	scan := observe.Scan{ID: observe.NewScanID(now), Profile: source, Started: now, Status: "running"}
	addresses := map[netip.Addr]bool{}
	batch := make([]observe.Observation, 0, len(ids))
	for i, item := range ids {
		if !item.Address.IsValid() || item.Address.IsMulticast() || item.Address.IsUnspecified() {
			return observe.Scan{}, fmt.Errorf("identifier %d: valid unicast address required", i+1)
		}
		v, ok := externalIdentityValue(item.Kind, item.Scope, item.Value)
		if !ok {
			return observe.Scan{}, fmt.Errorf("identifier %d: invalid kind, scope, or value", i+1)
		}
		o := observe.Observation{Kind: observe.KindHost, Target: item.Address, Timestamp: now,
			Transport: "inventory", State: "observed", Confidence: 100,
			Reason: "scoped inventory identifier from " + source, Probe: source,
			Fields: map[string]string{"external.kind": v.kind, "external.scope": strings.ToLower(strings.TrimSpace(item.Scope)),
				"external.value": strings.ToLower(strings.TrimSpace(item.Value))}}
		o.Stamp(scan.ID)
		batch = append(batch, o)
		addresses[item.Address] = true
	}
	scan.Targets, scan.Observations = len(addresses), len(batch)
	if err := s.BeginScan(ctx, scan); err != nil {
		return scan, err
	}
	for len(batch) > 0 {
		n := min(len(batch), 256)
		if err := s.AddObservations(ctx, batch[:n]); err != nil {
			scan.Status, scan.Error, scan.Finished = "failed", err.Error(), time.Now().UTC()
			_ = s.FinishScan(ctx, scan)
			return scan, err
		}
		batch = batch[n:]
	}
	scan.Status, scan.Finished = "completed", time.Now().UTC()
	return scan, s.FinishScan(ctx, scan)
}
