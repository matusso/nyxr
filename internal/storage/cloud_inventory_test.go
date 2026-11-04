package storage

import (
	"net/netip"
	"testing"
)

func cloudRecord(addr, id, role string) CloudRecord {
	return CloudRecord{Address: netip.MustParseAddr(addr), ResourceID: id, AddressRole: role,
		Resource: "arn:aws:ec2:eu-central-1:111122223333:instance/" + id, Location: "eu-central-1a", Owner: "111122223333"}
}

func TestCloudInventoryFeedsResolverAndReconcilesConservatively(t *testing.T) {
	s, _ := openTest(t)
	base := CloudInventory{Provider: "aws", Scope: "111122223333", Region: "eu-central-1", Collector: "test", Complete: true, Pages: 1}

	first := base
	first.Records = []CloudRecord{
		cloudRecord("10.0.0.10", "i-aaa", "private"),
		cloudRecord("198.51.100.10", "i-aaa", "public"),
		cloudRecord("10.0.0.20", "i-bbb", "private"),
		cloudRecord("10.0.0.30", "i-ccc", "private"),
	}
	result, err := s.ImportCloudInventory(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if result.Schema != CloudInventorySchema || result.Reconciliation.Status != "baseline" || result.Authorizes ||
		result.Scan.Profile != "cloud-inventory" || result.Scan.Observations != 4 {
		t.Fatalf("first import: %+v", result)
	}
	graph, err := s.IdentityGraph(ctx)
	if err != nil || len(graph) != 3 {
		t.Fatalf("graph: %d identities, %v", len(graph), err)
	}
	joined := false
	for _, asset := range graph {
		if len(asset.Addresses) == 2 && len(asset.PortableIDs) == 1 {
			joined = true
		}
	}
	if !joined {
		t.Fatalf("private and public address of one instance were not joined: %+v", graph)
	}

	// A partial snapshot cannot prove absence and is not a comparison base.
	partial := base
	partial.Complete = false
	partial.Records = []CloudRecord{cloudRecord("10.0.0.10", "i-aaa", "private")}
	result, err = s.ImportCloudInventory(ctx, partial)
	if err != nil {
		t.Fatal(err)
	}
	if result.Reconciliation.Status != "partial_not_compared" || len(result.Reconciliation.Changes) != 0 {
		t.Fatalf("partial reconciliation: %+v", result.Reconciliation)
	}

	second := base
	second.Records = []CloudRecord{
		cloudRecord("10.0.0.10", "i-aaa", "private"),
		cloudRecord("198.51.100.10", "i-aaa", "public"),
		cloudRecord("10.0.0.20", "i-ddd", "private"), // address reassigned to a new instance
	}
	result, err = s.ImportCloudInventory(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	r := result.Reconciliation
	if r.Status != "compared" || r.PreviousScan == "" || len(r.Changes) != 2 {
		t.Fatalf("reconciliation: %+v", r)
	}
	if c := r.Changes[0]; c.Change != "reassigned" || c.Claim != "observed" || c.ResourceID != "i-ddd" || c.Previous != "i-bbb" {
		t.Fatalf("reassignment: %+v", c)
	}
	if c := r.Changes[1]; c.Change != "absent" || c.Claim != "inferred" || c.ResourceID != "i-ccc" {
		t.Fatalf("absence: %+v", c)
	}
	// Absence never deletes evidence: the absent address keeps its identity.
	graph, err = s.IdentityGraph(ctx)
	if err != nil {
		t.Fatal(err)
	}
	kept := false
	for _, asset := range graph {
		for _, addr := range asset.Addresses {
			if addr.Address == netip.MustParseAddr("10.0.0.30") && len(asset.PortableIDs) == 1 {
				kept = true
			}
		}
	}
	if !kept {
		t.Fatal("absent resource lost its identity evidence")
	}
	// The reassigned address separated from the old instance's identity.
	events, err := s.IdentityHistory(ctx, netip.MustParseAddr("10.0.0.20"))
	if err != nil {
		t.Fatal(err)
	}
	separated := false
	for _, event := range events {
		if event.Cause == "signal_changed:cloud.aws.instance_id" {
			separated = true
		}
	}
	if !separated {
		t.Fatalf("reassigned address kept its old identity: %+v", events)
	}
}

func TestCloudInventoryRejectsInvalidScopeAndConflicts(t *testing.T) {
	s, _ := openTest(t)
	bad := CloudInventory{Provider: "aws", Scope: "Bad Scope!", Complete: true, Records: []CloudRecord{cloudRecord("10.0.0.1", "i-a", "private")}}
	if _, err := s.ImportCloudInventory(ctx, bad); err == nil {
		t.Fatal("invalid scope accepted")
	}
	conflict := CloudInventory{Provider: "gcp", Scope: "nyxr-lab-01", Complete: true, Records: []CloudRecord{
		cloudRecord("10.0.0.1", "1", "private"), cloudRecord("10.0.0.1", "2", "private")}}
	if _, err := s.ImportCloudInventory(ctx, conflict); err == nil {
		t.Fatal("conflicting address accepted")
	}
	unknown := CloudInventory{Provider: "oracle", Scope: "x", Records: []CloudRecord{cloudRecord("10.0.0.1", "1", "private")}}
	if _, err := s.ImportCloudInventory(ctx, unknown); err == nil {
		t.Fatal("unknown provider accepted")
	}
}
