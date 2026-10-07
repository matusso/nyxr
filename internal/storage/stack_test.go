package storage

import (
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

func TestStackPersistenceProfileAndNoIdentityMerge(t *testing.T) {
	s, _ := openTest(t)
	a := observe.Observation{Kind: observe.KindPort, Target: host, Timestamp: t0, Transport: "tcp", Port: 443, State: "open", Confidence: 100, Probe: "tcp-syn",
		TCPStack: &observe.TCPStack{Status: observe.FingerprintMatched, Signature: "nx_tcp_v1_test", Candidates: []observe.StackCandidate{{Family: "Linux", Confidence: 70}},
			Samples: []observe.StackSample{{Received: t0, TTL: 61, InitialTTL: 64}}}}
	b := a
	b.Target = host.Next()
	storeScan(t, s, "stack", t0, a, b)
	rows, err := s.Observations(ctx, Filter{ScanID: "stack"})
	if err != nil || len(rows) != 2 || rows[0].TCPStack == nil || rows[0].TCPStack.Signature != a.TCPStack.Signature || len(rows[0].TCPStack.Samples) != 1 {
		t.Fatalf("stack round trip: %+v %v", rows, err)
	}
	graph, err := s.IdentityGraph(ctx)
	if err != nil || len(graph) != 2 {
		t.Fatalf("TCP signature merged addresses: %+v %v", graph, err)
	}
	for _, asset := range graph {
		if asset.Profile.OS != "Linux" || len(asset.Profile.Claims) != 1 || asset.Profile.Claims[0].Kind != "os_family" || asset.Profile.Claims[0].Confidence != 70 {
			t.Fatalf("stack confidence overwritten by port state: %+v", asset)
		}
	}
	a.Port = 80
	a.Timestamp = t0.Add(time.Second)
	a.TCPStack = &observe.TCPStack{Status: observe.FingerprintMatched, Candidates: []observe.StackCandidate{{Family: "Windows", Confidence: 65}}}
	storeScan(t, s, "stack-conflict", a.Timestamp, a)
	graph, err = s.IdentityGraph(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, asset := range graph {
		if asset.Addresses[0].Address == host && (asset.Profile.OS != "" || len(asset.Profile.Claims) != 2) {
			t.Fatalf("conflicting families hidden: %+v", asset)
		}
	}
}
