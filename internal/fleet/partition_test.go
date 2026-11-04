package fleet

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/matusso/nyxr/internal/config"
)

func resolved(t *testing.T, targets ...string) config.Config {
	t.Helper()
	r, err := resolveForController(connectRequest(targets...))
	if err != nil {
		t.Fatal(err)
	}
	return r.Config
}

func TestPartitionKeepsSubnetsWhole(t *testing.T) {
	units, err := Partition(resolved(t, "10.0.0.0/23", "10.0.5.7", "10.0.5.9"), 300)
	if err != nil {
		t.Fatal(err)
	}
	// Two whole /24s do not fit in 300, so each /24 is a unit; the two
	// single hosts of 10.0.5.0/24 share the next one.
	want := [][]string{{"10.0.0.0-10.0.0.255"}, {"10.0.1.0-10.0.1.255", "10.0.5.7", "10.0.5.9"}}
	var got [][]string
	for _, u := range units {
		got = append(got, u.Targets)
		if u.SubnetShare != 1 {
			t.Fatalf("unit %+v split a subnet", u)
		}
	}
	if !reflect.DeepEqual(got, want) || units[1].Count != 258 {
		t.Fatalf("units %+v", units)
	}
}

func TestPartitionSplitsOversizedSubnet(t *testing.T) {
	units, err := Partition(resolved(t, "10.0.0.0/24"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(units) != 3 || units[0].Targets[0] != "10.0.0.0-10.0.0.99" || units[2].Targets[0] != "10.0.0.200-10.0.0.255" {
		t.Fatalf("units %+v", units)
	}
	total := 0
	for _, u := range units {
		total += u.Count
		if u.SubnetShare != 3 {
			t.Fatalf("subnet share %d, want 3", u.SubnetShare)
		}
	}
	if total != 256 {
		t.Fatalf("partition covers %d addresses", total)
	}
}

func TestPartitionIPv6AndRoundTrip(t *testing.T) {
	units, err := Partition(resolved(t, "2001:db8::1", "2001:db8::2", "2001:db8:0:1::5", "2001:db8::1"), 256)
	if err != nil {
		t.Fatal(err)
	}
	if len(units) != 1 || units[0].Count != 3 || !reflect.DeepEqual(units[0].Targets, []string{"2001:db8::1-2001:db8::2", "2001:db8:0:1::5"}) {
		t.Fatalf("units %+v", units)
	}
	runs, err := unitRuns(units[0].Targets)
	if err != nil {
		t.Fatal(err)
	}
	if !runsContain(runs, netip.MustParseAddr("2001:db8::2")) || runsContain(runs, netip.MustParseAddr("2001:db8::3")) {
		t.Fatal("unit runs do not round-trip")
	}
}

func TestLeaseRequestDividesBudgets(t *testing.T) {
	p, err := planFromStoredRequest(connectRequest("10.0.0.0/24"), JobOptions{MaxParallel: 4})
	if err != nil {
		t.Fatal(err)
	}
	p.rate, p.subnetRate = 1000, 90
	caps := agentCaps(t, 2, 200)
	req := leaseRequest(*p, []string{"10.0.0.0-10.0.0.99"}, 3, caps)
	// Global 1000/4 = 250, capped by the agent's 200/2 leases = 100.
	if req.Rate == nil || *req.Rate != 100 || req.SubnetRate == nil || *req.SubnetRate != 30 {
		t.Fatalf("rate %v subnet %v", req.Rate, req.SubnetRate)
	}
	if !reflect.DeepEqual(req.Targets, []string{"10.0.0.0-10.0.0.99"}) {
		t.Fatalf("targets %v", req.Targets)
	}
}

func TestRequestsTiedToOneVantageAreRefused(t *testing.T) {
	for _, req := range []config.Request{
		{Targets: []string{"10.0.0.1"}, Ports: "80", Interface: "eth0"},
		{Targets: []string{"10.0.0.1"}, Ports: "80", KnownOpen: true},
		{Targets: []string{"10.0.0.1"}, Ports: "80", SourceIP: "10.0.0.2"},
	} {
		if _, err := resolveForController(req); err == nil {
			t.Fatalf("accepted %+v", req)
		}
	}
}
