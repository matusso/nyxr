package storage

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/observe"
)

func at(o observe.Observation, addr string) observe.Observation {
	o.Target = netip.MustParseAddr(addr)
	return o
}

func plainService(when time.Time, port uint16, service, version string, attrs map[string]string) observe.Observation {
	return observe.Observation{Kind: observe.KindService, Timestamp: when, Target: host, Transport: "tcp", Port: port,
		State: "open", Service: service, Version: version, Fingerprint: observe.FingerprintMatched, Confidence: 100, Attributes: attrs}
}

func TestDiffScansIsCoverageAware(t *testing.T) {
	s, _ := openTest(t)
	t1 := t0.Add(time.Hour)
	storeScan(t, s, "before", t0,
		identityObs(host, t0, "02:00:00:00:00:05"),
		portObs(t0, 22, "open"), plainService(t0, 22, "ssh", "8.9", map[string]string{"ssh.host_key_sha256": "k1"}),
		portObs(t0, 80, "open"), plainService(t0, 80, "http", "", map[string]string{"http.title": "Old"}),
		portObs(t0, 443, "open"), serviceObs(t0, 443, "https", "nginx"), // truncated evidence
		portObs(t0, 8080, "open"), portObs(t0, 9000, "open"), portObs(t0, 23, "closed"),
		at(identityObs(host, t0, "02:00:00:00:00:07"), "192.0.2.7"), at(portObs(t0, 22, "open"), "192.0.2.7"),
		at(identityObs(host, t0, "02:00:00:00:00:08"), "192.0.2.8"), at(portObs(t0, 502, "open"), "192.0.2.8"),
		at(plainService(t0, 502, "modbus", "", nil), "192.0.2.8"),
	)
	cert := serviceObs(t1, 443, "https", "nginx")
	cert.TLS.Certificates[0].SHA256 = "cd"
	storeScan(t, s, "after", t1,
		identityObs(host, t1, "02:00:00:00:00:05"),
		portObs(t1, 22, "open"), plainService(t1, 22, "ssh", "9.6", map[string]string{"ssh.host_key_sha256": "k2"}),
		portObs(t1, 80, "closed"),
		portObs(t1, 443, "open"), cert,
		portObs(t1, 8080, "filtered"), portObs(t1, 23, "open"),
		// 192.0.2.7 is out of scope; 192.0.2.8's device now answers on .9.
		at(identityObs(host, t1, "02:00:00:00:00:08"), "192.0.2.9"), at(portObs(t1, 502, "open"), "192.0.2.9"),
		at(plainService(t1, 502, "modbus", "", nil), "192.0.2.9"),
		at(identityObs(host, t1, "02:00:00:00:00:10"), "192.0.2.10"), at(portObs(t1, 22, "open"), "192.0.2.10"),
	)
	diff, ok, err := s.DiffScans(ctx, "before", "after")
	if err != nil || !ok || diff.Version != DiffVersion {
		t.Fatalf("diff: %+v, %v, %v", diff, ok, err)
	}
	find := func(kind, addr string, port uint16) DiffChange {
		t.Helper()
		for _, c := range diff.Changes {
			if c.Kind == kind && c.Address.String() == addr && c.Port == port {
				return c
			}
		}
		t.Fatalf("no %s change for %s:%d in %+v", kind, addr, port, diff.Changes)
		return DiffChange{}
	}
	for _, tc := range []struct {
		kind, addr            string
		port                  uint16
		change, status, why   string
		wantBefore, wantAfter string
	}{
		{"service", "192.0.2.5", 22, "changed", DiffObserved, "", "ssh 8.9", "ssh 9.6"},
		{"ssh_host_key", "192.0.2.5", 22, "changed", DiffObserved, "", "k1", "k2"},
		{"service", "192.0.2.5", 80, "removed", DiffObserved, "", "open http", "closed"},
		{"service", "192.0.2.5", 23, "added", DiffObserved, "", "closed", "open"},
		{"tls_certificate", "192.0.2.5", 443, "changed", DiffUnverified, "truncated_evidence", "ab CN=x", "cd CN=x"},
		{"service", "192.0.2.5", 8080, "not_observed", DiffUnverified, "silent", "open", "filtered"},
		{"service", "192.0.2.5", 9000, "not_observed", DiffUnverified, "not_tested", "open", ""},
		{"asset_presence", "192.0.2.7", 0, "not_observed", DiffUnverified, "not_tested", "", ""},
		{"address_membership", "192.0.2.8", 0, "changed", DiffObserved, "", "192.0.2.8", "192.0.2.9"},
		{"asset_presence", "192.0.2.10", 0, "added", DiffUnverified, "not_tested", "", ""},
		{"service", "192.0.2.10", 22, "added", DiffUnverified, "not_tested", "", "open"},
	} {
		c := find(tc.kind, tc.addr, tc.port)
		if c.Change != tc.change || c.Status != tc.status || c.Reason != tc.why || c.Before != tc.wantBefore || c.After != tc.wantAfter {
			t.Errorf("%s %s:%d = %+v", tc.kind, tc.addr, tc.port, c)
		}
	}
	if c := find("service", "192.0.2.5", 80); c.BeforeObservation == "" || c.AfterObservation == "" || c.Asset == "" {
		t.Errorf("evidence references missing: %+v", c)
	}
	// The moved asset keeps its service: no change is reported on either address.
	for _, c := range diff.Changes {
		if c.Port == 502 || (c.Kind == "asset_presence" && (c.Address.String() == "192.0.2.8" || c.Address.String() == "192.0.2.9")) {
			t.Errorf("move reported as exposure change: %+v", c)
		}
	}
	again, _, _ := s.DiffScans(ctx, "before", "after")
	x, _ := json.Marshal(diff)
	y, _ := json.Marshal(again)
	if string(x) != string(y) {
		t.Error("diff output is not deterministic")
	}

	// A failed scan proves nothing about what it did not reach.
	t2 := t1.Add(time.Hour)
	storeScan(t, s, "failed", t2, identityObs(host, t2, "02:00:00:00:00:05"))
	if err := s.FinishScan(ctx, observe.Scan{ID: "failed", Status: "failed", Finished: t2.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	diff, _, err = s.DiffScans(ctx, "after", "failed")
	if c := find("service", "192.0.2.5", 22); err != nil || c.Change != "not_observed" || c.Reason != "scan_incomplete" || len(diff.Limitations) == 0 {
		t.Errorf("failed scan: %+v, %v, %v", c, diff.Limitations, err)
	}
	if _, ok, _ := s.DiffScans(ctx, "after", "missing"); ok {
		t.Error("unknown scan accepted")
	}
	if _, _, err := s.DiffScans(ctx, "after", "before"); err == nil {
		t.Error("reversed scans accepted")
	}
}

func TestDiffScansSeparatesReassignmentFromExposure(t *testing.T) {
	s, _ := openTest(t)
	t1 := t0.Add(time.Hour)
	storeScan(t, s, "before", t0, identityObs(host, t0, "02:00:00:00:00:05"), portObs(t0, 22, "open"))
	storeScan(t, s, "after", t1, identityObs(host, t1, "02:00:00:00:00:99"), portObs(t1, 22, "open"))
	diff, _, err := s.DiffScans(ctx, "before", "after")
	if err != nil || len(diff.Changes) != 1 {
		t.Fatalf("diff: %+v, %v", diff.Changes, err)
	}
	if c := diff.Changes[0]; c.Kind != "address_reassignment" || c.Reason != "signal_changed:mac" || c.Before == c.After {
		t.Fatalf("reassignment: %+v", c)
	}
}

// A stored scope turns "no result" into silence for planned endpoints and
// keeps it "not tested" for everything outside the plan.
func TestDiffScansUsesStoredScope(t *testing.T) {
	s, _ := openTest(t)
	t1 := t0.Add(time.Hour)
	store := func(id string, started time.Time, ports string, obs ...observe.Observation) {
		t.Helper()
		scan := observe.Scan{ID: id, Name: "office-lan", Profile: "tcp-syn", Started: started, Status: "running",
			Scope: &observe.ScanScope{Targets: []string{"192.0.2.5-192.0.2.7"}, Ports: map[string]string{"tcp": ports}}}
		if err := s.BeginScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
		for i := range obs {
			obs[i].Stamp(id)
		}
		if err := s.AddObservations(ctx, obs); err != nil {
			t.Fatal(err)
		}
		scan.Status, scan.Finished = "completed", started.Add(time.Minute)
		if err := s.FinishScan(ctx, scan); err != nil {
			t.Fatal(err)
		}
	}
	// A SYN-style scan stores only what answered.
	store("before", t0, "22,80,443", portObs(t0, 22, "open"), portObs(t0, 80, "open"), portObs(t0, 443, "open"),
		at(portObs(t0, 22, "open"), "192.0.2.6"))
	store("after", t1, "22,80-81", portObs(t1, 22, "open"), at(portObs(t1, 22, "open"), "192.0.2.7"))
	diff, _, err := s.DiffScans(ctx, "before", "after")
	if err != nil || diff.Before.Name != "office-lan" || diff.Before.Scope == nil {
		t.Fatalf("diff: %+v, %v", diff.Before, err)
	}
	want := map[string]string{ // address/port -> change status reason
		"192.0.2.5/80":  "not_observed unverified silent",     // planned, no answer
		"192.0.2.5/443": "not_observed unverified not_tested", // outside the after plan
		"192.0.2.6/0":   "not_observed unverified silent",
		"192.0.2.7/0":   "added observed ", // before planned it and heard nothing
		"192.0.2.7/22":  "added observed ",
	}
	for _, c := range diff.Changes {
		key := fmt.Sprintf("%s/%d", c.Address, c.Port)
		if got := c.Change + " " + c.Status + " " + c.Reason; got != want[key] {
			t.Errorf("%s = %q, want %q", key, got, want[key])
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Errorf("missing changes: %v", want)
	}
	// The name identifies the network: its last two scans are the diff.
	named, ok, err := s.DiffNetwork(ctx, "office-lan")
	if err != nil || !ok || named.Before.ID != "before" || named.After.ID != "after" || len(named.Changes) != len(diff.Changes) || len(named.Limitations) != 0 {
		t.Errorf("network diff: %+v, %v, %v", named, ok, err)
	}
	if _, ok, err := s.DiffNetwork(ctx, "no-such-lan"); ok || err != nil {
		t.Errorf("unknown network: %v, %v", ok, err)
	}
	storeScan(t, s, "single", t1.Add(time.Hour))
	if single, _, _ := s.Scan(ctx, "single"); single.Name == "" {
		t.Error("unnamed scan was not given a name")
	} else if _, _, err := s.DiffNetwork(ctx, single.Name); err == nil {
		t.Error("one scan of a network produced a diff")
	}
	if list, _ := s.Scans(ctx, 10); len(list) != 3 || list[1].Scope != nil || list[1].Name != "office-lan" {
		t.Errorf("listing: %+v", list)
	}
}
