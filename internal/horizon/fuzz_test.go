package horizon

import (
	"bytes"
	"testing"
	"time"
)

// Hostile serialization: every decoder that accepts operator- or
// network-supplied files must fail cleanly, never panic or accept garbage.

func FuzzLoadProfile(f *testing.F) {
	f.Add([]byte(`{"apiVersion":"horizon.nyxr.io/profile/v1","kind":"BehaviorProfile","id":"x"}`))
	f.Add([]byte(`{"evidenceFrom":"9999-12-31T23:59:59Z","validUntil":"0001-01-01T00:00:00Z"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := LoadProfile(bytes.NewReader(b))
		if err != nil {
			return
		}
		if p.ID != profileID(p) || !validWindow(p) {
			t.Fatal("LoadProfile accepted an inconsistent profile")
		}
		// A loaded profile is still checked against evidence; none here.
		if c := CheckProfile(p, nil, nil, time.Now()); c.Valid {
			t.Fatal("profile valid without evidence")
		}
	})
}

func FuzzLoadGraph(f *testing.F) {
	f.Add([]byte(`{"apiVersion":"horizon.nyxr.io/graph/v1","kind":"EvidenceGraph","hypotheses":[{"id":"HYP-1","support":["run:x"]}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		g, err := LoadGraph(bytes.NewReader(b))
		if err == nil && ValidateGraph(g) != nil {
			t.Fatal("LoadGraph accepted an invalid graph")
		}
		if err == nil {
			for _, h := range g.Hypotheses {
				_, _ = ExplainHypothesis(g, h.ID)
			}
		}
	})
}

func FuzzVerifyAudit(f *testing.F) {
	f.Add([]byte(`{"version":"horizon.nyxr.io/audit/v1","seq":1,"prev":"","hash":"x"}` + "\n"))
	f.Add(bytes.Repeat([]byte("{}\n"), 3))
	f.Fuzz(func(t *testing.T, b []byte) {
		n, err := VerifyAudit(bytes.NewReader(b))
		if err == nil && n > 0 && len(bytes.TrimSpace(b)) == 0 {
			t.Fatal("entries counted in an empty audit")
		}
	})
}

func FuzzCanonicalChangeScope(f *testing.F) {
	for _, s := range []string{"network", "host:192.0.2.1", "host:2001:DB8::1", "host:fe80::1%eth0", "hosts:1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, err := CanonicalChangeScope(s)
		if err != nil {
			return
		}
		if again, err := CanonicalChangeScope(c); err != nil || again != c {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, c, again)
		}
	})
}
