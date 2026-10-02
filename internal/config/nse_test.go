package config

import (
	"strings"
	"testing"
	"time"
)

func TestNSERequestAndSafety(t *testing.T) {
	r := Request{Targets: []string{"127.0.0.1"}, Ports: "80", Protocols: "tcp",
		NSEScripts: "http-title,ssl-cert,http-title", NSETimeout: "12s"}
	resolved, err := r.Resolve(ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.UsesPipeline() || len(resolved.NSE.Scripts) != 2 || resolved.NSE.Timeout != 12*time.Second || resolved.Plan().NSE.Safety != "safe" {
		t.Fatalf("NSE was not resolved into the plan: %+v", resolved.Plan())
	}
	if _, err := r.Resolve(ResolveOptions{Remote: true}); err == nil {
		t.Fatal("remote request accepted NSE execution")
	}
	for _, names := range []string{"safe", "all", "http-*", "http-title or exploit", "../evil", "http-title,,ssl-cert"} {
		r.NSEScripts = names
		if _, err := r.Resolve(ResolveOptions{}); err == nil {
			t.Errorf("accepted unsafe selection %q", names)
		}
	}
	r.NSEScripts = "http-title"
	r.Profile = "ot-safe"
	r.AllowTargets = []string{"127.0.0.1"}
	if _, err := r.Resolve(ResolveOptions{}); err == nil || !strings.Contains(err.Error(), "NSE") {
		t.Fatalf("ot-safe accepted NSE: %v", err)
	}
}
