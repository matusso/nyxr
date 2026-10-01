package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequestJSONAndYAMLShareFieldNames(t *testing.T) {
	yamlDoc := "targets: [127.0.0.1]\nports: \"22,80\"\nprotocols: tcp\nservice: true\nservice_probes: banner\nfingerprint: true\n"
	path := filepath.Join(t.TempDir(), "scan.yaml")
	if err := os.WriteFile(path, []byte(yamlDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	fromYAML, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON Request
	d := json.NewDecoder(strings.NewReader(`{"targets":["127.0.0.1"],"ports":"22,80","protocols":"tcp","service":true,"service_probes":"banner","fingerprint":true}`))
	d.DisallowUnknownFields()
	if err := d.Decode(&fromJSON); err != nil {
		t.Fatal(err)
	}
	a, err := fromYAML.Resolve(ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := fromJSON.Resolve(ResolveOptions{Remote: true})
	if err != nil {
		t.Fatal(err)
	}
	pa, _ := json.Marshal(a.Plan())
	pb, _ := json.Marshal(b.Plan())
	if string(pa) != string(pb) {
		t.Fatalf("YAML and JSON plans differ:\n%s\n%s", pa, pb)
	}
	if !b.Service.Enabled || !b.Fingerprint || !b.UsesPipeline() {
		t.Fatalf("stages not resolved: %+v", b)
	}
}

func TestRemoteRequestCannotNameServerFiles(t *testing.T) {
	base := Request{Targets: []string{"127.0.0.1"}, Protocols: "udp", Ports: "53"}
	for name, mutate := range map[string]func(*Request){
		"probe file":   func(r *Request) { r.UDPProbeFile = "/etc/passwd" },
		"payload file": func(r *Request) { r.PayloadFile = "/etc/shadow" },
		"UDP probe DB": func(r *Request) { r.NmapUDPProbes = "/etc/nmap-service-probes" },
		"pcapng path":  func(r *Request) { r.PCAPNG = "../../tmp/x.pcapng" },
		"pcapng abs":   func(r *Request) { r.PCAPNG = "/tmp/x.pcapng" },
		"pcapng dot":   func(r *Request) { r.PCAPNG = ".x.pcapng" },
		"pcapng ext":   func(r *Request) { r.PCAPNG = "x.txt" },
		"pcapng win":   func(r *Request) { r.PCAPNG = `..\x.pcapng` },
	} {
		r := base
		mutate(&r)
		if _, err := r.Resolve(ResolveOptions{Remote: true}); err == nil {
			t.Errorf("%s: remote request accepted", name)
		}
	}
	r := base
	r.PCAPNG = "evidence.pcapng"
	res, err := r.Resolve(ResolveOptions{Remote: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.PCAPNG != "evidence.pcapng" || res.PCAPNGMaxBytes != DefaultPCAPNGMaxMB<<20 {
		t.Fatalf("capture = %q %d", res.PCAPNG, res.PCAPNGMaxBytes)
	}
}

func TestRequestRejectsNegativeAndOrphanValues(t *testing.T) {
	neg := -1
	r := Request{Targets: []string{"127.0.0.1"}, Ports: "80", Protocols: "tcp", Workers: &neg}
	if _, err := r.Resolve(ResolveOptions{}); err == nil {
		t.Fatal("negative workers accepted")
	}
	mb := 5
	r = Request{Targets: []string{"127.0.0.1"}, Ports: "80", Protocols: "tcp", PCAPNGMaxMB: &mb}
	if _, err := r.Resolve(ResolveOptions{}); err == nil {
		t.Fatal("pcapng_max_mb without pcapng accepted")
	}
}

func TestOTSafeRequestEnablesFingerprinting(t *testing.T) {
	r := Request{Targets: []string{"10.0.0.5"}, AllowTargets: []string{"10.0.0.0/24"}, Profile: "ot-safe"}
	res, err := r.Resolve(ResolveOptions{Remote: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Fingerprint || !res.Service.Enabled {
		t.Fatalf("ot-safe stages = %+v", res)
	}
}
