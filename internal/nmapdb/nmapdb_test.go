package nmapdb

import (
	"strings"
	"testing"
)

// sample is a small, hand-written database in the nmap-service-probes format.
// It is not copied from Nmap's data file; it only exercises the grammar.
const sample = `# synthetic probes for tests
Exclude T:9100-9107

Probe TCP NULL q||
match ssh m|^SSH-([\d.]+)-OpenSSH[_-]([\w.]+)| p/OpenSSH/ v/$2/ i/protocol $1/ cpe:/a:openbsd:openssh:$2/
match ftp m|^220[- ](\w+) FTP| p/$1/
softmatch smtp m|^220 |
match broken m|^(foo)\1| p/never/
match redis m|^-ERR| p/Redis key-value store/

Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
ports 80,8080,8000-8010
sslports 443
rarity 3
match http m|^HTTP/1\.[01] \d\d\d| p/generic web server/
`

func parseSample(t *testing.T) *Database {
	t.Helper()
	db, err := Parse(strings.NewReader(sample), "sample")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return db
}

func TestParseProvenanceAndStats(t *testing.T) {
	db := parseSample(t)
	if db.Source != "sample" {
		t.Errorf("Source = %q", db.Source)
	}
	if len(db.SHA256) != 64 {
		t.Errorf("SHA256 = %q, want 64 hex chars", db.SHA256)
	}
	if len(db.Probes) != 2 {
		t.Fatalf("probes = %d, want 2", len(db.Probes))
	}
	// Six match/softmatch lines total across both probes.
	if db.TotalMatch != 6 {
		t.Errorf("TotalMatch = %d, want 6", db.TotalMatch)
	}
	if db.SoftMatch != 1 {
		t.Errorf("SoftMatch = %d, want 1", db.SoftMatch)
	}
	// The "broken" rule uses a backreference RE2 cannot compile.
	if db.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", db.Skipped)
	}
	if db.Usable != 5 {
		t.Errorf("Usable = %d, want 5", db.Usable)
	}
	if len(db.Exclude) != 1 || db.Exclude[0].Lo != 9100 || db.Exclude[0].Hi != 9107 || !db.Exclude[0].UDP == false {
		t.Errorf("Exclude = %+v", db.Exclude)
	}
}

func TestProbeMetadata(t *testing.T) {
	db := parseSample(t)
	get := db.Probes[1]
	if get.Name != "GetRequest" || get.Proto != "TCP" {
		t.Fatalf("probe = %+v", get)
	}
	if string(get.Payload) != "GET / HTTP/1.0\r\n\r\n" {
		t.Errorf("payload = %q", get.Payload)
	}
	if get.Rarity != 3 {
		t.Errorf("rarity = %d", get.Rarity)
	}
	if len(get.Ports) != 3 || !get.Ports[2].Contains(8005) || !get.Ports[0].Contains(80) {
		t.Errorf("ports = %+v", get.Ports)
	}
	if len(get.SSLPorts) != 1 || !get.SSLPorts[0].Contains(443) {
		t.Errorf("sslports = %+v", get.SSLPorts)
	}
}

func TestMatchBannerHardWins(t *testing.T) {
	db := parseSample(t)
	// The SSH banner should hard-match before the smtp softmatch is considered.
	res, ok := db.MatchBanner([]byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n"))
	if !ok {
		t.Fatal("expected a match")
	}
	if res.Service != "ssh" || res.Soft {
		t.Fatalf("result = %+v", res)
	}
	if res.Product != "OpenSSH" {
		t.Errorf("product = %q", res.Product)
	}
	if res.Version != "9.6p1" {
		t.Errorf("version = %q", res.Version)
	}
	if res.Info != "protocol 2.0" {
		t.Errorf("info = %q", res.Info)
	}
	if len(res.CPE) != 1 || res.CPE[0] != "cpe:/a:openbsd:openssh:9.6p1" {
		t.Errorf("cpe = %v", res.CPE)
	}
	if res.Probe != "NULL" {
		t.Errorf("probe = %q", res.Probe)
	}
}

func TestMatchBannerCaptureIntoProduct(t *testing.T) {
	db := parseSample(t)
	res, ok := db.MatchBanner([]byte("220 ProFTPD FTP server ready\r\n"))
	if !ok || res.Service != "ftp" {
		t.Fatalf("result = %+v ok=%v", res, ok)
	}
	if res.Product != "ProFTPD" {
		t.Errorf("product = %q, want ProFTPD", res.Product)
	}
}

func TestMatchBannerSoftFallback(t *testing.T) {
	db := parseSample(t)
	// "220 " with no FTP token: the ftp hard match needs "\w+ FTP" and fails,
	// so the smtp softmatch is returned.
	res, ok := db.MatchBanner([]byte("220 mail.example.com ESMTP\r\n"))
	if !ok {
		t.Fatal("expected a softmatch")
	}
	if res.Service != "smtp" || !res.Soft {
		t.Fatalf("result = %+v", res)
	}
}

func TestMatchBannerNoMatch(t *testing.T) {
	db := parseSample(t)
	if _, ok := db.MatchBanner([]byte("random noise")); ok {
		t.Fatal("did not expect a match")
	}
	if _, ok := db.MatchBanner(nil); ok {
		t.Fatal("empty banner should not match")
	}
}

func TestParseRejectsNonDatabase(t *testing.T) {
	if _, err := Parse(strings.NewReader("just some text\nwith no probes\n"), "x"); err == nil {
		t.Fatal("expected an error for a file with no Probe directives")
	}
}

func TestNilDatabaseSafe(t *testing.T) {
	var db *Database
	if _, ok := db.MatchBanner([]byte("SSH-2.0-x")); ok {
		t.Fatal("nil database should not match")
	}
	if db.NullRules() != 0 {
		t.Fatal("nil database has no rules")
	}
}

func TestTemplateHelpers(t *testing.T) {
	sub := [][]byte{[]byte("whole"), []byte("1-2-3"), []byte{0x01, 0x00}}
	cases := []struct {
		tmpl string
		want string
	}{
		{"$1", "1-2-3"},
		{"v$1x", "v1-2-3x"},
		{"$SUBST(1,\"-\",\".\")", "1.2.3"},
		{"$P(1)", "1-2-3"},
		{"$I(2,\">\")", "256"},
		{"$I(2,\"<\")", "1"},
		{"a$$b", "a$b"},
		{"$9", ""},
	}
	for _, c := range cases {
		if got := applyTemplate(c.tmpl, sub); got != c.want {
			t.Errorf("applyTemplate(%q) = %q, want %q", c.tmpl, got, c.want)
		}
	}
}
