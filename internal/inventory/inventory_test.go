package inventory

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matusso/nyxr/internal/storage"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func noSleep(context.Context, time.Duration) error { return nil }

func recordsByAddress(inv storage.CloudInventory) map[string]storage.CloudRecord {
	out := map[string]storage.CloudRecord{}
	for _, r := range inv.Records {
		out[r.Address.String()] = r
	}
	return out
}

// The AWS documentation's Signature Version 4 example (IAM ListUsers).
func TestSignAWSMatchesPublishedExample(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	when := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	signAWS(req, nil, AWSCredentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}, "us-east-1", "iam", when)
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("signature\n got %s\nwant %s", got, want)
	}
}

type awsServer struct {
	mu         sync.Mutex
	ec2Calls   int
	failPage2  bool
	stsAccount string
}

func (s *awsServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIATEST/") ||
			r.Header.Get("X-Amz-Security-Token") != "session-token" {
			t.Errorf("unsigned request: %q", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusForbidden)
			return
		}
		form := string(body)
		switch {
		case strings.Contains(form, "Action=GetCallerIdentity"):
			io.WriteString(w, strings.Replace(fixture(t, "aws_sts.xml"), "<Account>111122223333", "<Account>"+s.stsAccount, 1))
		case strings.Contains(form, "Action=DescribeInstances"):
			s.mu.Lock()
			s.ec2Calls++
			call := s.ec2Calls
			s.mu.Unlock()
			switch {
			case call == 1:
				w.WriteHeader(http.StatusBadRequest)
				io.WriteString(w, fixture(t, "aws_throttle.xml"))
			case !strings.Contains(form, "NextToken"):
				io.WriteString(w, fixture(t, "aws_page1.xml"))
			case s.failPage2:
				w.WriteHeader(http.StatusServiceUnavailable)
			default:
				io.WriteString(w, fixture(t, "aws_page2.xml"))
			}
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}

func newAWS(server *httptest.Server) *AWS {
	return &AWS{Account: "111122223333", Region: "eu-central-1", Client: server.Client(), Sleep: noSleep,
		Credentials: AWSCredentials{AccessKeyID: "AKIATEST", SecretAccessKey: "secret", SessionToken: "session-token"},
		EC2Endpoint: server.URL, STSEndpoint: server.URL}
}

func TestAWSPaginatesRetriesThrottlingAndWithholdsConflicts(t *testing.T) {
	server := httptest.NewTLSServer((&awsServer{stsAccount: "111122223333"}).handler(t))
	defer server.Close()
	inv, err := newAWS(server).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !inv.Complete || inv.Retries != 1 || inv.Pages != 3 {
		t.Fatalf("provenance: complete=%v retries=%d pages=%d", inv.Complete, inv.Retries, inv.Pages)
	}
	got := recordsByAddress(inv)
	for addr, want := range map[string]string{"10.0.0.10": "private", "10.0.0.11": "private", "198.51.100.10": "public",
		"2001:db8::10": "private", "10.0.1.20": "private"} {
		if got[addr].AddressRole != want {
			t.Errorf("%s role = %q, want %q", addr, got[addr].AddressRole, want)
		}
	}
	if r := got["10.0.0.10"]; r.ResourceID != "i-0aaa0000000000001" || r.Owner != "111122223333" ||
		r.Resource != "arn:aws:ec2:eu-central-1:111122223333:instance/i-0aaa0000000000001" || r.Location != "eu-central-1a" {
		t.Errorf("record metadata: %+v", r)
	}
	if _, ok := got["10.9.9.9"]; ok {
		t.Error("instance from a different owner account imported")
	}
	if len(inv.Conflicts) != 1 || inv.Conflicts[0].Address != netip.MustParseAddr("10.0.9.9") || len(inv.Conflicts[0].ResourceIDs) != 2 {
		t.Fatalf("conflicts: %+v", inv.Conflicts)
	}
	if _, ok := got["10.0.9.9"]; ok {
		t.Error("conflicting address imported")
	}
}

func TestAWSRejectsCredentialsForAnotherAccount(t *testing.T) {
	server := httptest.NewTLSServer((&awsServer{stsAccount: "999988887777"}).handler(t))
	defer server.Close()
	if _, err := newAWS(server).Collect(t.Context()); err == nil || !strings.Contains(err.Error(), "different account") {
		t.Fatalf("account mismatch: %v", err)
	}
}

func TestAWSMarksLaterPageFailureAsPartialWithoutLeakingSecrets(t *testing.T) {
	server := httptest.NewTLSServer((&awsServer{stsAccount: "111122223333", failPage2: true}).handler(t))
	defer server.Close()
	inv, err := newAWS(server).Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if inv.Complete || len(inv.Records) == 0 || len(inv.Notes) == 0 {
		t.Fatalf("partial: complete=%v records=%d notes=%v", inv.Complete, len(inv.Records), inv.Notes)
	}
	for _, note := range inv.Notes {
		if strings.Contains(note, "secret") || strings.Contains(note, "session-token") || strings.Contains(note, "page-2") {
			t.Fatalf("note leaks credentials or page tokens: %s", note)
		}
	}
}

func TestLoadAWSCredentialsRejectsExpiredAndRedactsJSON(t *testing.T) {
	dir := t.TempDir()
	expired := filepath.Join(dir, "expired.json")
	if err := os.WriteFile(expired, []byte(`{"Version":1,"AccessKeyId":"AKIA","SecretAccessKey":"s","Expiration":"2001-01-01T00:00:00Z"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAWSCredentials(expired); err == nil {
		t.Fatal("expired credentials accepted")
	}
	valid := filepath.Join(dir, "valid.json")
	if err := os.WriteFile(valid, []byte(`{"Version":1,"AccessKeyId":"AKIA","SecretAccessKey":"top-secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	creds, err := LoadAWSCredentials(valid)
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := creds.MarshalJSON(); strings.Contains(string(data), "top-secret") {
		t.Fatal("credentials JSON leaks the secret")
	}
}

func TestAzureJoinsVMsNICsAndPublicIPsAcrossPages(t *testing.T) {
	var throttled bool
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer azure-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/virtualMachines") && r.URL.Query().Get("$skiptoken") == "":
			if !throttled {
				throttled = true
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			io.WriteString(w, strings.ReplaceAll(fixture(t, "azure_vms.json"), "NEXT", server.URL))
		case strings.HasSuffix(r.URL.Path, "/virtualMachines"):
			io.WriteString(w, fixture(t, "azure_vms2.json"))
		case strings.HasSuffix(r.URL.Path, "/publicIPAddresses"):
			io.WriteString(w, fixture(t, "azure_publicips.json"))
		case strings.HasSuffix(r.URL.Path, "/networkInterfaces"):
			io.WriteString(w, fixture(t, "azure_nics.json"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	az := &Azure{Subscription: "00000000-0000-0000-0000-0000000000AA", Token: "azure-token", Client: server.Client(), Endpoint: server.URL, Sleep: noSleep}
	inv, err := az.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got := recordsByAddress(inv)
	if !inv.Complete || inv.Retries != 1 || len(inv.Records) != 3 {
		t.Fatalf("inventory: %+v", inv)
	}
	if got["10.1.0.4"].ResourceID != "11111111-1111-1111-1111-111111111111" || got["203.0.113.40"].AddressRole != "public" ||
		got["10.1.0.5"].ResourceID != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("records: %+v", inv.Records)
	}
	if _, ok := got["10.1.0.99"]; ok {
		t.Fatal("unattached NIC imported")
	}
}

func TestAzureRefusesNextLinkToAnotherOrigin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, strings.ReplaceAll(fixture(t, "azure_vms.json"), "NEXT", "https://attacker.example"))
	}))
	defer server.Close()
	az := &Azure{Subscription: "00000000-0000-0000-0000-0000000000aa", Token: "azure-token", Client: server.Client(), Endpoint: server.URL, Sleep: noSleep}
	if _, err := az.Collect(t.Context()); err == nil || !strings.Contains(err.Error(), "origin") {
		t.Fatalf("foreign nextLink: %v", err)
	}
}

func TestGCPPaginatesAndReportsUnreachableLocationsAsPartial(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gcp-token" || r.URL.Path != "/compute/v1/projects/nyxr-lab-01/aggregated/instances" ||
			r.URL.Query().Get("returnPartialSuccess") != "true" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("pageToken") == "gcp-page-2" {
			io.WriteString(w, fixture(t, "gcp_page2.json"))
			return
		}
		io.WriteString(w, fixture(t, "gcp_page1.json"))
	}))
	defer server.Close()
	g := &GCP{Project: "nyxr-lab-01", Token: "gcp-token", Client: server.Client(), Endpoint: server.URL, Sleep: noSleep}
	inv, err := g.Collect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got := recordsByAddress(inv)
	if inv.Complete || inv.Pages != 2 || len(inv.Records) != 4 {
		t.Fatalf("inventory: complete=%v pages=%d records=%+v", inv.Complete, inv.Pages, inv.Records)
	}
	if got["192.0.2.50"].AddressRole != "public" || got["10.2.0.2"].Location != "europe-west1-b" || got["2001:db8:2::2"].ResourceID != "1000000000000000001" {
		t.Fatalf("records: %+v", inv.Records)
	}
	if _, ok := got["10.2.0.99"]; ok {
		t.Fatal("instance from another project imported")
	}
	if !strings.Contains(strings.Join(inv.Notes, ";"), "asia-east1-a") {
		t.Fatalf("notes: %v", inv.Notes)
	}
}

func TestFetcherStopsAfterBoundedAttemptsAndKeepsBodiesOutOfErrors(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "token=leaked")
	}))
	defer server.Close()
	f := &Fetcher{Client: server.Client(), Sleep: noSleep}
	err := f.Do(t.Context(), "probe", func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, server.URL, nil)
	}, nil, func([]byte) error { return nil })
	if err == nil || calls != maxAttempts || f.Retries != maxAttempts-1 || strings.Contains(err.Error(), "leaked") {
		t.Fatalf("calls=%d retries=%d err=%v", calls, f.Retries, err)
	}
	if d := retryDelay(0, "120"); d != maxRetryDelay {
		t.Fatalf("Retry-After not capped: %s", d)
	}
}

func TestConnectorsImplementInterface(t *testing.T) {
	for _, c := range []Connector{&AWS{Account: "1"}, &Azure{Subscription: "2"}, &GCP{Project: "3"}} {
		if c.Provider() == "" || c.Scope() == "" {
			t.Fatalf("%T lacks provider or scope", c)
		}
	}
}
