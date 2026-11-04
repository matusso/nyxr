package inventory

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/storage"
)

// AWSCredentials uses the `aws configure export-credentials --format process`
// JSON shape so operators can hand Nyxr short-lived role credentials.
type AWSCredentials struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken,omitempty"`
	Expiration      string `json:"Expiration,omitempty"`
}

// LoadAWSCredentials reads a credential-process JSON file.
func LoadAWSCredentials(path string) (AWSCredentials, error) {
	data, err := ReadSecretFile(path, "AWS credentials")
	if err != nil {
		return AWSCredentials{}, err
	}
	var creds AWSCredentials
	if err := decodeJSON(data, &creds); err != nil {
		return AWSCredentials{}, errors.New("AWS credentials file must be credential-process JSON")
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return AWSCredentials{}, errors.New("AWS credentials file lacks AccessKeyId or SecretAccessKey")
	}
	if creds.Expiration != "" {
		if expires, err := time.Parse(time.RFC3339, creds.Expiration); err == nil && time.Now().After(expires) {
			return AWSCredentials{}, errors.New("AWS credentials have expired")
		}
	}
	return creds, nil
}

var (
	awsAccountPattern = regexp.MustCompile(`^[0-9]{12}$`)
	awsRegionPattern  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
)

// AWS collects EC2 instance addresses for one account and region. Required
// permissions: ec2:DescribeInstances (sts:GetCallerIdentity needs none).
type AWS struct {
	Account     string
	Region      string
	Credentials AWSCredentials
	Client      *http.Client
	// Endpoint overrides, for VPC endpoints and tests. Empty uses the
	// regional public endpoints.
	EC2Endpoint string
	STSEndpoint string
	Sleep       func(context.Context, time.Duration) error
	now         func() time.Time
}

func (a *AWS) Provider() string { return "aws" }
func (a *AWS) Scope() string    { return a.Account }

func (a *AWS) endpoint(override, service string) (*url.URL, error) {
	raw := override
	if raw == "" {
		raw = "https://" + service + "." + a.Region + ".amazonaws.com/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%s endpoint must be an HTTPS origin", service)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

func awsThrottled(status int, body []byte) bool {
	if status != http.StatusBadRequest {
		return false
	}
	return bytes.Contains(body, []byte("<Code>Throttling</Code>")) || bytes.Contains(body, []byte("<Code>RequestLimitExceeded</Code>"))
}

func (a *AWS) post(ctx context.Context, f *Fetcher, service string, endpoint *url.URL, form url.Values, out any) error {
	body := form.Encode()
	return f.Do(ctx, service+" "+form.Get("Action"), func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		now := time.Now
		if a.now != nil {
			now = a.now
		}
		signAWS(req, []byte(body), a.Credentials, a.Region, service, now().UTC())
		return req, nil
	}, awsThrottled, func(b []byte) error { return decodeXML(b, out) })
}

type awsInstance struct {
	InstanceID       string `xml:"instanceId"`
	PrivateIPAddress string `xml:"privateIpAddress"`
	PublicIPAddress  string `xml:"ipAddress"`
	Placement        struct {
		Zone string `xml:"availabilityZone"`
	} `xml:"placement"`
	Interfaces []struct {
		OwnerID string `xml:"ownerId"`
		Private []struct {
			Address     string `xml:"privateIpAddress"`
			Association struct {
				PublicIP string `xml:"publicIp"`
			} `xml:"association"`
		} `xml:"privateIpAddressesSet>item"`
		IPv6 []struct {
			Address string `xml:"ipv6Address"`
		} `xml:"ipv6AddressesSet>item"`
	} `xml:"networkInterfaceSet>item"`
}

// Collect verifies the credential's account, then pages DescribeInstances.
func (a *AWS) Collect(ctx context.Context) (storage.CloudInventory, error) {
	if !awsAccountPattern.MatchString(a.Account) {
		return storage.CloudInventory{}, errors.New("AWS scope must be a 12-digit account ID")
	}
	if !awsRegionPattern.MatchString(a.Region) {
		return storage.CloudInventory{}, errors.New("AWS region is required, for example eu-central-1")
	}
	stsURL, err := a.endpoint(a.STSEndpoint, "sts")
	if err != nil {
		return storage.CloudInventory{}, err
	}
	ec2URL, err := a.endpoint(a.EC2Endpoint, "ec2")
	if err != nil {
		return storage.CloudInventory{}, err
	}
	f := &Fetcher{Client: a.Client, Sleep: a.Sleep}
	var identity struct {
		Account string `xml:"GetCallerIdentityResult>Account"`
	}
	if err := a.post(ctx, f, "sts", stsURL, url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}}, &identity); err != nil {
		return storage.CloudInventory{}, err
	}
	if identity.Account != a.Account {
		return storage.CloudInventory{}, errors.New("AWS credentials belong to a different account than the requested scope")
	}
	inv := storage.CloudInventory{Provider: "aws", Scope: a.Account, Region: a.Region,
		Collector: "aws-ec2-describe-instances/2016-11-15", Complete: true}
	b := newBuilder()
	token, seen := "", map[string]bool{}
	for page := 0; ; page++ {
		if page >= maxPages {
			inv.Complete = false
			b.note("stopped after %d DescribeInstances pages", maxPages)
			break
		}
		form := url.Values{"Action": {"DescribeInstances"}, "Version": {"2016-11-15"}, "MaxResults": {"1000"}}
		if token != "" {
			form.Set("NextToken", token)
		}
		var result struct {
			Reservations []struct {
				OwnerID   string        `xml:"ownerId"`
				Instances []awsInstance `xml:"instancesSet>item"`
			} `xml:"reservationSet>item"`
			NextToken string `xml:"nextToken"`
		}
		if err := a.post(ctx, f, "ec2", ec2URL, form, &result); err != nil {
			if page == 0 {
				return storage.CloudInventory{}, err
			}
			inv.Complete = false
			b.note("DescribeInstances page %d failed: %v", page+1, err)
			break
		}
		for _, reservation := range result.Reservations {
			if reservation.OwnerID != a.Account {
				b.note("skipped reservation owned by a different account")
				continue
			}
			for _, instance := range reservation.Instances {
				if err := addAWSInstance(b, a, reservation.OwnerID, instance); err != nil {
					return storage.CloudInventory{}, err
				}
			}
		}
		if result.NextToken == "" {
			break
		}
		if seen[result.NextToken] {
			return storage.CloudInventory{}, errors.New("DescribeInstances pagination repeated a token")
		}
		seen[result.NextToken], token = true, result.NextToken
	}
	inv.Pages, inv.Retries = f.Pages, f.Retries
	b.finish(&inv)
	return inv, nil
}

func addAWSInstance(b *builder, a *AWS, owner string, instance awsInstance) error {
	if !strings.HasPrefix(instance.InstanceID, "i-") {
		return nil
	}
	record := storage.CloudRecord{ResourceID: instance.InstanceID, Owner: owner, Location: instance.Placement.Zone,
		Resource: "arn:aws:ec2:" + a.Region + ":" + owner + ":instance/" + instance.InstanceID}
	add := func(raw, role string) error { return b.add(raw, role, record) }
	if err := add(instance.PrivateIPAddress, "private"); err != nil {
		return err
	}
	if err := add(instance.PublicIPAddress, "public"); err != nil {
		return err
	}
	for _, nic := range instance.Interfaces {
		if nic.OwnerID != "" && nic.OwnerID != owner {
			b.note("skipped interface owned by a different account on %s", instance.InstanceID)
			continue
		}
		for _, private := range nic.Private {
			if err := add(private.Address, "private"); err != nil {
				return err
			}
			if err := add(private.Association.PublicIP, "public"); err != nil {
				return err
			}
		}
		for _, v6 := range nic.IPv6 {
			if err := add(v6.Address, "private"); err != nil {
				return err
			}
		}
	}
	return nil
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// signAWS adds a Signature Version 4 Authorization header. The canonical
// request covers every header already set plus host and x-amz-date.
func signAWS(req *http.Request, body []byte, creds AWSCredentials, region, service string, now time.Time) {
	payload := sha256.Sum256(body)
	SignAWS(req, hex.EncodeToString(payload[:]), creds, region, service, now)
}

// SignAWS signs req for a payload whose SHA-256 is payloadHash (lowercase
// hex), so a streamed body need not be held in memory. S3 also requires the
// same hash in an X-Amz-Content-Sha256 header, which the caller sets first.
func SignAWS(req *http.Request, payloadHash string, creds AWSCredentials, region, service string, now time.Time) {
	amzDate := now.Format("20060102T150405Z")
	day := now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}
	headers := map[string]string{"host": req.URL.Host}
	for name, values := range req.Header {
		headers[strings.ToLower(name)] = strings.Join(values, ",")
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, name := range names {
		fmt.Fprintf(&canonicalHeaders, "%s:%s\n", name, strings.TrimSpace(headers[name]))
	}
	signed := strings.Join(names, ";")
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	query := req.URL.Query()
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var canonicalQuery []string
	for _, key := range keys {
		values := append([]string(nil), query[key]...)
		sort.Strings(values)
		for _, value := range values {
			canonicalQuery = append(canonicalQuery, awsEscape(key)+"="+awsEscape(value))
		}
	}
	canonical := strings.Join([]string{req.Method, path, strings.Join(canonicalQuery, "&"),
		canonicalHeaders.String(), signed, payloadHash}, "\n")
	digest := sha256.Sum256([]byte(canonical))
	scope := day + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(digest[:])
	key := hmacSHA256([]byte("AWS4"+creds.SecretAccessKey), day)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+creds.AccessKeyID+"/"+scope+
		", SignedHeaders="+signed+", Signature="+signature)
}

func awsEscape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

// MarshalJSON keeps secrets out of any accidental encoding.
func (c AWSCredentials) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"AccessKeyId": "[redacted]"})
}
