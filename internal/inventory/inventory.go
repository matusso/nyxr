// Package inventory collects read-only, scoped asset inventory from
// provider APIs. Collection never authorizes scanning: addresses it returns
// become identity evidence only, never scan targets.
package inventory

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/storage"
)

// Connector collects one provider scope (AWS account and region, Azure
// subscription, GCP project). Implementations verify that every returned
// resource belongs to Scope and never mutate provider state.
type Connector interface {
	Provider() string
	Scope() string
	Collect(ctx context.Context) (storage.CloudInventory, error)
}

// Limits bound every collection.
const (
	maxPages      = 1000
	maxRecords    = 100_000
	maxBodyBytes  = 16 << 20
	maxAttempts   = 4
	maxRetryDelay = 30 * time.Second
)

// HTTPError carries only the operation and status code; response bodies and
// credentials never reach error text.
type HTTPError struct {
	Operation string
	Status    int
}

func (e *HTTPError) Error() string { return fmt.Sprintf("%s: HTTP %d", e.Operation, e.Status) }

// NewHTTPClient returns a TLS-verifying client that refuses redirects. caFile
// optionally adds a PEM bundle to the system roots.
func NewHTTPClient(caFile string) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system certificates: %w", err)
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file contains no certificates")
		}
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// ReadSecretFile reads a credential file of at most 64 KiB. Callers never
// echo its contents.
func ReadSecretFile(path, what string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%s file is required", what)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s file: %w", what, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil {
		return nil, fmt.Errorf("read %s file: %w", what, err)
	}
	if len(data) > 64<<10 {
		return nil, fmt.Errorf("%s file is too large", what)
	}
	return data, nil
}

// ReadBearerToken reads a single-line bearer token.
func ReadBearerToken(path, what string) (string, error) {
	data, err := ReadSecretFile(path, what)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" || strings.ContainsAny(token, "\r\n\t ") {
		return "", fmt.Errorf("%s file must contain one token", what)
	}
	return token, nil
}

// Fetcher performs bounded, retried requests. Retries cover throttling and
// transient server errors only; each attempt rebuilds and re-signs the
// request.
type Fetcher struct {
	Client  *http.Client
	Retries int // retries performed, recorded as provenance
	Pages   int // successful responses
	// Sleep waits between attempts; tests replace it.
	Sleep func(context.Context, time.Duration) error
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func retryable(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusInternalServerError ||
		status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

func retryDelay(attempt int, header string) time.Duration {
	header = strings.TrimSpace(header)
	if seconds, err := strconv.Atoi(header); err == nil && seconds >= 0 {
		return min(time.Duration(seconds)*time.Second, maxRetryDelay)
	}
	if when, err := http.ParseTime(header); err == nil {
		return min(max(time.Until(when), 0), maxRetryDelay)
	}
	return min(500*time.Millisecond<<attempt, 8*time.Second)
}

// Do sends the request from build and decodes a 200 response. throttled
// recognizes provider throttling sent with another status (AWS uses 400).
func (f *Fetcher) Do(ctx context.Context, operation string, build func() (*http.Request, error),
	throttled func(status int, body []byte) bool, decode func([]byte) error) error {
	sleep := f.Sleep
	if sleep == nil {
		sleep = sleepContext
	}
	for attempt := 0; ; attempt++ {
		req, err := build()
		if err != nil {
			return err
		}
		resp, err := f.Client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if attempt+1 >= maxAttempts || !transientTransport(err) {
				return fmt.Errorf("%s: request failed: %w", operation, redactURLError(err))
			}
			f.Retries++
			if err := sleep(ctx, retryDelay(attempt, "")); err != nil {
				return err
			}
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
		resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("%s: read response failed", operation)
		}
		if len(body) > maxBodyBytes {
			return fmt.Errorf("%s: response exceeds %d bytes", operation, maxBodyBytes)
		}
		if resp.StatusCode == http.StatusOK {
			if err := decode(body); err != nil {
				return fmt.Errorf("%s: invalid response", operation)
			}
			f.Pages++
			return nil
		}
		again := retryable(resp.StatusCode) || (throttled != nil && throttled(resp.StatusCode, body))
		if !again || attempt+1 >= maxAttempts {
			return &HTTPError{Operation: operation, Status: resp.StatusCode}
		}
		f.Retries++
		if err := sleep(ctx, retryDelay(attempt, resp.Header.Get("Retry-After"))); err != nil {
			return err
		}
	}
}

// transientTransport rejects certificate failures, which never heal on
// retry and must not be papered over.
func transientTransport(err error) bool {
	var verify *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	return !errors.As(err, &verify) && !errors.As(err, &unknown) && !errors.As(err, &host) && !errors.As(err, &invalid)
}

// redactURLError drops the request URL, which can carry page tokens.
func redactURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

// decodeJSON decodes exactly one JSON value.
func decodeJSON(body []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(v); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing content")
	}
	return nil
}

func decodeXML(body []byte, v any) error { return xml.Unmarshal(body, v) }

// builder accumulates records and isolates conflicting addresses.
type builder struct {
	byAddress map[netip.Addr]map[string]storage.CloudRecord
	notes     []string
}

func newBuilder() *builder {
	return &builder{byAddress: map[netip.Addr]map[string]storage.CloudRecord{}}
}

func (b *builder) add(raw, role string, record storage.CloudRecord) error {
	ip, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !ip.IsValid() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback() {
		return nil
	}
	record.Address, record.AddressRole = ip.Unmap(), role
	record.ResourceID = strings.ToLower(strings.TrimSpace(record.ResourceID))
	if record.ResourceID == "" {
		return nil
	}
	ids := b.byAddress[record.Address]
	if ids == nil {
		if len(b.byAddress) >= maxRecords {
			return fmt.Errorf("inventory exceeds %d addresses", maxRecords)
		}
		ids = map[string]storage.CloudRecord{}
		b.byAddress[record.Address] = ids
	}
	if _, ok := ids[record.ResourceID]; !ok {
		ids[record.ResourceID] = record
	}
	return nil
}

func (b *builder) note(format string, args ...any) {
	if len(b.notes) < 100 {
		b.notes = append(b.notes, fmt.Sprintf(format, args...))
	}
}

// finish writes records sorted by address. Addresses claimed by several
// resources (overlapping private ranges in separate networks, for example)
// become conflicts and are not imported.
func (b *builder) finish(inv *storage.CloudInventory) {
	addrs := make([]netip.Addr, 0, len(b.byAddress))
	for addr := range b.byAddress {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
	for _, addr := range addrs {
		ids := b.byAddress[addr]
		if len(ids) == 1 {
			for _, record := range ids {
				inv.Records = append(inv.Records, record)
			}
			continue
		}
		conflict := storage.CloudConflict{Address: addr}
		for id := range ids {
			conflict.ResourceIDs = append(conflict.ResourceIDs, id)
		}
		sort.Strings(conflict.ResourceIDs)
		inv.Conflicts = append(inv.Conflicts, conflict)
	}
	inv.Notes = append(inv.Notes, b.notes...)
	inv.Finished = time.Now().UTC()
}
