package central

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/inventory"
)

// ErrObjectNotFound means the object store has no object under the key.
var ErrObjectNotFound = errors.New("object not found")

// ObjectStore holds artifact bytes under content-addressed keys. Put is
// given the verified SHA-256 so a backend can check it end to end.
type ObjectStore interface {
	Put(ctx context.Context, key string, r io.Reader, size int64, sha256Hex string) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
	Location() string
}

// OpenObjects selects a backend: file:///dir or a plain directory path, or
// s3://bucket/prefix?endpoint=https://host&region=r for S3 or an
// S3-compatible store (path-style). S3 credentials come from credsFile
// (credential-process JSON, as for AWS inventory) or, when empty, the
// AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN variables.
func OpenObjects(location, credsFile string) (ObjectStore, error) {
	if location == "" {
		return nil, nil
	}
	if strings.HasPrefix(location, "s3://") {
		return openS3(location, credsFile)
	}
	dir := strings.TrimPrefix(location, "file://")
	if dir == "" {
		return nil, errors.New("object directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &DirObjects{Dir: dir}, nil
}

// DirObjects stores objects as files below Dir.
type DirObjects struct{ Dir string }

func (d *DirObjects) Location() string { return "file://" + d.Dir }

func (d *DirObjects) path(key string) (string, error) {
	if key == "" || strings.Contains(key, "..") || strings.HasPrefix(key, "/") || strings.ContainsAny(key, "\\\x00") {
		return "", fmt.Errorf("invalid object key %q", key)
	}
	return filepath.Join(d.Dir, filepath.FromSlash(key)), nil
}

// Put writes to a temporary file and renames it, so a reader never sees a
// partial object.
func (d *DirObjects) Put(_ context.Context, key string, r io.Reader, size int64, _ string) error {
	p, err := d.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".upload-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	n, err := io.Copy(f, r)
	if err == nil && n != size {
		err = fmt.Errorf("object size %d, want %d", n, size)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), p)
}

func (d *DirObjects) Get(_ context.Context, key string) (io.ReadCloser, error) {
	p, err := d.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrObjectNotFound
	}
	return f, err
}

func (d *DirObjects) Delete(_ context.Context, key string) error {
	p, err := d.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// S3Objects stores objects in an S3 bucket with path-style requests signed by
// Signature Version 4.
type S3Objects struct {
	Endpoint    *url.URL
	Bucket      string
	Prefix      string
	Region      string
	Credentials inventory.AWSCredentials
	Client      *http.Client
	now         func() time.Time
}

func openS3(location, credsFile string) (*S3Objects, error) {
	u, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, errors.New("s3 location needs a bucket: s3://bucket/prefix")
	}
	region := u.Query().Get("region")
	if region == "" {
		region = "us-east-1"
	}
	endpoint := u.Query().Get("endpoint")
	if endpoint == "" {
		endpoint = "https://s3." + region + ".amazonaws.com"
	}
	ep, err := url.Parse(endpoint)
	if err != nil || ep.Host == "" || (ep.Scheme != "https" && ep.Scheme != "http") {
		return nil, fmt.Errorf("invalid s3 endpoint %q", endpoint)
	}
	if ep.Scheme == "http" && !loopbackHost(ep.Hostname()) {
		return nil, errors.New("s3 endpoint must use https unless it is on loopback")
	}
	var creds inventory.AWSCredentials
	if credsFile != "" {
		if creds, err = inventory.LoadAWSCredentials(credsFile); err != nil {
			return nil, err
		}
	} else {
		creds = inventory.AWSCredentials{AccessKeyID: os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"), SessionToken: os.Getenv("AWS_SESSION_TOKEN")}
		if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
			return nil, errors.New("s3 objects need --objects-credentials-file or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
		}
	}
	return &S3Objects{Endpoint: ep, Bucket: u.Host, Prefix: strings.Trim(u.Path, "/"), Region: region,
		Credentials: creds, Client: &http.Client{Timeout: 30 * time.Minute}}, nil
}

func loopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func (s *S3Objects) Location() string {
	loc := "s3://" + s.Bucket
	if s.Prefix != "" {
		loc += "/" + s.Prefix
	}
	return loc
}

func (s *S3Objects) objectURL(key string) *url.URL {
	u := *s.Endpoint
	full := key
	if s.Prefix != "" {
		full = s.Prefix + "/" + key
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + s.Bucket + "/" + full
	u.RawQuery = ""
	return &u
}

func (s *S3Objects) do(ctx context.Context, method, key string, body io.Reader, size int64, payloadHash string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.objectURL(key).String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	if payloadHash == "" {
		payloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // empty body
	}
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	inventory.SignAWS(req, payloadHash, s.Credentials, s.Region, "s3", now().UTC())
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	return client.Do(req)
}

func (s *S3Objects) Put(ctx context.Context, key string, r io.Reader, size int64, sha256Hex string) error {
	resp, err := s.do(ctx, http.MethodPut, key, r, size, sha256Hex)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return s3Error("put", resp)
	}
	return nil
}

func (s *S3Objects) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	resp, err := s.do(ctx, http.MethodGet, key, nil, 0, "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, ErrObjectNotFound
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		return nil, s3Error("get", resp)
	}
	return resp.Body, nil
}

func (s *S3Objects) Delete(ctx context.Context, key string) error {
	resp, err := s.do(ctx, http.MethodDelete, key, nil, 0, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNotFound {
		return s3Error("delete", resp)
	}
	return nil
}

func s3Error(op string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("s3 %s: %s: %s", op, resp.Status, strings.TrimSpace(string(body)))
}
