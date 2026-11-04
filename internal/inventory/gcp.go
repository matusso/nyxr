package inventory

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/storage"
)

var (
	gcpProjectPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	gcpIDPattern      = regexp.MustCompile(`^[0-9]{1,20}$`)
)

// GCP collects Compute Engine instance addresses for one project. Required
// permission: compute.instances.list (roles/compute.viewer).
type GCP struct {
	Project  string
	Token    string // OAuth access token, e.g. gcloud auth print-access-token
	Client   *http.Client
	Endpoint string // empty uses https://compute.googleapis.com
	Sleep    func(context.Context, time.Duration) error
}

func (g *GCP) Provider() string { return "gcp" }
func (g *GCP) Scope() string    { return g.Project }

type gcpInstance struct {
	ID                string `json:"id"`
	SelfLink          string `json:"selfLink"`
	Zone              string `json:"zone"`
	NetworkInterfaces []struct {
		NetworkIP     string `json:"networkIP"`
		IPv6Address   string `json:"ipv6Address"`
		AccessConfigs []struct {
			NatIP string `json:"natIP"`
		} `json:"accessConfigs"`
		IPv6AccessConfigs []struct {
			ExternalIPv6 string `json:"externalIpv6"`
		} `json:"ipv6AccessConfigs"`
	} `json:"networkInterfaces"`
}

func (g *GCP) Collect(ctx context.Context) (storage.CloudInventory, error) {
	if !gcpProjectPattern.MatchString(g.Project) {
		return storage.CloudInventory{}, errors.New("GCP scope must be a project ID")
	}
	raw := g.Endpoint
	if raw == "" {
		raw = "https://compute.googleapis.com"
	}
	base, err := url.Parse(raw)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || (base.Path != "" && base.Path != "/") || base.RawQuery != "" {
		return storage.CloudInventory{}, errors.New("GCP endpoint must be an HTTPS origin")
	}
	projectPath := "/projects/" + g.Project + "/"
	f := &Fetcher{Client: g.Client, Sleep: g.Sleep}
	inv := storage.CloudInventory{Provider: "gcp", Scope: g.Project,
		Collector: "gcp-compute-v1/aggregated-instances", Complete: true}
	b := newBuilder()
	token, seen := "", map[string]bool{}
	for page := 0; ; page++ {
		if page >= maxPages {
			inv.Complete = false
			b.note("stopped after %d aggregated instance pages", maxPages)
			break
		}
		endpoint := *base
		endpoint.Path = "/compute/v1/projects/" + g.Project + "/aggregated/instances"
		query := url.Values{"maxResults": {"500"}, "returnPartialSuccess": {"true"}}
		if token != "" {
			query.Set("pageToken", token)
		}
		endpoint.RawQuery = query.Encode()
		var result struct {
			Items map[string]struct {
				Instances []gcpInstance `json:"instances"`
				Warning   *struct {
					Code string `json:"code"`
				} `json:"warning"`
			} `json:"items"`
			NextPageToken string   `json:"nextPageToken"`
			Unreachables  []string `json:"unreachables"`
		}
		err := f.Do(ctx, "gcp aggregated instances", func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+g.Token)
			req.Header.Set("Accept", "application/json")
			return req, nil
		}, nil, func(body []byte) error { return decodeJSON(body, &result) })
		if err != nil {
			if page == 0 {
				return storage.CloudInventory{}, err
			}
			inv.Complete = false
			b.note("aggregated instances page %d failed: %v", page+1, err)
			break
		}
		if len(result.Unreachables) > 0 {
			inv.Complete = false
			sort.Strings(result.Unreachables)
			b.note("unreachable locations: %s", strings.Join(result.Unreachables[:min(len(result.Unreachables), 20)], ", "))
		}
		for scope, entry := range result.Items {
			if entry.Warning != nil && entry.Warning.Code != "" && entry.Warning.Code != "NO_RESULTS_ON_PAGE" {
				inv.Complete = false
				b.note("%s reported %s", scope, entry.Warning.Code)
			}
			for _, instance := range entry.Instances {
				if err := addGCPInstance(b, g.Project, projectPath, instance); err != nil {
					return storage.CloudInventory{}, err
				}
			}
		}
		if result.NextPageToken == "" {
			break
		}
		if seen[result.NextPageToken] {
			return storage.CloudInventory{}, errors.New("GCP pagination repeated a page token")
		}
		seen[result.NextPageToken], token = true, result.NextPageToken
	}
	inv.Pages, inv.Retries = f.Pages, f.Retries
	b.finish(&inv)
	return inv, nil
}

func addGCPInstance(b *builder, project, projectPath string, instance gcpInstance) error {
	if !gcpIDPattern.MatchString(instance.ID) {
		return nil
	}
	if self, err := url.Parse(instance.SelfLink); err != nil || !strings.Contains(self.Path, projectPath) {
		b.note("skipped instance %s outside project", instance.ID)
		return nil
	}
	zone := instance.Zone[strings.LastIndex(instance.Zone, "/")+1:]
	record := storage.CloudRecord{ResourceID: instance.ID, Resource: instance.SelfLink, Location: zone, Owner: project}
	for _, nic := range instance.NetworkInterfaces {
		if err := b.add(nic.NetworkIP, "private", record); err != nil {
			return err
		}
		if err := b.add(nic.IPv6Address, "private", record); err != nil {
			return err
		}
		for _, access := range nic.AccessConfigs {
			if err := b.add(access.NatIP, "public", record); err != nil {
				return err
			}
		}
		for _, access := range nic.IPv6AccessConfigs {
			if err := b.add(access.ExternalIPv6, "public", record); err != nil {
				return err
			}
		}
	}
	return nil
}
