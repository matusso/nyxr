package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/storage"
)

var guidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Azure collects VM addresses for one subscription through Azure Resource
// Manager. The built-in Reader role suffices; the narrowest custom role
// needs Microsoft.Compute/virtualMachines/read,
// Microsoft.Network/networkInterfaces/read and
// Microsoft.Network/publicIPAddresses/read.
type Azure struct {
	Subscription string
	Token        string // ARM bearer token, e.g. az account get-access-token
	Client       *http.Client
	Endpoint     string // empty uses https://management.azure.com
	Sleep        func(context.Context, time.Duration) error
}

func (a *Azure) Provider() string { return "azure" }
func (a *Azure) Scope() string    { return a.Subscription }

const (
	azureComputeAPI = "2024-07-01"
	azureNetworkAPI = "2024-05-01"
)

// list pages one ARM collection. nextLink must stay on the same origin so
// the bearer token is never sent elsewhere.
func (a *Azure) list(ctx context.Context, f *Fetcher, base *url.URL, path, apiVersion string, each func([]byte) error) error {
	next := *base
	next.Path = path
	next.RawQuery = url.Values{"api-version": {apiVersion}}.Encode()
	link := next.String()
	seen := map[string]bool{}
	for page := 0; link != ""; page++ {
		if page >= maxPages {
			return fmt.Errorf("%s: more than %d pages", path, maxPages)
		}
		target, err := url.Parse(link)
		if err != nil || target.Scheme != base.Scheme || target.Host != base.Host || target.User != nil {
			return errors.New("Azure nextLink left the Resource Manager origin")
		}
		if seen[link] {
			return errors.New("Azure pagination repeated a nextLink")
		}
		seen[link] = true
		var result struct {
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"nextLink"`
		}
		err = f.Do(ctx, "azure list "+path[strings.LastIndex(path, "/")+1:], func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+a.Token)
			req.Header.Set("Accept", "application/json")
			return req, nil
		}, nil, func(b []byte) error { return decodeJSON(b, &result) })
		if err != nil {
			return err
		}
		for _, item := range result.Value {
			if err := each(item); err != nil {
				return err
			}
		}
		link = result.NextLink
	}
	return nil
}

func (a *Azure) Collect(ctx context.Context) (storage.CloudInventory, error) {
	sub := strings.ToLower(strings.TrimSpace(a.Subscription))
	if !guidPattern.MatchString(sub) {
		return storage.CloudInventory{}, errors.New("Azure scope must be a subscription ID (GUID)")
	}
	raw := a.Endpoint
	if raw == "" {
		raw = "https://management.azure.com"
	}
	base, err := url.Parse(raw)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || (base.Path != "" && base.Path != "/") || base.RawQuery != "" {
		return storage.CloudInventory{}, errors.New("Azure endpoint must be an HTTPS origin")
	}
	prefix := "/subscriptions/" + sub + "/"
	inScope := func(id string) bool { return strings.HasPrefix(strings.ToLower(id), prefix) }
	f := &Fetcher{Client: a.Client, Sleep: a.Sleep}
	inv := storage.CloudInventory{Provider: "azure", Scope: sub,
		Collector: "azure-arm/compute-" + azureComputeAPI + "+network-" + azureNetworkAPI, Complete: true}
	b := newBuilder()

	type vm struct{ vmID, location string }
	vms := map[string]vm{}
	err = a.list(ctx, f, base, prefix+"providers/Microsoft.Compute/virtualMachines", azureComputeAPI, func(item []byte) error {
		var v struct {
			ID         string `json:"id"`
			Location   string `json:"location"`
			Properties struct {
				VMID string `json:"vmId"`
			} `json:"properties"`
		}
		if decodeJSON(item, &v) != nil || !inScope(v.ID) {
			b.note("skipped a virtual machine outside the subscription or with an unreadable shape")
			return nil
		}
		if guidPattern.MatchString(strings.ToLower(v.Properties.VMID)) {
			vms[strings.ToLower(v.ID)] = vm{strings.ToLower(v.Properties.VMID), v.Location}
		}
		return nil
	})
	if err != nil {
		return storage.CloudInventory{}, err
	}
	publicIPs := map[string]string{}
	if err := a.list(ctx, f, base, prefix+"providers/Microsoft.Network/publicIPAddresses", azureNetworkAPI, func(item []byte) error {
		var p struct {
			ID         string `json:"id"`
			Properties struct {
				IPAddress string `json:"ipAddress"`
			} `json:"properties"`
		}
		if decodeJSON(item, &p) == nil && inScope(p.ID) && p.Properties.IPAddress != "" {
			publicIPs[strings.ToLower(p.ID)] = p.Properties.IPAddress
		}
		return nil
	}); err != nil {
		inv.Complete = false
		b.note("public IP addresses unavailable: %v", err)
	}
	err = a.list(ctx, f, base, prefix+"providers/Microsoft.Network/networkInterfaces", azureNetworkAPI, func(item []byte) error {
		var nic struct {
			ID         string `json:"id"`
			Properties struct {
				VirtualMachine *struct {
					ID string `json:"id"`
				} `json:"virtualMachine"`
				IPConfigurations []struct {
					Properties struct {
						PrivateIPAddress string `json:"privateIPAddress"`
						PublicIPAddress  *struct {
							ID string `json:"id"`
						} `json:"publicIPAddress"`
					} `json:"properties"`
				} `json:"ipConfigurations"`
			} `json:"properties"`
		}
		if decodeJSON(item, &nic) != nil || !inScope(nic.ID) || nic.Properties.VirtualMachine == nil {
			return nil
		}
		vmID := strings.ToLower(nic.Properties.VirtualMachine.ID)
		owner, ok := vms[vmID]
		if !ok {
			// The VM may be in another subscription or was not listed.
			return nil
		}
		record := storage.CloudRecord{ResourceID: owner.vmID, Resource: vmID, Location: owner.location, Owner: sub}
		for _, config := range nic.Properties.IPConfigurations {
			if err := b.add(config.Properties.PrivateIPAddress, "private", record); err != nil {
				return err
			}
			if config.Properties.PublicIPAddress != nil {
				if ip, ok := publicIPs[strings.ToLower(config.Properties.PublicIPAddress.ID)]; ok {
					if err := b.add(ip, "public", record); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		inv.Complete = false
		b.note("network interfaces incomplete: %v", err)
	}
	inv.Pages, inv.Retries = f.Pages, f.Retries
	b.finish(&inv)
	return inv, nil
}
