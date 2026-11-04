package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/matusso/nyxr/internal/inventory"
	"github.com/matusso/nyxr/internal/storage"
)

// collectKubernetesNodes reads node UIDs and their advertised IP addresses.
// The supplied scope is the operator's stable identifier for this cluster.
func collectKubernetesNodes(ctx context.Context, apiURL, tokenFile, caFile, scope string) ([]storage.ExternalIdentifier, error) {
	base, err := url.Parse(apiURL)
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil || base.Opaque != "" ||
		(base.Path != "" && base.Path != "/") || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("kube-api must be an HTTPS server origin")
	}
	if strings.TrimSpace(scope) == "" {
		return nil, errors.New("kube-cluster-scope is required")
	}
	if tokenFile == "" {
		return nil, errors.New("kube-token-file is required")
	}
	token, err := inventory.ReadBearerToken(tokenFile, "Kubernetes token")
	if err != nil {
		return nil, err
	}
	client, err := inventory.NewHTTPClient(caFile)
	if err != nil {
		return nil, fmt.Errorf("Kubernetes TLS: %w", err)
	}
	client.Timeout = 15 * time.Second
	defer client.CloseIdleConnections()
	fetcher := &inventory.Fetcher{Client: client}
	endpoint := *base
	endpoint.Path = "/api/v1/nodes"
	seenPages := map[string]bool{}
	addressUID := map[netip.Addr]string{}
	var ids []storage.ExternalIdentifier
	continuation := ""
	for page := 0; page < 1000; page++ {
		query := url.Values{"limit": {"500"}}
		if continuation != "" {
			query.Set("continue", continuation)
		}
		endpoint.RawQuery = query.Encode()
		var result struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []struct {
				Metadata struct {
					UID string `json:"uid"`
				} `json:"metadata"`
				Status struct {
					Addresses []struct {
						Type    string `json:"type"`
						Address string `json:"address"`
					} `json:"addresses"`
				} `json:"status"`
			} `json:"items"`
		}
		err := fetcher.Do(ctx, "list Kubernetes nodes", func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Accept", "application/json")
			return req, nil
		}, nil, func(body []byte) error {
			if len(body) > 8<<20 {
				return errors.New("oversized")
			}
			decoder := json.NewDecoder(bytes.NewReader(body))
			if err := decoder.Decode(&result); err != nil {
				return err
			}
			var trailing any
			if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
				return errors.New("trailing content")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		for _, node := range result.Items {
			uid := strings.ToLower(strings.TrimSpace(node.Metadata.UID))
			if uid == "" {
				continue
			}
			for _, address := range node.Status.Addresses {
				if address.Type != "InternalIP" && address.Type != "ExternalIP" {
					continue
				}
				ip, err := netip.ParseAddr(address.Address)
				if err != nil || !ip.IsValid() || ip.IsMulticast() || ip.IsUnspecified() {
					continue
				}
				ip = ip.Unmap()
				if previous, ok := addressUID[ip]; ok {
					if previous != uid {
						return nil, fmt.Errorf("Kubernetes nodes disagree about address %s", ip)
					}
					continue
				}
				addressUID[ip] = uid
				ids = append(ids, storage.ExternalIdentifier{Address: ip, Kind: "kubernetes.node_uid", Scope: scope, Value: uid})
				if len(ids) > 100_000 {
					return nil, errors.New("Kubernetes node list exceeds 100000 addresses")
				}
			}
		}
		if result.Metadata.Continue == "" {
			if len(ids) == 0 {
				return nil, errors.New("Kubernetes API returned no nodes with usable UIDs and IP addresses")
			}
			return ids, nil
		}
		if seenPages[result.Metadata.Continue] {
			return nil, errors.New("Kubernetes node pagination repeated a cursor")
		}
		seenPages[result.Metadata.Continue] = true
		continuation = result.Metadata.Continue
	}
	return nil, errors.New("Kubernetes node list exceeds 1000 pages")
}
