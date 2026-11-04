package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/matusso/nyxr/internal/inventory"
	"github.com/matusso/nyxr/internal/storage"
)

type cloudOptions struct {
	provider, scope, region, credentialsFile, caFile string
	allowPartial                                     bool
}

// newCloudConnector builds a read-only connector. Credentials come only from
// a file so they never appear in process arguments or shell history.
func newCloudConnector(opts cloudOptions, client *http.Client) (inventory.Connector, error) {
	scope := strings.TrimSpace(opts.scope)
	if scope == "" {
		return nil, errors.New("--cloud-scope is required (AWS account ID, Azure subscription ID or GCP project ID)")
	}
	if opts.provider != "aws" && opts.region != "" {
		return nil, errors.New("--cloud-region applies to AWS only")
	}
	switch opts.provider {
	case "aws":
		creds, err := inventory.LoadAWSCredentials(opts.credentialsFile)
		if err != nil {
			return nil, err
		}
		return &inventory.AWS{Account: scope, Region: strings.TrimSpace(opts.region), Credentials: creds, Client: client}, nil
	case "azure":
		token, err := inventory.ReadBearerToken(opts.credentialsFile, "Azure access token")
		if err != nil {
			return nil, err
		}
		return &inventory.Azure{Subscription: scope, Token: token, Client: client}, nil
	case "gcp":
		token, err := inventory.ReadBearerToken(opts.credentialsFile, "GCP access token")
		if err != nil {
			return nil, err
		}
		return &inventory.GCP{Project: scope, Token: token, Client: client}, nil
	default:
		return nil, errors.New("--cloud-provider must be aws, azure or gcp")
	}
}

// collectCloudInventory runs one connector and imports its snapshot. A
// partial snapshot is imported only on request and never proves absence.
func collectCloudInventory(ctx context.Context, store *storage.Store, connector inventory.Connector, allowPartial bool) (storage.CloudImport, error) {
	inv, err := connector.Collect(ctx)
	if err != nil {
		return storage.CloudImport{}, fmt.Errorf("%s inventory: %w", connector.Provider(), err)
	}
	if !inv.Complete && !allowPartial {
		return storage.CloudImport{}, fmt.Errorf("%s inventory is partial (%s); rerun or pass --cloud-allow-partial",
			connector.Provider(), strings.Join(inv.Notes, "; "))
	}
	if len(inv.Records) == 0 {
		return storage.CloudImport{}, fmt.Errorf("%s inventory returned no attributable addresses", connector.Provider())
	}
	return store.ImportCloudInventory(ctx, inv)
}
