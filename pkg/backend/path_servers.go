package backend

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/openbao/openbao-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/openbao/openbao-plugin-secrets-oauthapp/v3/pkg/provider"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
)

func (b *backend) serversListOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var serverNames []string

	m := b.data.AuthServer.Manager(req.Storage)
	err := m.ForEachAuthServerKey(ctx, func(keyer persistence.AuthServerKeyer) error {
		entry, err := m.ReadAuthServerEntry(ctx, keyer)
		if err != nil {
			return err
		}

		if persistence.AuthServerName(entry.Name).AuthServerKey() != keyer.AuthServerKey() {
			// Corrupt or likely empty data.
			//
			// UPGRADING (v3.0.0-beta.{1,2,3}): There was a brief period where
			// we didn't record the server name in storage at all (in which case
			// we can't show it here), so this check is important to maintain.
			return nil
		}

		serverNames = append(serverNames, entry.Name)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(serverNames)
	return logical.ListResponse(serverNames), nil
}

func (b *backend) serversReadOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	server, err := b.cache.AuthServer.Get(ctx, req.Storage, persistence.AuthServerName(data.Get("name").(string)))
	if err != nil || server == nil {
		return nil, err
	}
	defer server.Put()

	resp := &logical.Response{
		Data: map[string]interface{}{
			"client_id":        server.ClientID,
			"auth_url_params":  server.AuthURLParams,
			"provider":         server.ProviderName,
			"provider_version": server.ProviderVersion,
			"provider_options": server.ProviderOptions,
		},
	}
	return resp, nil
}

func (b *backend) serversUpdateOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	clientID, ok := data.GetOk("client_id")
	if !ok {
		return logical.ErrorResponse("missing client ID"), nil
	}

	providerName, ok := data.GetOk("provider")
	if !ok {
		return logical.ErrorResponse("missing provider"), nil
	}

	providerOptions := data.Get("provider_options").(map[string]string)

	p, err := b.providerRegistry.New(ctx, providerName.(string), providerOptions)
	if errors.Is(err, provider.ErrNoSuchProvider) {
		return logical.ErrorResponse("provider %q does not exist", providerName), nil
	} else if errmark.MarkedUser(err) {
		return logical.ErrorResponse(errmark.MarkShort(err).Error()), nil
	} else if err != nil {
		return nil, err
	}

	var clientSecrets []string
	if clientSecret := data.Get("client_secret").(string); clientSecret != "" {
		clientSecrets = append(clientSecrets, clientSecret)
	}
	clientSecrets = append(clientSecrets, data.Get("client_secrets").([]string)...)

	entry := &persistence.AuthServerEntry{
		Name: data.Get("name").(string),

		ClientID:        clientID.(string),
		ClientSecrets:   clientSecrets,
		AuthURLParams:   data.Get("auth_url_params").(map[string]string),
		ProviderName:    providerName.(string),
		ProviderVersion: p.Version(),
		ProviderOptions: providerOptions,
	}
	keyer := persistence.AuthServerName(entry.Name)

	if err := b.data.AuthServer.Manager(req.Storage).WriteAuthServerEntry(ctx, keyer, entry); err != nil {
		return nil, err
	}

	b.cache.AuthServer.Invalidate(keyer)

	return nil, nil
}

func (b *backend) serversDeleteOperation(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	keyer := persistence.AuthServerName(data.Get("name").(string))

	if err := b.data.AuthServer.Manager(req.Storage).DeleteAuthServerEntry(ctx, keyer); err != nil {
		return nil, err
	}

	b.cache.AuthServer.Invalidate(keyer)

	return nil, nil
}

const (
	ServersPathPrefix = "servers/"
)

var serversFields = map[string]*framework.FieldSchema{
	// fields for both read & write operations
	"name": {
		Type:        framework.TypeString,
		Description: "Specifies the name of the server.",
	},
	// fields for write operation
	"client_id": {
		Type:        framework.TypeString,
		Description: "Specifies the OAuth 2 client ID.",
	},
	"client_secret": {
		Type:        framework.TypeString,
		Description: "Specifies the OAuth 2 client secret. Prepended to the values of the client_secrets field if present.",
	},
	"client_secrets": {
		Type:        framework.TypeCommaStringSlice,
		Description: "Specifies OAuth 2 client secrets, each of which will be tried in order. Appended to the value of the client_secret field if present.",
	},
	"auth_url_params": {
		Type:        framework.TypeKVPairs,
		Description: "Specifies the additional query parameters to add to the authorization code URL.",
	},
	"provider": {
		Type:        framework.TypeString,
		Description: "Specifies the OAuth 2 provider.",
	},
	"provider_options": {
		Type:        framework.TypeKVPairs,
		Description: "Specifies any provider-specific options.",
	},
}

const serversHelpSynopsis = `
Manages the OAuth 2.0 authorization servers used by this plugin.
`

const serversHelpDescription = `
This endpoint allows users to configure the set of authorization
servers and client information for use in other endpoints. Other
endpoints that contain a server name as a path parameter or field
reference the names of servers defined in this endpoint.
`

func pathServersList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: ServersPathPrefix + `?$`,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.serversListOperation,
				Summary:  "List available OAuth 2.0 authorization server names.",
			},
		},
		HelpSynopsis:    strings.TrimSpace(serversHelpSynopsis),
		HelpDescription: strings.TrimSpace(serversHelpDescription),
	}
}

func pathServers(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: ServersPathPrefix + nameRegex("name") + `$`,
		Fields:  serversFields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.serversReadOperation,
				Summary:  "Get information about an OAuth 2.0 authorization server.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.serversUpdateOperation,
				Summary:  "Write information about an OAuth 2.0 authorization server.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.serversDeleteOperation,
				Summary:  "Remove an OAuth 2.0 authorization server.",
			},
		},
		HelpSynopsis:    strings.TrimSpace(serversHelpSynopsis),
		HelpDescription: strings.TrimSpace(serversHelpDescription),
	}
}
