package integration_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
	backendv3 "github.com/openbao/openbao-plugin-secrets-oauthapp/v3/pkg/backend"
	"github.com/openbao/openbao-plugin-secrets-oauthapp/v3/pkg/persistence"
	backendv2 "github.com/puppetlabs/vault-plugin-secrets-oauthapp/v2/pkg/backend"
	"github.com/stretchr/testify/require"
)

func TestV2ToV3Upgrade(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	ctx = namespace.RootContext(ctx)

	// Set up an initial token validity of 1 minute, which we'll then scale to 5
	// minutes later to force a credential refresh.
	desiredMinimumSeconds := 60
	setDesiredMinimumSeconds := func(minimumSeconds int) {
		desiredMinimumSeconds = minimumSeconds
	}

	// Set up a stub server to handle token requests. This server simply returns
	// a random token with a pre-defined expiration for any HTTP request.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken, err := uuid.GenerateRandomBytes(16)
		require.NoError(t, err)

		refreshToken, err := uuid.GenerateRandomBytes(16)
		require.NoError(t, err)

		_, _ = fmt.Fprintf(
			w,
			"access_token=%s&refresh_token=%s&expires_in=%d",
			base64.RawURLEncoding.EncodeToString(accessToken),
			base64.RawURLEncoding.EncodeToString(refreshToken),
			// The server will give an extra minute of leeway to account for
			// slow tests.
			desiredMinimumSeconds+60,
		)
	}))
	defer srv.Close()

	// Set up a pointer to the factory to use. We'll switch this out later and
	// then reload plugins.
	factory := backendv2.Factory

	core, _, token := vault.TestCoreUnsealedWithConfig(t, &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"oauthapp": func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
				return factory(ctx, conf)
			},
		},
		EnableUI:  false,
		EnableRaw: false,
	})
	defer func() {
		require.NoError(t, core.Shutdown())
	}()

	logger := core.Logger().ResetNamed(t.Name())

	// Set up test engine.
	logger.Info("setting up test engine")

	req := &logical.Request{
		ClientToken: token,
		Operation:   logical.UpdateOperation,
		Path:        "sys/mounts/oauth2",
		Data: map[string]interface{}{
			"type": "oauthapp",
			"path": "oauth2/",
		},
	}

	resp, err := core.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Write configuration.
	logger.Info("writing V2 configuration")

	req = &logical.Request{
		ClientToken: token,
		Operation:   logical.UpdateOperation,
		Path:        "oauth2/config",
		Data: map[string]interface{}{
			"provider": "custom",
			"provider_options": map[string]interface{}{
				"token_url": srv.URL,
			},
			"client_id":     "foo",
			"client_secret": "bar",
		},
	}

	resp, err = core.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Store some credentials.
	logger.Info("writing credentials")

	for i := 0; i < 2; i++ {
		req := &logical.Request{
			ClientToken: token,
			Operation:   logical.UpdateOperation,
			Path:        fmt.Sprintf("oauth2/creds/test-%d", i),
			Data: map[string]interface{}{
				"code": "test",
			},
		}

		resp, err := core.HandleRequest(ctx, req)
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
		require.Nil(t, resp)
	}

	// Read initial token values.
	logger.Info("reading initial credential information")

	auths := map[string]string{
		"oauth2/creds/test-0": "",
		"oauth2/creds/test-1": "",
		"oauth2/self/test":    "",
	}
	for path := range auths {
		req := &logical.Request{
			ClientToken: token,
			Operation:   logical.ReadOperation,
			Path:        path,
		}

		resp, err := core.HandleRequest(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
		require.NotEmpty(t, resp.Data["access_token"])

		auths[path] = resp.Data["access_token"].(string)
	}

	// Update factory to use the new V3 backend. The next call to the factory
	// function will go through this factory instead.
	factory = backendv3.Factory

	// Reload plugin to switch to V3 backend.
	logger.Info("reloading plugin to switch to V3 backend")

	req = &logical.Request{
		ClientToken: token,
		Operation:   logical.UpdateOperation,
		Path:        "sys/plugins/reload/backend",
		Data: map[string]interface{}{
			"mounts": []interface{}{"oauth2/"},
		},
	}

	resp, err = core.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "response has error: %+v", resp.Error())

	tests := []struct {
		Name string
		Test func(t *testing.T, ctx context.Context)
	}{
		{
			Name: "New server information",
			Test: testV2ToV3ServerInformation(core, token),
		},
		{
			Name: "Legacy credential refresh",
			Test: testV2TToV3Credentials(core, token, auths, setDesiredMinimumSeconds),
		},
		{
			Name: "Legacy server is set as default",
			Test: testV2ToV3LegacyDefaultServer(core, token),
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			test.Test(t, ctx)
		})
	}
}

func testV2ToV3ServerInformation(core *vault.Core, token string) func(t *testing.T, ctx context.Context) {
	return func(t *testing.T, ctx context.Context) {
		// Read the new server.
		logger := core.Logger().ResetNamed(t.Name())
		logger.Info("reading new server information")

		req := &logical.Request{
			ClientToken: token,
			Operation:   logical.ReadOperation,
			Path:        "oauth2/servers/legacy",
		}

		resp, err := core.HandleRequest(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
		require.Equal(t, "foo", resp.Data["client_id"])
	}
}

func testV2TToV3Credentials(core *vault.Core, token string, auths map[string]string, setDesiredMinimumSeconds func(minimumSeconds int)) func(t *testing.T, ctx context.Context) {
	return func(t *testing.T, ctx context.Context) {
		// Make sure we can still read all the original tokens. Because none of them
		// have expired, the access tokens should be identical.
		logger := core.Logger().ResetNamed(t.Name())
		logger.Info("reading credential information stored by V2 backend")

		for path := range auths {
			req := &logical.Request{
				ClientToken: token,
				Operation:   logical.ReadOperation,
				Path:        path,
			}

			resp, err := core.HandleRequest(ctx, req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
			require.Equal(t, persistence.LegacyAuthServerName, resp.Data["server"])
			require.Equal(t, auths[path], resp.Data["access_token"])
		}

		// Do the same, but this time force a refresh with a large minimum_seconds
		// value. The access token should change as it requests new values from the
		// newly created legacy server.
		logger.Info("refreshing credentials using new server")

		// Update value for the server.
		desiredMinimumSeconds := 60 * 5
		setDesiredMinimumSeconds(desiredMinimumSeconds)

		for path := range auths {
			req := &logical.Request{
				ClientToken: token,
				Operation:   logical.ReadOperation,
				Path:        path,
				Data: map[string]interface{}{
					"minimum_seconds": desiredMinimumSeconds,
				},
			}

			resp, err := core.HandleRequest(ctx, req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
			require.NotEmpty(t, resp.Data["access_token"])
			require.NotEqual(t, auths[path], resp.Data["access_token"])
		}
	}
}

func testV2ToV3LegacyDefaultServer(core *vault.Core, token string) func(t *testing.T, ctx context.Context) {
	return func(t *testing.T, ctx context.Context) {
		logger := core.Logger().ResetNamed(t.Name())
		logger.Info("reading configuration")
		req := &logical.Request{
			ClientToken: token,
			Operation:   logical.ReadOperation,
			Path:        "oauth2/config",
		}

		resp, err := core.HandleRequest(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
		require.Equal(t, persistence.LegacyAuthServerName, resp.Data["default_server"])

		logger.Info("writing credential without server information")

		req = &logical.Request{
			ClientToken: token,
			Operation:   logical.UpdateOperation,
			Path:        "oauth2/creds/test-legacy-default",
			Data: map[string]interface{}{
				"code": "test",
			},
		}

		resp, err = core.HandleRequest(ctx, req)
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
		require.Nil(t, resp)

		// Read the credential back and make sure the server is set.
		req = &logical.Request{
			ClientToken: token,
			Operation:   logical.ReadOperation,
			Path:        "oauth2/creds/test-legacy-default",
		}

		resp, err = core.HandleRequest(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
		require.Equal(t, persistence.LegacyAuthServerName, resp.Data["server"])
		require.NotEmpty(t, resp.Data["access_token"])
	}
}
