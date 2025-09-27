package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func generateTestPKCS8Key(t *testing.T) (string, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return string(privateKeyPEM), privateKey
}

func TestOktaFactory(t *testing.T) {
	tests := []struct {
		name    string
		opts    map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			opts: map[string]string{
				"domain": "test.okta.com",
			},
			wantErr: false,
		},
		{
			name:    "missing domain",
			opts:    map[string]string{},
			wantErr: true,
			errMsg:  "domain is required",
		},
		{
			name: "invalid private key",
			opts: map[string]string{
				"domain":      "test.okta.com",
				"private_key": "invalid-key",
			},
			wantErr: true,
			errMsg:  "failed to parse PEM block",
		},
		{
			name: "valid private key",
			opts: map[string]string{
				"domain": "test.okta.com",
			},
			wantErr: false,
		},
		{
			name: "custom scheme",
			opts: map[string]string{
				"domain": "test.okta.com",
				"scheme": "http",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "valid private key" {
				keyPEM, _ := generateTestPKCS8Key(t)
				tt.opts["private_key"] = keyPEM
			}

			provider, err := OktaFactory(context.Background(), OktaProviderV1, tt.opts)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, provider)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, provider)
			}
		})
	}
}

func TestOktaRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "new-access-token",
			"token_type": "Bearer",
			"expires_in": 3600,
			"refresh_token": "new-refresh-token"
		}`))
	}))
	defer server.Close()

	provider, err := OktaFactory(context.Background(), OktaProviderV1, map[string]string{
		"domain": strings.TrimPrefix(server.URL, "http://"),
		"scheme": "http",
	})
	require.NoError(t, err)

	ops := provider.Private("test-client", "test-secret")

	// Create a mock token to refresh
	mockToken := &Token{
		Token: &oauth2.Token{
			RefreshToken: "old-refresh-token",
		},
		ProviderVersion: OktaProviderV1,
	}

	newToken, err := ops.RefreshToken(context.Background(), mockToken)
	require.NoError(t, err)
	assert.Equal(t, "new-access-token", newToken.AccessToken)
	assert.Equal(t, "Bearer", newToken.TokenType)
}
func TestOktaClientCredentials(t *testing.T) {
	const (
		testClientID = "test-client"
	)

	tests := []struct {
		name          string
		usePrivateKey bool
		clientID      string
		clientSecret  string
		wantErr       bool
		checkRequest  func(t *testing.T, r *http.Request)
	}{
		{
			name:          "private key success",
			usePrivateKey: true,
			clientID:      testClientID,
			wantErr:       false,
			checkRequest: func(t *testing.T, r *http.Request) {
				err := r.ParseForm()
				require.NoError(t, err)

				// Verify common parameters
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "/oauth2/v1/token", r.URL.Path)
				assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
				assert.Equal(t, "client_credentials", r.Form.Get("grant_type"))

				// Verify JWT parameters
				assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.Form.Get("client_assertion_type"))
				assert.NotEmpty(t, r.Form.Get("client_assertion"))
			},
		},
		{
			name:          "missing client secret",
			usePrivateKey: false,
			clientID:      testClientID,
			wantErr:       true,
			checkRequest:  nil,
		},
		{
			name:          "client secret success",
			usePrivateKey: false,
			clientID:      testClientID,
			clientSecret:  "test-secret",
			wantErr:       false,
			checkRequest: func(t *testing.T, r *http.Request) {
				err := r.ParseForm()
				require.NoError(t, err)
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "client_credentials", r.Form.Get("grant_type"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.checkRequest != nil {
					tt.checkRequest(t, r)
				}

				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{
                    "access_token": "test-token",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }`))
			}))
			defer server.Close()

			opts := map[string]string{
				"domain": strings.TrimPrefix(server.URL, "http://"),
				"scheme": "http",
			}

			if tt.usePrivateKey {
				keyPEM, _ := generateTestPKCS8Key(t)
				opts["private_key"] = keyPEM
			}

			provider, err := OktaFactory(context.Background(), OktaProviderV1, opts)
			require.NoError(t, err)

			ops := provider.Private(tt.clientID, tt.clientSecret)
			token, err := ops.ClientCredentials(context.Background())

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, token)
			assert.Equal(t, "test-token", token.AccessToken)
			assert.Equal(t, "Bearer", token.TokenType)
		})
	}
}

func TestOktaClientCredentialsErrors(t *testing.T) {
	tests := []struct {
		name         string
		usePrivateKey bool
		serverStatus int
		serverResp   string
		wantErrMsg   string
	}{
		{
			name:         "JWT auth server error",
			usePrivateKey: true,
			serverStatus: http.StatusUnauthorized,
			serverResp:   `{"error": "invalid_client", "error_description": "Client authentication failed"}`,
			wantErrMsg:   "authentication failed: invalid_client - Client authentication failed",
		},
		{
			name:         "JWT auth server error without JSON",
			usePrivateKey: true,
			serverStatus: http.StatusInternalServerError,
			serverResp:   "Internal Server Error",
			wantErrMsg:   "request failed with status 500",
		},
		{
			name:         "JWT auth invalid JSON response",
			usePrivateKey: true,
			serverStatus: http.StatusOK,
			serverResp:   "invalid-json",
			wantErrMsg:   "failed to parse response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.serverStatus)
				w.Write([]byte(tt.serverResp))
			}))
			defer server.Close()

			opts := map[string]string{
				"domain": strings.TrimPrefix(server.URL, "http://"),
				"scheme": "http",
			}

			if tt.usePrivateKey {
				keyPEM, _ := generateTestPKCS8Key(t)
				opts["private_key"] = keyPEM
			}

			provider, err := OktaFactory(context.Background(), OktaProviderV1, opts)
			require.NoError(t, err)

			ops := provider.Private("test-client", "test-secret")
			token, err := ops.ClientCredentials(context.Background())

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrMsg)
			assert.Nil(t, token)
		})
	}
}

func TestOktaJWTCreationErrors(t *testing.T) {
	t.Run("missing client ID", func(t *testing.T) {
		keyPEM, _ := generateTestPKCS8Key(t)
		provider, err := OktaFactory(context.Background(), OktaProviderV1, map[string]string{
			"domain":      "test.okta.com",
			"private_key": keyPEM,
		})
		require.NoError(t, err)

		ops := provider.Private("", "").(*oktaOperations)
		assertion, err := ops.createClientAssertion()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client ID is required")
		assert.Empty(t, assertion)
	})

	t.Run("private key not configured", func(t *testing.T) {
		provider, err := OktaFactory(context.Background(), OktaProviderV1, map[string]string{
			"domain": "test.okta.com",
		})
		require.NoError(t, err)

		ops := provider.Private("test-client", "").(*oktaOperations)
		assertion, err := ops.createClientAssertion()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "private key not configured")
		assert.Empty(t, assertion)
	})
}


func TestOktaProviderMethods(t *testing.T) {
	provider, err := OktaFactory(context.Background(), OktaProviderV1, map[string]string{
		"domain": "test.okta.com",
	})
	require.NoError(t, err)

	t.Run("version", func(t *testing.T) {
		assert.Equal(t, OktaProviderV1, provider.Version())
	})

	t.Run("public operations", func(t *testing.T) {
		pubOps := provider.Public("test-client")
		assert.NotNil(t, pubOps)
	})

	t.Run("auth code URL", func(t *testing.T) {
		ops := provider.Private("test-client", "test-secret")
		url, ok := ops.AuthCodeURL("test-state")
		assert.True(t, ok)
		assert.Contains(t, url, "test.okta.com/oauth2/v1/authorize")
		assert.Contains(t, url, "client_id=test-client")
		assert.Contains(t, url, "state=test-state")
	})
}

func TestOktaUnsupportedFlows(t *testing.T) {
	provider, err := OktaFactory(context.Background(), OktaProviderV1, map[string]string{
		"domain": "test.okta.com",
	})
	require.NoError(t, err)

	ops := provider.Private("test-client", "test-secret")

	t.Run("device code auth", func(t *testing.T) {
		auth, ok, err := ops.DeviceCodeAuth(context.Background())
		assert.Nil(t, auth)
		assert.False(t, ok)
		assert.Nil(t, err)
	})

	t.Run("device code exchange", func(t *testing.T) {
		token, err := ops.DeviceCodeExchange(context.Background(), "test-code")
		assert.Nil(t, token)
		assert.EqualError(t, err, "device code flow not supported")
	})

	t.Run("auth code exchange", func(t *testing.T) {
		token, err := ops.AuthCodeExchange(context.Background(), "test-code")
		assert.Nil(t, token)
		assert.EqualError(t, err, "auth code exchange flow not supported")
	})

	t.Run("token exchange", func(t *testing.T) {
		token, err := ops.TokenExchange(context.Background(), nil)
		assert.Nil(t, token)
		assert.EqualError(t, err, "token exchange flow not supported")
	})
}
