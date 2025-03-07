package backend_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao-plugin-secrets-oauthapp/v3/pkg/backend"
	"github.com/openbao/openbao-plugin-secrets-oauthapp/v3/pkg/provider"
	"github.com/openbao/openbao-plugin-secrets-oauthapp/v3/pkg/testutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/puppetlabs/leg/timeutil/pkg/clock"
	"github.com/puppetlabs/leg/timeutil/pkg/clock/k8sext"
	"github.com/puppetlabs/leg/timeutil/pkg/retry"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	testclock "k8s.io/utils/clock/testing"
)

func TestPeriodicRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	// We may have at most 3 writes with no reads (second, third token issuance
	// and third token refresh).
	refreshed := make(chan string, 3)

	clk := testclock.NewFakeClock(time.Now())

	exchanges := map[string]testutil.MockAuthCodeExchangeFunc{
		"first": testutil.RandomMockAuthCodeExchange,
		"second": testutil.AmendTokenMockAuthCodeExchange(
			testutil.IncrementMockAuthCodeExchange("second_"),
			func(tok *provider.Token) error {
				refreshed <- tok.AccessToken
				return nil
			},
		),
		"third": testutil.AmendTokenMockAuthCodeExchange(
			testutil.IncrementMockAuthCodeExchange("third_"),
			func(tok *provider.Token) error {
				if tok.AccessToken == "third_1" {
					// We start with an expiry that falls within our default
					// expiration window (70 seconds) but will also be valid if
					// we tick the clock forward a minute. That way we don't
					// have a race condition on scheduler startup.
					tok.RefreshToken = "refresh"
					tok.Expiry = clk.Now().Add(65 * time.Second)
				}

				refreshed <- tok.AccessToken
				return nil
			},
		),
	}

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithAuthCodeExchange(client, testutil.RestrictMockAuthCodeExchange(exchanges))))

	storage := &logical.InmemStorage{}

	b, err := backend.New(backend.Options{
		ProviderRegistry: pr,
		Clock: clock.NewTimerCallbackClock(
			k8sext.NewClock(clk),
			func(d time.Duration) {
				// Stepping the clock every time a timer is created or reset
				// guarantees that the normally-delayed timer will immediately
				// retry over and over.
				clk.Step(d)
			},
		),
	})
	require.NoError(t, err)
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{StorageView: storage}))
	require.NoError(t, b.Initialize(ctx, &logical.InitializationRequest{Storage: storage}))
	defer b.Cleanup(ctx)

	// Write server configuration.
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ServersPathPrefix + `mock`,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     client.ID,
			"client_secret": client.Secret,
			"provider":      "mock",
		},
	}

	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Write our credentials.
	for code := range exchanges {
		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      backend.CredsPathPrefix + code,
			Storage:   storage,
			Data: map[string]interface{}{
				"server": "mock",
				"code":   code,
			},
		}

		resp, err = b.HandleRequest(ctx, req)
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
		require.Nil(t, resp)
	}

	// Since our refresher is now firing indiscriminately, we just need to
	// allocate a bucket of potential iteration values. We should get two
	// initial step values (1) and one refresh value (2).
	var values []string
	for i := 0; i < 3; i++ {
		select {
		case tok := <-refreshed:
			values = append(values, tok)
		case <-ctx.Done():
			require.Fail(t, "context expired waiting for tokens")
		}
	}

	require.ElementsMatch(t, []string{"second_1", "third_1", "third_2"}, values)
}

func TestTuneRefreshCheckInterval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	sig := make(chan string, 1)
	exchange := testutil.AmendTokenMockAuthCodeExchange(
		testutil.IncrementMockAuthCodeExchange("tok_"),
		func(tok *provider.Token) error {
			switch tok.AccessToken {
			case "tok_1":
				tok.RefreshToken = "long"
				tok.Expiry = time.Now().Add(12 * time.Hour)
			case "tok_2":
				tok.RefreshToken = "short"
				tok.Expiry = time.Now().Add(5 * time.Second)
			case "tok_3":
				tok.RefreshToken = "medium"
				tok.Expiry = time.Now().Add(30 * time.Second)
			}

			select {
			case sig <- tok.AccessToken:
			case <-ctx.Done():
				require.Fail(t, "context expired waiting for test")
			}
			return nil
		},
	)

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(testutil.MockWithAuthCodeExchange(client, exchange)))

	storage := &logical.InmemStorage{}

	b, err := backend.New(backend.Options{ProviderRegistry: pr})
	require.NoError(t, err)
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{StorageView: storage}))
	require.NoError(t, b.Initialize(ctx, &logical.InitializationRequest{Storage: storage}))
	defer b.Cleanup(ctx)

	// Write server configuration.
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ServersPathPrefix + `mock`,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     client.ID,
			"client_secret": client.Secret,
			"provider":      "mock",
		},
	}

	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	configure := func(checkInterval time.Duration) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      backend.ConfigPath,
			Storage:   storage,
			Data: map[string]interface{}{
				"tune_refresh_check_interval_seconds": checkInterval.String(),
			},
		}

		resp, err := b.HandleRequest(ctx, req)
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
		require.Nil(t, resp)
	}

	// Write initial configuration.
	configure(time.Minute)

	// Write credential.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.CredsPathPrefix + "test",
		Storage:   storage,
		Data: map[string]interface{}{
			"server": "mock",
			"code":   "test",
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	select {
	case tok := <-sig:
		require.Equal(t, "tok_1", tok)
	case <-ctx.Done():
		require.Fail(t, "context expired waiting for token issuance")
	}

	// Reconfigure with a very long refresh interval, which should trigger a
	// restart of the underlying descriptor.
	configure(24 * time.Hour)

	select {
	case tok := <-sig:
		require.Equal(t, "tok_2", tok)
	case <-ctx.Done():
		require.Fail(t, "context expired waiting for token refresh for token #2")
	}

	// Disable the refresher altogether. Now reading the token should be the
	// only way to cause it to refresh.
	configure(0)

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      backend.CredsPathPrefix + "test",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Error())
	require.Equal(t, "tok_3", resp.Data["access_token"])

	select {
	case tok := <-sig:
		require.Equal(t, "tok_3", tok)
	case <-ctx.Done():
		require.Fail(t, "context expired waiting for token refresh for token #3")
	}

	// Writing a new configuration should restart the descriptor again.
	configure(time.Minute)

	select {
	case tok := <-sig:
		require.Equal(t, "tok_4", tok)
	case <-ctx.Done():
		require.Fail(t, "context expired waiting for token refresh for token #4")
	}
}

func TestMinimumSeconds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	authCodeExchanges := map[string]testutil.MockAuthCodeExchangeFunc{
		"first": testutil.StaticMockAuthCodeExchange(
			&provider.Token{
				Token: &oauth2.Token{
					AccessToken: "first",
				},
			},
		),
		"second": testutil.RefreshableMockAuthCodeExchange(
			testutil.IncrementMockAuthCodeExchange("second_"),
			func(i int) (time.Duration, error) {
				// add 30 seconds for each subsequent read
				return (70 + time.Duration(i)*30) * time.Second, nil
			},
		),
	}
	tokenExchanges := map[string]testutil.MockTokenExchangeFunc{
		// use same names as above to re-use the refresh tokens
		"first": testutil.StaticMockTokenExchange(
			&provider.Token{
				Token: &oauth2.Token{
					AccessToken: "first",
				},
			},
		),
		"second": testutil.ExpiringMockTokenExchangeStep(
			testutil.IncrementMockTokenExchange("second_"),
			func(i int) (time.Duration, error) {
				// add 30 seconds for each subsequent read
				return (70 + time.Duration(i)*30) * time.Second, nil
			},
		),
	}

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(
		testutil.MockWithAuthCodeExchange(client,
			testutil.RestrictMockAuthCodeExchange(authCodeExchanges)),
		testutil.MockWithTokenExchange(client,
			testutil.RestrictMockTokenExchange(tokenExchanges)),
	))

	storage := &logical.InmemStorage{}

	b, err := backend.New(backend.Options{
		ProviderRegistry: pr,
	})
	require.NoError(t, err)
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{StorageView: storage}))
	defer b.Cleanup(ctx)

	// Write server configuration.
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ServersPathPrefix + `mock`,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     client.ID,
			"client_secret": client.Secret,
			"provider":      "mock",
		},
	}

	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Write our credentials.
	for code := range authCodeExchanges {
		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      backend.CredsPathPrefix + code,
			Storage:   storage,
			Data: map[string]interface{}{
				"server": "mock",
				"code":   code,
			},
		}

		resp, err = b.HandleRequest(ctx, req)
		require.NoError(t, err)
		require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
		require.Nil(t, resp)
	}
	for code := range tokenExchanges {
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      backend.STSPathPrefix + code,
			Storage:   storage,
		}

		resp, err = b.HandleRequest(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
		require.True(t, len(resp.Warnings) == 0)
	}

	tokens := make(map[string]string)
	tests := []struct {
		Name                string
		Token               string
		Data                map[string]interface{}
		ExpectedAccessToken func() string
		ExpectedExpireTime  bool
		ExpectedError       string
	}{
		{
			Name:  "first",
			Token: "first",
		},
		{
			Name:                "make sure minimum_seconds added to first does not generate new token",
			Token:               "first",
			Data:                map[string]interface{}{"minimum_seconds": "10"},
			ExpectedAccessToken: func() string { return tokens["first"] },
		},
		// The initial token will be issued at +100s (70 seconds + 30 seconds),
		// so we force a refresh with a requirement of +110s.
		{
			Name:                "second initial",
			Token:               "second",
			Data:                map[string]interface{}{"minimum_seconds": "110"},
			ExpectedAccessToken: func() string { return "second_2" },
			ExpectedExpireTime:  true,
		},
		// The token should now be issued for +130s, so asking for anything
		// under that should let us keep the token as-is.
		{
			Name:                "test minimum_seconds less than the expiry of the second token",
			Token:               "second",
			Data:                map[string]interface{}{"minimum_seconds": "120"},
			ExpectedAccessToken: func() string { return "second_2" },
			ExpectedExpireTime:  true,
		},
		// If we ask for +140s (> +130s), we should get another refresh to +160s.
		{
			Name:                "test minimum_seconds more than the expiry of the second token",
			Token:               "second",
			Data:                map[string]interface{}{"minimum_seconds": "140"},
			ExpectedAccessToken: func() string { return "second_3" },
			ExpectedExpireTime:  true,
		},
		// Finally, if we ask for something outside the range of what is issued,
		// we'll just get an error.
		{
			Name:          "verify that second is marked expired if new token is less than request",
			Token:         "second",
			Data:          map[string]interface{}{"minimum_seconds": "200"},
			ExpectedError: "token expired",
		},
	}

	prefixes := []string{backend.CredsPathPrefix, backend.STSPathPrefix}
	for _, prefix := range prefixes {
		pfx := strings.ReplaceAll(prefix, "/", "")
		for _, test := range tests {
			t.Run(pfx+" "+test.Name, func(t *testing.T) {
				req := &logical.Request{
					Operation: logical.ReadOperation,
					Path:      prefix + test.Token,
					Storage:   storage,
					Data:      test.Data,
				}

				resp, err := b.HandleRequest(ctx, req)
				require.NoError(t, err)
				require.NotNil(t, resp)
				if test.ExpectedError != "" {
					require.True(t, resp.IsError())
					require.EqualError(t, resp.Error(), test.ExpectedError)
				} else {
					require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
					require.Equal(t, test.ExpectedExpireTime, resp.Data["expire_time"] != nil)

					if test.ExpectedAccessToken != nil {
						require.Equal(t, test.ExpectedAccessToken(), resp.Data["access_token"])
					} else {
						require.NotEmpty(t, resp.Data["access_token"])
					}

					tokens[test.Token] = resp.Data["access_token"].(string)
				}
			})
		}
	}
}

func TestServerDeletedFromUnderCred(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client1 := testutil.MockClient{
		ID:     "abc",
		Secret: "def",
	}

	client2 := testutil.MockClient{
		ID:     "123",
		Secret: "456",
	}

	clk := testclock.NewFakeClock(time.Now())

	expire := func(delegate testutil.MockAuthCodeExchangeFunc) testutil.MockAuthCodeExchangeFunc {
		return testutil.AmendTokenMockAuthCodeExchange(delegate, func(t *provider.Token) error {
			t.RefreshToken = "test"
			t.Expiry = clk.Now().Add(30 * time.Second)
			return nil
		})
	}

	pr := provider.NewRegistry()
	pr.MustRegister("mock", testutil.MockFactory(
		testutil.MockWithAuthCodeExchange(client1, expire(testutil.IncrementMockAuthCodeExchange("client1_"))),
		testutil.MockWithAuthCodeExchange(client2, expire(testutil.IncrementMockAuthCodeExchange("client2_"))),
	))

	storage := &logical.InmemStorage{}

	b, err := backend.New(backend.Options{
		ProviderRegistry: pr,
		Clock:            k8sext.NewClock(clk),
	})
	require.NoError(t, err)
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{StorageView: storage}))
	require.NoError(t, b.Initialize(ctx, &logical.InitializationRequest{Storage: storage}))
	defer b.Cleanup(ctx)

	// Write global configuratio to turn off the reaper for creds without
	// servers, which could fire since we're rapidly incrementing the clock.
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ConfigPath,
		Storage:   storage,
		Data: map[string]interface{}{
			"tune_reap_server_deleted_seconds": 0,
		},
	}

	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Write server configuration.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ServersPathPrefix + `mock`,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     client1.ID,
			"client_secret": client1.Secret,
			"provider":      "mock",
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Write a credential.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.CredsPathPrefix + `test`,
		Storage:   storage,
		Data: map[string]interface{}{
			"server": "mock",
			"code":   "test",
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Now the token should be valid.
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      backend.CredsPathPrefix + `test`,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
	require.Contains(t, resp.Data["access_token"], "client1_")

	// Delete the server.
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      backend.ServersPathPrefix + `mock`,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Force the refresher to run.
	clk.Step(time.Minute)

	// The token should expire, and we should see a warning about the server
	// configuration.
	require.NoError(t, retry.Wait(ctx, func(ctx context.Context) (bool, error) {
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      backend.CredsPathPrefix + `test`,
			Storage:   storage,
		}

		resp, err = b.HandleRequest(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		if !resp.IsError() {
			return retry.Repeat(fmt.Errorf("token still valid"))
		}
		require.EqualError(t, resp.Error(), fmt.Sprintf(`server "mock" has configuration problems: %s`, backend.ErrNoSuchServer))

		return retry.Done(nil)
	}))

	// Put the server back.
	req = &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      backend.ServersPathPrefix + `mock`,
		Storage:   storage,
		Data: map[string]interface{}{
			"client_id":     client2.ID,
			"client_secret": client2.Secret,
			"provider":      "mock",
		},
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.False(t, resp != nil && resp.IsError(), "response has error: %+v", resp.Error())
	require.Nil(t, resp)

	// Now the credential should become available again.
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      backend.CredsPathPrefix + `test`,
		Storage:   storage,
	}

	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "response has error: %+v", resp.Error())
	require.Contains(t, resp.Data["access_token"], "client2_")
}
