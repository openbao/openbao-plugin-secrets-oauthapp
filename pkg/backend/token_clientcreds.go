package backend

import (
	"context"
	"fmt"
	"time"

	"github.com/openbao/openbao-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/openbao/openbao-plugin-secrets-oauthapp/v3/pkg/provider"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/leg/timeutil/pkg/clockctx"
)

func (b *backend) updateClientCredsToken(ctx context.Context, storage logical.Storage, keyer persistence.ClientCredsKeyer, expiryDelta time.Duration) (*persistence.ClientCredsEntry, error) {
	ctx = clockctx.WithClock(ctx, b.clock)

	var entry *persistence.ClientCredsEntry
	err := b.data.ClientCreds.WithLock(keyer, func(ch *persistence.LockedClientCredsHolder) error {
		cm := ch.Manager(storage)

		// In case someone else updated this token from under us, we'll re-request
		// it here with the lock acquired.
		candidate, err := cm.ReadClientCredsEntry(ctx)
		switch {
		case err != nil || candidate == nil:
			return err
		case b.tokenValid(candidate.Token.Token, expiryDelta):
			entry = candidate
			return nil
		}

		ops, put, err := b.getProviderOperations(ctx, storage, persistence.AuthServerName(candidate.AuthServerName), expiryDelta)
		if errmark.MarkedUser(err) {
			return fmt.Errorf("server %q has configuration problems: %w", candidate.AuthServerName, err)
		} else if err != nil {
			return err
		}
		defer put()

		updated, err := ops.ClientCredentials(
			ctx,
			provider.WithURLParams(candidate.Config.TokenURLParams),
			provider.WithScopes(candidate.Config.Scopes),
			provider.WithProviderOptions(candidate.Config.ProviderOptions),
		)
		if err != nil {
			return err
		}

		// Store the new creds.
		candidate.SetToken(ctx, updated)

		if err := cm.WriteClientCredsEntry(ctx, candidate); err != nil {
			return err
		}

		entry = candidate
		return nil
	})
	return entry, err
}

func (b *backend) getUpdateClientCredsToken(ctx context.Context, storage logical.Storage, keyer persistence.ClientCredsKeyer, expiryDelta time.Duration) (*persistence.ClientCredsEntry, error) {
	entry, err := b.data.ClientCreds.Manager(storage).ReadClientCredsEntry(ctx, keyer)
	switch {
	case err != nil:
		return nil, err
	case entry != nil && b.tokenValid(entry.Token.Token, expiryDelta):
		return entry, nil
	default:
		return b.updateClientCredsToken(ctx, storage, keyer, expiryDelta)
	}
}
