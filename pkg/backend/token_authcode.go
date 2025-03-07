package backend

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/openbao/openbao-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/openbao/openbao-plugin-secrets-oauthapp/v3/pkg/provider"
	"github.com/puppetlabs/leg/errmap/pkg/errmap"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/leg/scheduler"
	"github.com/puppetlabs/leg/timeutil/pkg/backoff"
	"github.com/puppetlabs/leg/timeutil/pkg/clockctx"
	"github.com/puppetlabs/leg/timeutil/pkg/retry"
	"golang.org/x/oauth2"
)

type refreshProcess struct {
	backend     *backend
	storage     logical.Storage
	keyer       persistence.AuthCodeKeyer
	expiryDelta time.Duration
}

var _ scheduler.Process = &refreshProcess{}

func (rp *refreshProcess) Description() string {
	return fmt.Sprintf("credential refresh (%s)", rp.keyer.AuthCodeKey())
}

func (rp *refreshProcess) Run(ctx context.Context) error {
	_, err := rp.backend.getRefreshCredToken(ctx, rp.storage, rp.keyer, rp.expiryDelta)
	return err
}

type refreshDescriptor struct {
	backend *backend
	storage logical.Storage
}

var _ scheduler.Descriptor = &refreshDescriptor{}

func (rd *refreshDescriptor) Run(ctx context.Context, pc chan<- scheduler.Process) error {
	tuning := persistence.DefaultConfigTuningEntry

	if cfg, err := rd.backend.cache.Config.Get(ctx, rd.storage); err != nil {
		return err
	} else if cfg != nil {
		tuning = cfg.Tuning
	}

	if tuning.RefreshCheckIntervalSeconds <= 0 {
		return nil
	}

	refreshInterval := time.Duration(tuning.RefreshCheckIntervalSeconds) * time.Second

	expiryDeltaSeconds := float64(tuning.RefreshCheckIntervalSeconds) * tuning.RefreshExpiryDeltaFactor
	if lim := float64(math.MaxInt64 / time.Second); expiryDeltaSeconds > lim {
		expiryDeltaSeconds = lim
	}

	b := backoff.Build(
		backoff.Constant(refreshInterval),
		backoff.NonSliding,
	)
	err := retry.Wait(ctx, func(ctx context.Context) (bool, error) {
		rd.backend.Logger().Debug("running automatic credential refresh")

		err := rd.backend.data.AuthCode.Manager(rd.storage).ForEachAuthCodeKey(ctx, func(keyer persistence.AuthCodeKeyer) error {
			proc := &refreshProcess{
				backend:     rd.backend,
				storage:     rd.storage,
				keyer:       keyer,
				expiryDelta: time.Duration(expiryDeltaSeconds) * time.Second,
			}

			select {
			case pc <- proc:
			case <-ctx.Done():
			}

			return nil
		})
		if err != nil {
			return retry.Done(err)
		}

		return retry.Repeat(nil)
	}, retry.WithClock(rd.backend.clock), retry.WithBackoffFactory(b))
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

func (b *backend) refreshCredToken(ctx context.Context, storage logical.Storage, keyer persistence.AuthCodeKeyer, expiryDelta time.Duration) (*persistence.AuthCodeEntry, error) {
	ctx = clockctx.WithClock(ctx, b.clock)

	var entry *persistence.AuthCodeEntry
	err := b.data.AuthCode.WithLock(keyer, func(ach *persistence.LockedAuthCodeHolder) error {
		acm := ach.Manager(storage)

		// In case someone else refreshed this token from under us, we'll re-request
		// it here with the lock acquired.
		candidate, err := acm.ReadAuthCodeEntry(ctx)
		switch {
		case err != nil || candidate == nil:
			return err
		case !candidate.TokenIssued() || b.tokenValid(candidate.Token.Token, expiryDelta) || candidate.RefreshToken == "":
			entry = candidate
			return nil
		}

		ops, put, err := b.getProviderOperations(ctx, storage, persistence.AuthServerName(candidate.AuthServerName), expiryDelta)
		if errmark.MarkedUser(err) {
			candidate.SetAuthServerError(ctx, errmark.MarkShort(err).Error())
		} else if err != nil {
			return err
		} else {
			defer put()

			// Refresh.
			refreshed, err := ops.RefreshToken(ctx, candidate.Token, provider.WithProviderOptions(candidate.ProviderOptions))

			if err != nil {
				msg := errmap.Wrap(errmark.MarkShort(err), "refresh failed").Error()
				if errmark.MarkedUser(err) {
					candidate.SetUserError(ctx, msg)
				} else {
					candidate.SetTransientError(ctx, msg)
				}
			} else {
				candidate.SetToken(ctx, refreshed)
			}
		}

		if err := acm.WriteAuthCodeEntry(ctx, candidate); err != nil {
			return err
		}

		entry = candidate
		return nil
	})
	return entry, err
}

func (b *backend) getRefreshCredToken(ctx context.Context, storage logical.Storage, keyer persistence.AuthCodeKeyer, expiryDelta time.Duration) (*persistence.AuthCodeEntry, error) {
	entry, err := b.data.AuthCode.Manager(storage).ReadAuthCodeEntry(ctx, keyer)
	switch {
	case err != nil:
		return nil, err
	case entry == nil:
		return nil, nil
	case !entry.TokenIssued() || b.tokenValid(entry.Token.Token, expiryDelta):
		return entry, nil
	default:
		return b.refreshCredToken(ctx, storage, keyer, expiryDelta)
	}
}

func (b *backend) storeExchangedToken(ctx context.Context, storage logical.Storage, keyer persistence.AuthCodeKeyer, exchangeKey string, tok *oauth2.Token) error {
	ctx = clockctx.WithClock(ctx, b.clock)

	err := b.data.AuthCode.WithLock(keyer, func(ach *persistence.LockedAuthCodeHolder) error {
		acm := ach.Manager(storage)

		entry, err := acm.ReadAuthCodeEntry(ctx)
		if err != nil || entry == nil {
			return err
		}

		if entry.ExchangedTokens == nil {
			// first time, make the map
			entry.ExchangedTokens = make(map[string]*oauth2.Token)
		} else {
			// remove every expired exchanged token while we're here
			for k, t := range entry.ExchangedTokens {
				if !b.tokenValid(t, defaultExpiryDelta) {
					delete(entry.ExchangedTokens, k)
				}
			}
		}
		entry.ExchangedTokens[exchangeKey] = tok

		if err := acm.WriteAuthCodeEntry(ctx, entry); err != nil {
			return err
		}

		return nil
	})
	return err
}
