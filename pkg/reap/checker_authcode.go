package reap

import (
	"context"
	"fmt"
	"time"

	"github.com/openbao/openbao-plugin-secrets-oauthapp/v3/pkg/persistence"
	"github.com/puppetlabs/leg/timeutil/pkg/clockctx"
)

type AuthCodeChecker struct {
	nonRefreshableTTL      time.Duration
	revokedTTL             time.Duration
	transientErrorAttempts int
	transientErrorTTL      time.Duration
	serverDeletedTTL       time.Duration
}

// Check tests whether the given authorization code entry is still valid. If it
// is, it returns nil. Otherwise, it returns an error indicating the reason the
// entry is not valid.
func (acc *AuthCodeChecker) Check(ctx context.Context, entry *persistence.AuthCodeEntry) error {
	now := clockctx.Clock(ctx).Now()

	// We can get an error before we ever actually issue a token, so for the
	// reference time to check, we'll either use the actual expiry or the last
	// attempted issue time.
	getReferenceTime := func() time.Time {
		if entry.TokenIssued() && !entry.Expiry.IsZero() {
			return entry.Expiry
		}
		return entry.LastAttemptedIssueTime
	}

	switch {
	case entry.UserError != "":
		if acc.revokedTTL <= 0 {
			// We will not take action on this token for the revoked
			// criterion.
			return nil
		}

		if getReferenceTime().Add(acc.revokedTTL).After(now) {
			// Not yet ready to be reaped.
			return nil
		}

		return fmt.Errorf("token revoked: %s", entry.UserError)
	case entry.TransientErrorsSinceLastIssue > 0:
		if acc.transientErrorAttempts <= 0 && acc.transientErrorTTL <= 0 {
			// We will not take action on this token for the transient error
			// criteria.
			return nil
		}

		if entry.TransientErrorsSinceLastIssue < acc.transientErrorAttempts {
			// Haven't met the threshold for transient errors yet.
			return nil
		}

		if getReferenceTime().Add(acc.transientErrorTTL).After(now) {
			// Not yet ready to be reaped.
			return nil
		}

		return fmt.Errorf("transient errors exceeded limits, most recently: %s", entry.LastTransientError)
	case entry.AuthServerError != "":
		if acc.serverDeletedTTL <= 0 {
			// We will not take action on this token if its backing server is
			// deleted. Wait for the server to come back.
			return nil
		}

		if getReferenceTime().Add(acc.serverDeletedTTL).After(now) {
			// Not yet ready to be reaped.
			return nil
		}

		return fmt.Errorf("server %q has configuration problems: %s", entry.AuthServerName, entry.AuthServerError)
	case !entry.TokenIssued():
		// Waiting for a token from an external process (e.g., device code
		// auth). Do nothing.
		return nil
	case entry.Expiry.IsZero():
		// Token never expires.
		return nil
	case entry.RefreshToken != "":
		// Token expires, but it has a valid refresh token.
		return nil
	case acc.nonRefreshableTTL <= 0, entry.Expiry.Add(acc.nonRefreshableTTL).After(now):
		// Token expires, but it is not yet ready to be reaped.
		return nil
	default:
		return fmt.Errorf("token expired")
	}
}

func NewAuthCodeChecker(tuning persistence.ConfigTuningEntry) *AuthCodeChecker {
	return &AuthCodeChecker{
		nonRefreshableTTL:      time.Duration(tuning.ReapNonRefreshableSeconds) * time.Second,
		revokedTTL:             time.Duration(tuning.ReapRevokedSeconds) * time.Second,
		transientErrorAttempts: tuning.ReapTransientErrorAttempts,
		transientErrorTTL:      time.Duration(tuning.ReapTransientErrorSeconds) * time.Second,
		serverDeletedTTL:       time.Duration(tuning.ReapServerDeletedSeconds) * time.Second,
	}
}
