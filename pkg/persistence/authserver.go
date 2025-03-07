package persistence

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/openbao/openbao-plugin-secrets-oauthapp/v3/pkg/vaultext"
)

const (
	authServerKeyPrefix = "servers/"
)

type AuthServerKeyer interface {
	// AuthServerKey returns the storage key for storing AuthServerEntry
	// objects.
	AuthServerKey() string
}

type AuthServerEntry struct {
	Name string `json:"name"`

	ClientID        string            `json:"client_id"`
	ClientSecrets   []string          `json:"client_secrets"`
	AuthURLParams   map[string]string `json:"auth_url_params"`
	ProviderName    string            `json:"provider_name"`
	ProviderVersion int               `json:"provider_version"`
	ProviderOptions map[string]string `json:"provider_options"`
}

// UPGRADING (v2): LegacyAuthServerName is the name of the default server
// created by the v2v3 upgrade.
const LegacyAuthServerName = "legacy"

type AuthServerKey string

var _ AuthServerKeyer = AuthServerKey("")

func (ack AuthServerKey) AuthServerKey() string { return authServerKeyPrefix + string(ack) }

func AuthServerName(name string) AuthServerKeyer {
	hash := sha256.Sum224([]byte(name))
	first, second, rest := hash[:2], hash[2:4], hash[4:]
	return AuthServerKey(fmt.Sprintf("%x/%x/%x", first, second, rest))
}

func AuthServerKeyFromStorage(key string) (AuthServerKeyer, bool) {
	if !strings.HasPrefix(key, authServerKeyPrefix) {
		return nil, false
	}

	return AuthServerKey(key[len(authServerKeyPrefix):]), true
}

type LockedAuthServerManager struct {
	storage logical.Storage
	keyer   AuthServerKeyer
}

func (lasm *LockedAuthServerManager) ReadAuthServerEntry(ctx context.Context) (*AuthServerEntry, error) {
	se, err := lasm.storage.Get(ctx, lasm.keyer.AuthServerKey())
	if err != nil {
		return nil, err
	} else if se == nil {
		return nil, nil
	}

	entry := &AuthServerEntry{}
	if err := se.DecodeJSON(entry); err != nil {
		return nil, err
	}

	// UPGRADING (v3.0.0-beta.{1,2,3,4}): Early v3 versions only supported a
	// single client secret for a server, so we check for it here and copy it
	// into the returned value if necessary.
	var migrating struct {
		ClientSecret string `json:"client_secret"`
	}
	if err := se.DecodeJSON(&migrating); err != nil {
		return nil, err
	}

	if migrating.ClientSecret != "" {
		entry.ClientSecrets = append([]string{migrating.ClientSecret}, entry.ClientSecrets...)
	}

	return entry, nil
}

func (lasm *LockedAuthServerManager) WriteAuthServerEntry(ctx context.Context, entry *AuthServerEntry) error {
	key := lasm.keyer.AuthServerKey()

	// Sanity check: constructing the key from the name specified in the entry
	// must equal the key we're using for this operation.
	if AuthServerName(entry.Name).AuthServerKey() != key {
		return fmt.Errorf("writing authorization server: name %q does not correspond to storage key", entry.Name)
	}

	se, err := logical.StorageEntryJSON(key, entry)
	if err != nil {
		return err
	}

	return lasm.storage.Put(ctx, se)
}

func (lasm *LockedAuthServerManager) DeleteAuthServerEntry(ctx context.Context) error {
	return lasm.storage.Delete(ctx, lasm.keyer.AuthServerKey())
}

type LockedAuthServerHolder struct {
	keyer AuthServerKeyer
}

func (lash *LockedAuthServerHolder) Manager(storage logical.Storage) *LockedAuthServerManager {
	return &LockedAuthServerManager{
		storage: storage,
		keyer:   lash.keyer,
	}
}

type AuthServerLocker interface {
	WithLock(AuthServerKeyer, func(*LockedAuthServerHolder) error) error
}

type AuthServerManager struct {
	storage logical.Storage
	locker  AuthServerLocker
}

func (asm *AuthServerManager) ReadAuthServerEntry(ctx context.Context, keyer AuthServerKeyer) (*AuthServerEntry, error) {
	var entry *AuthServerEntry
	err := asm.locker.WithLock(keyer, func(lash *LockedAuthServerHolder) (err error) {
		entry, err = lash.Manager(asm.storage).ReadAuthServerEntry(ctx)
		return
	})
	return entry, err
}

func (asm *AuthServerManager) WriteAuthServerEntry(ctx context.Context, keyer AuthServerKeyer, entry *AuthServerEntry) error {
	return asm.locker.WithLock(keyer, func(lash *LockedAuthServerHolder) error {
		return lash.Manager(asm.storage).WriteAuthServerEntry(ctx, entry)
	})
}

func (asm *AuthServerManager) DeleteAuthServerEntry(ctx context.Context, keyer AuthServerKeyer) error {
	return asm.locker.WithLock(keyer, func(lash *LockedAuthServerHolder) error {
		return lash.Manager(asm.storage).DeleteAuthServerEntry(ctx)
	})
}

func (asm *AuthServerManager) ForEachAuthServerKey(ctx context.Context, fn func(AuthServerKeyer) error) error {
	view := logical.NewStorageView(asm.storage, authServerKeyPrefix)
	return vaultext.ScanView(ctx, view, func(path string) error { return fn(AuthServerKey(path)) })
}

type AuthServerHolder struct {
	locks []*locksutil.LockEntry
}

func (ash *AuthServerHolder) WithLock(keyer AuthServerKeyer, fn func(*LockedAuthServerHolder) error) error {
	lock := locksutil.LockForKey(ash.locks, keyer.AuthServerKey())
	lock.Lock()
	defer lock.Unlock()

	return fn(&LockedAuthServerHolder{
		keyer: keyer,
	})
}

func (ash *AuthServerHolder) Manager(storage logical.Storage) *AuthServerManager {
	return &AuthServerManager{
		storage: storage,
		locker:  ash,
	}
}
