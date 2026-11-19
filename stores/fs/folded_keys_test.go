package fs

// Two keys can map to one file name. safeName folds "/", "\" and ":" into
// "_" on every OS, osFileName folds more on Windows, and a case-insensitive
// file system (Windows, and macOS by default) folds letter case. Every FS
// store keyed by safeName must refuse to read, overwrite or delete a record
// under a key other than its own.
//
// See: https://cwe.mitre.org/data/definitions/706.html
// See: https://github.com/panyam/oneauth/issues/505

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
)

// keyedStore drives one FS store by key. get returns the owner recorded
// with the key, and del is nil for a store with no delete.
type keyedStore struct {
	name string
	put  func(key, owner string) error
	get  func(key string) (string, error)
	del  func(key string) error
}

func keyedStores(t *testing.T) []keyedStore {
	ctx := context.Background()
	users := NewFSUserStore(t.TempDir())
	usernames := NewFSUsernameStore(t.TempDir())
	apps := NewFSAppStore(t.TempDir())
	keyStore := NewFSKeyStore(t.TempDir())
	kids := NewFSKidStore(t.TempDir())
	apiKeys := NewFSAPIKeyStore(t.TempDir())
	return []keyedStore{
		{
			name: "users",
			put: func(k, owner string) error {
				_, err := users.CreateUser(ctx, &accounts.CreateUserRequest{UserID: k, Profile: map[string]any{"owner": owner}})
				return err
			},
			get: func(k string) (string, error) {
				r, err := users.GetUserById(ctx, &accounts.GetUserByIDRequest{UserID: k})
				if err != nil {
					return "", err
				}
				return r.User.Profile()["owner"].(string), nil
			},
		},
		{
			name: "usernames",
			put: func(k, owner string) error {
				_, err := usernames.ReserveUsername(ctx, &accounts.ReserveUsernameRequest{Username: k, UserID: owner})
				return err
			},
			get: func(k string) (string, error) {
				r, err := usernames.GetUserByUsername(ctx, &accounts.GetUserByUsernameRequest{Username: k})
				if err != nil {
					return "", err
				}
				return r.UserID, nil
			},
			del: func(k string) error {
				_, err := usernames.ReleaseUsername(ctx, &accounts.ReleaseUsernameRequest{Username: k})
				return err
			},
		},
		{
			name: "apps",
			put: func(k, owner string) error {
				_, err := apps.SaveApp(ctx, &core.SaveAppRequest{App: &core.AppRegistration{ClientID: k, ClientName: owner}})
				return err
			},
			get: func(k string) (string, error) {
				r, err := apps.GetApp(ctx, &core.GetAppRequest{ClientID: k})
				if err != nil {
					return "", err
				}
				return r.App.ClientName, nil
			},
			del: func(k string) error {
				_, err := apps.DeleteApp(ctx, &core.DeleteAppRequest{ClientID: k})
				return err
			},
		},
		{
			name: "keys",
			put: func(k, owner string) error {
				_, err := keyStore.PutKey(ctx, &keys.PutKeyRequest{Record: &keys.KeyRecord{ClientID: k, Key: []byte(owner), Algorithm: "HS256"}})
				return err
			},
			get: func(k string) (string, error) {
				r, err := keyStore.GetKey(ctx, &keys.GetKeyRequest{ClientID: k})
				if err != nil {
					return "", err
				}
				return string(r.Record.Key.([]byte)), nil
			},
			del: func(k string) error {
				_, err := keyStore.DeleteKey(ctx, &keys.DeleteKeyRequest{ClientID: k})
				return err
			},
		},
		{
			name: "kids",
			put: func(k, owner string) error {
				_, err := kids.Add(ctx, &keys.AddKidRequest{Kid: k, Key: []byte("secret"), Algorithm: "HS256", ClientID: owner})
				return err
			},
			get: func(k string) (string, error) {
				r, err := kids.GetKeyByKid(ctx, &keys.GetKeyByKidRequest{Kid: k})
				if err != nil {
					return "", err
				}
				return r.Record.ClientID, nil
			},
			del: func(k string) error {
				_, err := kids.Remove(ctx, &keys.RemoveKidRequest{Kid: k})
				return err
			},
		},
		{
			name: "apikeys",
			put: func(k, owner string) error {
				return apiKeys.saveKey(&core.APIKey{KeyID: k, Subject: owner})
			},
			get: func(k string) (string, error) {
				r, err := apiKeys.getKeyUnsafe(k)
				if err != nil {
					return "", err
				}
				return r.Subject, nil
			},
		},
	}
}

// checkFoldedKeys stores victim's record, then uses a second key that maps to
// the same file. Each operation on the second key must fail with
// ErrKeyCollision, and the victim's record must survive.
func checkFoldedKeys(t *testing.T, victim, other string) {
	for _, s := range keyedStores(t) {
		t.Run(s.name, func(t *testing.T) {
			require.NoError(t, s.put(victim, "victim"))

			_, err := s.get(other)
			assert.ErrorIs(t, err, ErrKeyCollision, "read under %q", other)
			assert.ErrorIs(t, s.put(other, "attacker"), ErrKeyCollision, "write under %q", other)
			if s.del != nil {
				assert.ErrorIs(t, s.del(other), ErrKeyCollision, "delete under %q", other)
			}

			owner, err := s.get(victim)
			require.NoError(t, err)
			assert.Equal(t, "victim", owner)
		})
	}
}

func TestFolding_SlashAndUnderscoreShareAFile(t *testing.T) {
	checkFoldedKeys(t, "a_b", "a/b")
}

// Runs where the temp dir's file system ignores letter case, which is
// Windows, and macOS by default.
func TestFolding_LetterCaseOnACaseInsensitiveFileSystem(t *testing.T) {
	if !caseInsensitiveTempDir(t) {
		t.Skip("the temp dir's file system is case-sensitive")
	}
	// Usernames are lowercased before they are stored, so the username store
	// sees one key here, and the other stores see two.
	for _, s := range keyedStores(t) {
		if s.name == "usernames" {
			continue
		}
		t.Run(s.name, func(t *testing.T) {
			require.NoError(t, s.put("alice", "victim"))
			_, err := s.get("Alice")
			assert.ErrorIs(t, err, ErrKeyCollision)
			assert.ErrorIs(t, s.put("Alice", "attacker"), ErrKeyCollision)
			owner, err := s.get("alice")
			require.NoError(t, err)
			assert.Equal(t, "victim", owner)
		})
	}
}

func caseInsensitiveTempDir(t *testing.T) bool {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "probe"), nil, 0o600))
	_, err := os.Stat(filepath.Join(dir, strings.ToUpper("probe")))
	return err == nil
}
