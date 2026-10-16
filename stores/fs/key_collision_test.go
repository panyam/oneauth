package fs

// The FS identity and channel stores turn a key into a file name, and two
// different keys can map to the same name (filepath.Base drops everything up
// to the last "/", safeName folds "/", "\" and ":" into "_"). A record found
// under someone else's key must never be returned or overwritten.
//
// See: https://cwe.mitre.org/data/definitions/706.html
// See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/accounts"
)

func TestFSIdentityStore_CollidingValueNeverReachesAnotherIdentity(t *testing.T) {
	ctx := context.Background()
	s := NewFSIdentityStore(t.TempDir())
	_, err := s.SaveIdentity(ctx, &accounts.SaveIdentityRequest{Identity: &accounts.Identity{Type: "email", Value: "victim@example.com", UserID: "victim", Verified: true}})
	require.NoError(t, err)

	// "email:" + "x/email:victim@example.com" has the victim's key as its base name.
	resp, err := s.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: "email", IdentityValue: "x/email:victim@example.com", CreateIfMissing: true})
	if err == nil {
		assert.NotEqual(t, "victim", resp.Identity.UserID, "the crafted value read the victim's identity")
	}
	_, err = s.SaveIdentity(ctx, &accounts.SaveIdentityRequest{Identity: &accounts.Identity{Type: "email", Value: "x/email:victim@example.com", UserID: "attacker"}})
	assert.Error(t, err, "saving the crafted value would overwrite the victim's identity")

	got, err := s.GetIdentity(ctx, &accounts.GetIdentityRequest{IdentityType: "email", IdentityValue: "victim@example.com"})
	require.NoError(t, err)
	assert.Equal(t, "victim", got.Identity.UserID, "the victim's identity is untouched")
}

func TestFSChannelStore_CollidingKeyNeverReachesAnotherChannel(t *testing.T) {
	ctx := context.Background()
	s := NewFSChannelStore(t.TempDir())
	_, err := s.SaveChannel(ctx, &accounts.SaveChannelRequest{Channel: &accounts.Channel{Provider: "local", IdentityKey: "email:a_b@example.com", Credentials: map[string]any{"password_hash": "victim-hash"}}})
	require.NoError(t, err)

	// "a:b" and "a_b" fold to the same file name.
	resp, err := s.GetChannel(ctx, &accounts.GetChannelRequest{Provider: "local", IdentityKey: "email:a:b@example.com"})
	if err == nil && resp.Channel != nil {
		assert.NotEqual(t, "victim-hash", resp.Channel.Credentials["password_hash"], "another key's channel, credentials included")
	}
	_, err = s.SaveChannel(ctx, &accounts.SaveChannelRequest{Channel: &accounts.Channel{Provider: "local", IdentityKey: "email:a:b@example.com", Credentials: map[string]any{"password_hash": "attacker-hash"}}})
	assert.Error(t, err, "saving would overwrite another key's channel")

	got, err := s.GetChannel(ctx, &accounts.GetChannelRequest{Provider: "local", IdentityKey: "email:a_b@example.com"})
	require.NoError(t, err)
	assert.Equal(t, "victim-hash", got.Channel.Credentials["password_hash"])
}
