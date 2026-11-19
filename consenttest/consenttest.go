// Package consenttest provides the shared contract test suite for every
// core.ConsentStore implementation. Each backend hands RunAll a Factory,
// so memory, FS, GORM and GAE answer the same questions about replacing a
// grant, keeping one grant per user and client, and returning copies.
// Mirrors the partest and authcodetest precedents.
package consenttest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/core"
)

// Backend is the per-scenario fixture. Reopen returns a fresh handle over
// the same storage, so RestartPersists can simulate a process restart.
// In-memory backends return the same instance.
type Backend struct {
	Store  core.ConsentStore
	Reopen func() core.ConsentStore
}

// Factory creates a Backend per scenario. Persistent backends must close
// over per-test state (a *gorm.DB, a tempdir, a namespace).
type Factory func(t *testing.T) Backend

// RunAll runs the complete contract suite against factory.
func RunAll(t *testing.T, factory Factory) {
	t.Run("SaveAndGet", func(t *testing.T) { TestSaveAndGet(t, factory) })
	t.Run("NotFound", func(t *testing.T) { TestNotFound(t, factory) })
	t.Run("SaveReplaces", func(t *testing.T) { TestSaveReplaces(t, factory) })
	t.Run("KeyedByUserAndClient", func(t *testing.T) { TestKeyedByUserAndClient(t, factory) })
	t.Run("ExpiredIsReturned", func(t *testing.T) { TestExpiredIsReturned(t, factory) })
	t.Run("RevokeIsIdempotent", func(t *testing.T) { TestRevokeIsIdempotent(t, factory) })
	t.Run("ReturnsCopies", func(t *testing.T) { TestReturnsCopies(t, factory) })
	t.Run("RestartPersists", func(t *testing.T) { TestRestartPersists(t, factory) })
	t.Run("RefusesAnEmptyKey", func(t *testing.T) { TestRefusesAnEmptyKey(t, factory) })
}

func grant(subject, clientID string, scopes ...string) *core.ConsentGrant {
	now := time.Now().UTC().Truncate(time.Second)
	return &core.ConsentGrant{
		Subject:   subject,
		ClientID:  clientID,
		Scopes:    scopes,
		GrantedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
}

func get(t *testing.T, s core.ConsentStore, subject, clientID string) *core.ConsentGrant {
	t.Helper()
	resp, err := s.GetConsent(context.Background(), &core.GetConsentRequest{Subject: subject, ClientID: clientID})
	require.NoError(t, err)
	require.NotNil(t, resp.Grant)
	return resp.Grant
}

func save(t *testing.T, s core.ConsentStore, g *core.ConsentGrant) {
	t.Helper()
	_, err := s.SaveConsent(context.Background(), &core.SaveConsentRequest{Grant: g})
	require.NoError(t, err)
}

// TestSaveAndGet stores a grant and reads every field back.
func TestSaveAndGet(t *testing.T, factory Factory) {
	b := factory(t)
	want := grant("user-1", "client-x", "openid", "email")
	save(t, b.Store, want)

	got := get(t, b.Store, "user-1", "client-x")
	assert.Equal(t, want.Subject, got.Subject)
	assert.Equal(t, want.ClientID, got.ClientID)
	assert.Equal(t, want.Scopes, got.Scopes)
	assert.True(t, want.GrantedAt.Equal(got.GrantedAt), "GrantedAt %v, got %v", want.GrantedAt, got.GrantedAt)
	assert.True(t, want.ExpiresAt.Equal(got.ExpiresAt), "ExpiresAt %v, got %v", want.ExpiresAt, got.ExpiresAt)
}

// TestNotFound: a user with no grant gets ErrConsentNotFound, not an
// empty grant, so a backend can't make "never asked" look like "asked for
// nothing".
func TestNotFound(t *testing.T, factory Factory) {
	b := factory(t)
	_, err := b.Store.GetConsent(context.Background(), &core.GetConsentRequest{Subject: "nobody", ClientID: "client-x"})
	assert.True(t, errors.Is(err, core.ErrConsentNotFound), "got %v", err)
}

// TestSaveReplaces: a second save for the same user and client replaces
// the first. The caller merges scopes, not the store.
func TestSaveReplaces(t *testing.T, factory Factory) {
	b := factory(t)
	save(t, b.Store, grant("user-1", "client-x", "openid", "email"))
	save(t, b.Store, grant("user-1", "client-x", "openid"))
	assert.Equal(t, []string{"openid"}, get(t, b.Store, "user-1", "client-x").Scopes)
}

// TestKeyedByUserAndClient: a grant to one client says nothing about
// another, and one user's grant says nothing about another user.
func TestKeyedByUserAndClient(t *testing.T, factory Factory) {
	b := factory(t)
	save(t, b.Store, grant("user-1", "client-x", "openid"))
	save(t, b.Store, grant("user-1", "client-y", "email"))
	save(t, b.Store, grant("user-2", "client-x", "profile"))

	assert.Equal(t, []string{"openid"}, get(t, b.Store, "user-1", "client-x").Scopes)
	assert.Equal(t, []string{"email"}, get(t, b.Store, "user-1", "client-y").Scopes)
	assert.Equal(t, []string{"profile"}, get(t, b.Store, "user-2", "client-x").Scopes)
	_, err := b.Store.GetConsent(context.Background(), &core.GetConsentRequest{Subject: "user-2", ClientID: "client-y"})
	assert.True(t, errors.Is(err, core.ErrConsentNotFound), "got %v", err)
}

// TestExpiredIsReturned: the store returns an expired grant and leaves the
// decision to Covers.
func TestExpiredIsReturned(t *testing.T, factory Factory) {
	b := factory(t)
	g := grant("user-1", "client-x", "openid")
	g.GrantedAt = g.GrantedAt.Add(-2 * time.Hour)
	g.ExpiresAt = g.GrantedAt.Add(time.Hour)
	save(t, b.Store, g)

	got := get(t, b.Store, "user-1", "client-x")
	assert.True(t, got.IsExpired(time.Now()))
	assert.False(t, got.Covers([]string{"openid"}, time.Now()))
}

// TestRevokeIsIdempotent: revoking removes the grant, and revoking again,
// or revoking what was never there, is not an error.
func TestRevokeIsIdempotent(t *testing.T, factory Factory) {
	b := factory(t)
	ctx := context.Background()
	save(t, b.Store, grant("user-1", "client-x", "openid"))
	for i := 0; i < 2; i++ {
		_, err := b.Store.RevokeConsent(ctx, &core.RevokeConsentRequest{Subject: "user-1", ClientID: "client-x"})
		require.NoError(t, err, "revoke #%d", i+1)
	}
	_, err := b.Store.GetConsent(ctx, &core.GetConsentRequest{Subject: "user-1", ClientID: "client-x"})
	assert.True(t, errors.Is(err, core.ErrConsentNotFound), "got %v", err)
}

// TestReturnsCopies: changing a grant after saving it, or changing what
// GetConsent returned, doesn't change the stored grant.
func TestReturnsCopies(t *testing.T, factory Factory) {
	b := factory(t)
	g := grant("user-1", "client-x", "openid", "email")
	save(t, b.Store, g)
	g.Scopes[0] = "admin"

	got := get(t, b.Store, "user-1", "client-x")
	got.Scopes[1] = "admin"
	assert.Equal(t, []string{"openid", "email"}, get(t, b.Store, "user-1", "client-x").Scopes)
}

// TestRestartPersists: a grant survives reopening the store.
func TestRestartPersists(t *testing.T, factory Factory) {
	b := factory(t)
	save(t, b.Store, grant("user-1", "client-x", "openid"))
	assert.Equal(t, []string{"openid"}, get(t, b.Reopen(), "user-1", "client-x").Scopes)
}

// TestRefusesAnEmptyKey: a grant without a subject or client can't be
// stored, so a caller bug can't create a grant that covers every user or
// every client.
func TestRefusesAnEmptyKey(t *testing.T, factory Factory) {
	b := factory(t)
	ctx := context.Background()
	for _, g := range []*core.ConsentGrant{nil, grant("", "client-x", "openid"), grant("user-1", "", "openid")} {
		_, err := b.Store.SaveConsent(ctx, &core.SaveConsentRequest{Grant: g})
		assert.Error(t, err, "grant %+v", g)
	}
}
