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
	t.Run("Lister", func(t *testing.T) { RunLister(t, factory) })
}

// RunLister runs the core.ConsentLister scenarios. RunAll calls it, and
// it skips a store that doesn't implement the optional interface, so a
// custom ConsentStore without listing still passes RunAll. Every bundled
// backend implements it and asserts so at compile time.
func RunLister(t *testing.T, factory Factory) {
	t.Run("ListsOnlyTheSubjectsGrants", func(t *testing.T) { TestListsOnlyTheSubjectsGrants(t, factory) })
	t.Run("ListLeavesOutExpired", func(t *testing.T) { TestListLeavesOutExpired(t, factory) })
	t.Run("ListEmptySubject", func(t *testing.T) { TestListEmptySubject(t, factory) })
	t.Run("ListNoGrants", func(t *testing.T) { TestListNoGrants(t, factory) })
	t.Run("ListAfterRevoke", func(t *testing.T) { TestListAfterRevoke(t, factory) })
	t.Run("ListReturnsCopies", func(t *testing.T) { TestListReturnsCopies(t, factory) })
	t.Run("ListPersists", func(t *testing.T) { TestListPersists(t, factory) })
	t.Run("ListIsSorted", func(t *testing.T) { TestListIsSorted(t, factory) })
}

func lister(t *testing.T, s core.ConsentStore) core.ConsentLister {
	t.Helper()
	l, ok := s.(core.ConsentLister)
	if !ok {
		t.Skipf("%T does not implement core.ConsentLister", s)
	}
	return l
}

func list(t *testing.T, s core.ConsentStore, subject string) []*core.ConsentGrant {
	t.Helper()
	resp, err := lister(t, s).ListConsents(context.Background(), &core.ListConsentsRequest{Subject: subject})
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp.Grants
}

func clientIDs(grants []*core.ConsentGrant) []string {
	out := []string{}
	for _, g := range grants {
		out = append(out, g.ClientID)
	}
	return out
}

// TestListsOnlyTheSubjectsGrants: a user's list holds their grants, by
// client_id, with every field, and nothing another user approved. A
// grant that never expires is listed.
func TestListsOnlyTheSubjectsGrants(t *testing.T, factory Factory) {
	b := factory(t)
	lister(t, b.Store)
	y := grant("user-1", "client-y", "email")
	save(t, b.Store, y)
	forever := grant("user-1", "client-x", "openid", "profile")
	forever.ExpiresAt = time.Time{}
	save(t, b.Store, forever)
	save(t, b.Store, grant("user-2", "client-z", "openid"))
	save(t, b.Store, grant("user-10", "client-w", "openid"))

	got := list(t, b.Store, "user-1")
	require.Equal(t, []string{"client-x", "client-y"}, clientIDs(got), "sorted by client_id")
	for _, g := range got {
		assert.Equal(t, "user-1", g.Subject)
	}
	assert.Equal(t, []string{"openid", "profile"}, got[0].Scopes)
	assert.True(t, got[0].ExpiresAt.IsZero(), "a grant that never expires is listed as such")
	assert.True(t, y.GrantedAt.Equal(got[1].GrantedAt), "GrantedAt %v, got %v", y.GrantedAt, got[1].GrantedAt)
	assert.True(t, y.ExpiresAt.Equal(got[1].ExpiresAt), "ExpiresAt %v, got %v", y.ExpiresAt, got[1].ExpiresAt)
	assert.Equal(t, []string{"client-z"}, clientIDs(list(t, b.Store, "user-2")))
}

// TestListLeavesOutExpired: an expired grant no longer skips the consent
// screen, so it isn't shown as a connected app.
func TestListLeavesOutExpired(t *testing.T, factory Factory) {
	b := factory(t)
	lister(t, b.Store)
	old := grant("user-1", "client-old", "openid")
	old.GrantedAt = old.GrantedAt.Add(-2 * time.Hour)
	old.ExpiresAt = old.GrantedAt.Add(time.Hour)
	save(t, b.Store, old)
	save(t, b.Store, grant("user-1", "client-new", "openid"))
	assert.Equal(t, []string{"client-new"}, clientIDs(list(t, b.Store, "user-1")))
}

// TestListEmptySubject: an empty subject lists nothing, so a caller that
// lost the session's user can't list every user's grants.
func TestListEmptySubject(t *testing.T, factory Factory) {
	b := factory(t)
	lister(t, b.Store)
	save(t, b.Store, grant("user-1", "client-x", "openid"))
	assert.Empty(t, list(t, b.Store, ""))
}

// TestListNoGrants: a user who approved nothing gets an empty list and
// no error.
func TestListNoGrants(t *testing.T, factory Factory) {
	b := factory(t)
	assert.Empty(t, list(t, b.Store, "nobody"))
}

// TestListAfterRevoke: a revoked grant leaves the list.
func TestListAfterRevoke(t *testing.T, factory Factory) {
	b := factory(t)
	lister(t, b.Store)
	save(t, b.Store, grant("user-1", "client-x", "openid"))
	save(t, b.Store, grant("user-1", "client-y", "openid"))
	_, err := b.Store.RevokeConsent(context.Background(), &core.RevokeConsentRequest{Subject: "user-1", ClientID: "client-x"})
	require.NoError(t, err)
	assert.Equal(t, []string{"client-y"}, clientIDs(list(t, b.Store, "user-1")))
}

// TestListReturnsCopies: changing a listed grant doesn't change the
// stored one.
func TestListReturnsCopies(t *testing.T, factory Factory) {
	b := factory(t)
	lister(t, b.Store)
	save(t, b.Store, grant("user-1", "client-x", "openid", "email"))
	got := list(t, b.Store, "user-1")
	require.Len(t, got, 1)
	got[0].Scopes[0] = "admin"
	assert.Equal(t, []string{"openid", "email"}, get(t, b.Store, "user-1", "client-x").Scopes)
}

// TestListPersists: a reopened store lists what was saved before.
func TestListPersists(t *testing.T, factory Factory) {
	b := factory(t)
	lister(t, b.Store)
	save(t, b.Store, grant("user-1", "client-x", "openid"))
	assert.Equal(t, []string{"client-x"}, clientIDs(list(t, b.Reopen(), "user-1")))
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

// TestListIsSorted: grants come back by client_id whatever order they
// were saved in, so a page listing them doesn't reorder between loads.
// Eight clients saved in reverse make an accidental order (by file name
// hash, Datastore key or insertion) unlikely to pass.
func TestListIsSorted(t *testing.T, factory Factory) {
	b := factory(t)
	lister(t, b.Store)
	want := []string{"client-a", "client-b", "client-c", "client-d", "client-e", "client-f", "client-g", "client-h"}
	for i := len(want) - 1; i >= 0; i-- {
		save(t, b.Store, grant("user-1", want[i], "openid"))
	}
	assert.Equal(t, want, clientIDs(list(t, b.Store, "user-1")))
}
