package outbound_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/outbound"
	"github.com/panyam/oneauth/outbound/githubtest"
	"golang.org/x/oauth2"
)

const testMaster = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func newUserTokens(t *testing.T, gh *githubtest.Server, store outbound.UserTokenStore) *outbound.UserTokens {
	t.Helper()
	u, err := outbound.NewUserTokens("github", store, testMaster, gh.OAuthConfig())
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// saveExpired stores a token the fake has expired, so the next Token call
// must refresh it.
func saveExpired(t *testing.T, gh *githubtest.Server, u *outbound.UserTokens, subject string) *oauth2.Token {
	t.Helper()
	tok := gh.IssueUserToken(subject)
	gh.ExpireUserToken(tok.AccessToken)
	tok.Expiry = time.Now().Add(-time.Second)
	if err := u.Save(context.Background(), subject, tok); err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestStoredUserToken_FreshTokenNeedsNoRefresh(t *testing.T) {
	gh := githubtest.New(t)
	u := newUserTokens(t, gh, outbound.NewMemoryUserTokenStore())
	tok := gh.IssueUserToken("alice")
	if err := u.Save(context.Background(), "alice", tok); err != nil {
		t.Fatal(err)
	}
	got, err := u.TokenSource("alice").Token()
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != tok.AccessToken || gh.RefreshCalls() != 0 {
		t.Fatalf("got %q, refresh calls %d", got.AccessToken, gh.RefreshCalls())
	}
}

// See: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens
func TestStoredUserToken_RefreshesAndWritesBack(t *testing.T) {
	gh := githubtest.New(t)
	store := outbound.NewMemoryUserTokenStore()
	u := newUserTokens(t, gh, store)
	old := saveExpired(t, gh, u, "alice")

	got, err := u.TokenSource("alice").Token()
	if err != nil {
		t.Fatal(err)
	}
	if sub, ok := gh.ValidUserToken(got.AccessToken); !ok || sub != "alice" {
		t.Fatalf("refreshed token not live at the fake")
	}
	rec, _ := store.GetUserToken(context.Background(), &outbound.GetUserTokenRequest{Provider: "github", Subject: "alice"})
	if rec.Record.Version != 2 {
		t.Fatalf("version = %d, want 2", rec.Record.Version)
	}
	// A second read finds the written-back token and doesn't refresh.
	again, err := u.TokenSource("alice").Token()
	if err != nil {
		t.Fatal(err)
	}
	if again.AccessToken != got.AccessToken || gh.RefreshCalls() != 1 {
		t.Fatalf("second read refreshed again (calls=%d)", gh.RefreshCalls())
	}
	if got.RefreshToken == old.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}
}

// See: https://cwe.mitre.org/data/definitions/312.html
func TestStoredUserToken_SealedAtRest(t *testing.T) {
	gh := githubtest.New(t)
	store := outbound.NewMemoryUserTokenStore()
	u := newUserTokens(t, gh, store)
	tok := gh.IssueUserToken("alice")
	if err := u.Save(context.Background(), "alice", tok); err != nil {
		t.Fatal(err)
	}
	rec, _ := store.GetUserToken(context.Background(), &outbound.GetUserTokenRequest{Provider: "github", Subject: "alice"})
	raw := string(rec.Record.Sealed)
	if !keys.IsSealed(rec.Record.Sealed) || strings.Contains(raw, tok.AccessToken) || strings.Contains(raw, tok.RefreshToken) {
		t.Fatalf("stored bytes aren't sealed: %q", raw)
	}
}

// Someone who can write the store copies Alice's sealed token into
// Mallory's record. It must not open there.
// See: https://cwe.mitre.org/data/definitions/639.html
func TestStoredUserToken_CiphertextBoundToRecord(t *testing.T) {
	gh := githubtest.New(t)
	store := outbound.NewMemoryUserTokenStore()
	u := newUserTokens(t, gh, store)
	ctx := context.Background()
	if err := u.Save(ctx, "alice", gh.IssueUserToken("alice")); err != nil {
		t.Fatal(err)
	}
	rec, _ := store.GetUserToken(ctx, &outbound.GetUserTokenRequest{Provider: "github", Subject: "alice"})
	if _, err := store.PutUserToken(ctx, &outbound.PutUserTokenRequest{Provider: "github", Subject: "mallory", Sealed: rec.Record.Sealed}); err != nil {
		t.Fatal(err)
	}
	if _, err := u.TokenSource("mallory").Token(); !errors.Is(err, keys.ErrSealedOpen) {
		t.Fatalf("want ErrSealedOpen, got %v", err)
	}
}

func TestStoredUserToken_WrongMasterKeyFails(t *testing.T) {
	gh := githubtest.New(t)
	store := outbound.NewMemoryUserTokenStore()
	u := newUserTokens(t, gh, store)
	if err := u.Save(context.Background(), "alice", gh.IssueUserToken("alice")); err != nil {
		t.Fatal(err)
	}
	other, _ := outbound.NewUserTokens("github", store, strings.Repeat("ab", 32), gh.OAuthConfig())
	if _, err := other.TokenSource("alice").Token(); !errors.Is(err, keys.ErrSealedOpen) {
		t.Fatalf("want ErrSealedOpen, got %v", err)
	}
}

func TestStoredUserToken_NotConnected(t *testing.T) {
	gh := githubtest.New(t)
	u := newUserTokens(t, gh, outbound.NewMemoryUserTokenStore())
	if _, err := u.TokenSource("nobody").Token(); !errors.Is(err, outbound.ErrUserTokenNotFound) {
		t.Fatalf("want ErrUserTokenNotFound, got %v", err)
	}
}

func TestStoredUserToken_ExpiredWithoutRefreshTokenNeedsReconnect(t *testing.T) {
	gh := githubtest.New(t)
	u := newUserTokens(t, gh, outbound.NewMemoryUserTokenStore())
	tok := &oauth2.Token{AccessToken: "gho_old", Expiry: time.Now().Add(-time.Minute)}
	if err := u.Save(context.Background(), "alice", tok); err != nil {
		t.Fatal(err)
	}
	if _, err := u.TokenSource("alice").Token(); !errors.Is(err, outbound.ErrReconnect) {
		t.Fatalf("want ErrReconnect, got %v", err)
	}
}

func TestStoredUserToken_RefusedRefreshNeedsReconnect(t *testing.T) {
	gh := githubtest.New(t)
	u := newUserTokens(t, gh, outbound.NewMemoryUserTokenStore())
	u.RaceWait = 50 * time.Millisecond
	tok := &oauth2.Token{AccessToken: "gho_old", RefreshToken: "ghr_revoked", Expiry: time.Now().Add(-time.Minute)}
	if err := u.Save(context.Background(), "alice", tok); err != nil {
		t.Fatal(err)
	}
	_, err := u.TokenSource("alice").Token()
	if !errors.Is(err, outbound.ErrReconnect) || !strings.Contains(err.Error(), "bad_refresh_token") {
		t.Fatalf("want ErrReconnect naming bad_refresh_token, got %v", err)
	}
	if strings.Contains(err.Error(), "ghr_revoked") {
		t.Fatalf("error leaks the refresh token: %v", err)
	}
}

// Two replicas share a store but not a process lock. Each has its own
// UserTokens, so only the store's compare-and-swap keeps them apart. The
// fake's refresh tokens are single-use, as GitHub's are.
func TestStoredUserToken_ReplicasRefreshingAtOnceBothGetALiveToken(t *testing.T) {
	gh := githubtest.New(t)
	store := outbound.NewMemoryUserTokenStore()
	saveExpired(t, gh, newUserTokens(t, gh, store), "alice")

	const replicas = 8
	var wg sync.WaitGroup
	toks := make([]*oauth2.Token, replicas)
	errs := make([]error, replicas)
	for i := range replicas {
		wg.Add(1)
		go func() {
			defer wg.Done()
			toks[i], errs[i] = newUserTokens(t, gh, store).TokenSource("alice").Token()
		}()
	}
	wg.Wait()
	for i := range replicas {
		if errs[i] != nil {
			t.Fatalf("replica %d: %v", i, errs[i])
		}
		if _, ok := gh.ValidUserToken(toks[i].AccessToken); !ok {
			t.Fatalf("replica %d got a dead token", i)
		}
	}
	// Whatever is stored must still refresh, so the next expiry is
	// survivable.
	rec, _ := store.GetUserToken(context.Background(), &outbound.GetUserTokenRequest{Provider: "github", Subject: "alice"})
	u := newUserTokens(t, gh, store)
	stored, err := u.TokenSource("alice").Token()
	if err != nil {
		t.Fatal(err)
	}
	gh.ExpireUserToken(stored.AccessToken)
	u.Now = func() time.Time { return time.Now().Add(9 * time.Hour) }
	if _, err := u.TokenSource("alice").Token(); err != nil {
		t.Fatalf("stored refresh token (version %d) is dead: %v", rec.Record.Version, err)
	}
}

func TestUserTokens_SaveOverwritesAndDeleteIsIdempotent(t *testing.T) {
	gh := githubtest.New(t)
	u := newUserTokens(t, gh, outbound.NewMemoryUserTokenStore())
	ctx := context.Background()
	first, second := gh.IssueUserToken("alice"), gh.IssueUserToken("alice")
	if err := u.Save(ctx, "alice", first); err != nil {
		t.Fatal(err)
	}
	if err := u.Save(ctx, "alice", second); err != nil {
		t.Fatal(err)
	}
	got, err := u.TokenSource("alice").Token()
	if err != nil || got.AccessToken != second.AccessToken {
		t.Fatalf("got %v, %v", got, err)
	}
	if err := u.Delete(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := u.Delete(ctx, "alice"); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if _, err := u.TokenSource("alice").Token(); !errors.Is(err, outbound.ErrUserTokenNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestUserTokens_ScopeSurvivesStorage(t *testing.T) {
	gh := githubtest.New(t)
	u := newUserTokens(t, gh, outbound.NewMemoryUserTokenStore())
	tok := gh.IssueUserToken("alice").WithExtra(map[string]any{"scope": "repo,read:user"})
	if err := u.Save(context.Background(), "alice", tok); err != nil {
		t.Fatal(err)
	}
	got, err := u.TokenSource("alice").Token()
	if err != nil {
		t.Fatal(err)
	}
	if got.Extra("scope") != "repo,read:user" {
		t.Fatalf("scope = %v", got.Extra("scope"))
	}
}

// GitHub invalidates the previous access token as soon as it is refreshed
// (seen in make testgh), so the fake does too.
// See: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens
func TestStoredUserToken_RefreshKillsPreviousAccessToken(t *testing.T) {
	gh := githubtest.New(t)
	u := newUserTokens(t, gh, outbound.NewMemoryUserTokenStore())
	old := gh.IssueUserToken("alice")
	stale := *old
	stale.Expiry = time.Now().Add(-time.Second)
	if err := u.Save(context.Background(), "alice", &stale); err != nil {
		t.Fatal(err)
	}
	if _, err := u.TokenSource("alice").Token(); err != nil {
		t.Fatal(err)
	}
	if _, ok := gh.ValidUserToken(old.AccessToken); ok {
		t.Fatal("previous access token still live after refresh")
	}
}
