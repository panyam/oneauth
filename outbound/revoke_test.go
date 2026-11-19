package outbound_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/outbound"
	"github.com/panyam/oneauth/outbound/githubtest"
)

func withRevoker(t *testing.T, gh *githubtest.Server, store outbound.UserTokenStore) *outbound.UserTokens {
	t.Helper()
	u := newUserTokens(t, gh, store)
	u.Revoker = &outbound.GitHubRevoker{ClientID: gh.ClientID, ClientSecret: gh.ClientSecret, BaseURL: gh.URL}
	return u
}

func hasRecord(t *testing.T, store outbound.UserTokenStore, subject string) bool {
	t.Helper()
	_, err := store.GetUserToken(context.Background(), &outbound.GetUserTokenRequest{Provider: "github", Subject: subject})
	if err != nil && !errors.Is(err, outbound.ErrUserTokenNotFound) {
		t.Fatal(err)
	}
	return err == nil
}

// A disconnect has to stop the token working at GitHub, not only drop
// our copy, and the refresh token with it.
// See: https://datatracker.ietf.org/doc/html/rfc7009#section-2
func TestRevoke_TokenDeadAtGitHubAndRecordGone(t *testing.T) {
	gh := githubtest.New(t)
	store := outbound.NewMemoryUserTokenStore()
	u := withRevoker(t, gh, store)
	tok := gh.IssueUserToken("alice")
	if err := u.Save(context.Background(), "alice", tok); err != nil {
		t.Fatal(err)
	}

	if err := u.Revoke(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if _, ok := gh.ValidUserToken(tok.AccessToken); ok {
		t.Fatal("access token still live at GitHub")
	}
	if hasRecord(t, store, "alice") {
		t.Fatal("record kept after revoke")
	}
	// The refresh token was revoked too: a copy saved elsewhere can't
	// mint a new access token.
	other := newUserTokens(t, gh, outbound.NewMemoryUserTokenStore())
	tok.Expiry = time.Now().Add(-time.Minute)
	if err := other.Save(context.Background(), "alice", tok); err != nil {
		t.Fatal(err)
	}
	other.RaceWait = 10 * time.Millisecond
	if _, err := other.TokenSource("alice").Token(); !errors.Is(err, outbound.ErrReconnect) {
		t.Fatalf("refresh after revoke: %v", err)
	}
}

func TestRevoke_TwiceIsSafeAndCallsGitHubOnce(t *testing.T) {
	gh := githubtest.New(t)
	u := withRevoker(t, gh, outbound.NewMemoryUserTokenStore())
	if err := u.Save(context.Background(), "alice", gh.IssueUserToken("alice")); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := u.Revoke(context.Background(), "alice"); err != nil {
			t.Fatal(err)
		}
	}
	if gh.RevokeCalls() != 1 {
		t.Fatalf("revoke calls = %d, want 1", gh.RevokeCalls())
	}
	if err := u.Revoke(context.Background(), "never-connected"); err != nil {
		t.Fatalf("never connected: %v", err)
	}
}

// A refused revoke keeps the record, so the app can retry, and the error
// carries neither the token nor the client secret.
// See: https://cwe.mitre.org/data/definitions/532.html
func TestRevoke_RefusalKeepsRecordAndSecrets(t *testing.T) {
	gh := githubtest.New(t)
	store := outbound.NewMemoryUserTokenStore()
	u := newUserTokens(t, gh, store)
	u.Revoker = &outbound.GitHubRevoker{ClientID: gh.ClientID, ClientSecret: "wrong-secret", BaseURL: gh.URL}
	tok := gh.IssueUserToken("alice")
	if err := u.Save(context.Background(), "alice", tok); err != nil {
		t.Fatal(err)
	}

	err := u.Revoke(context.Background(), "alice")
	var ge *outbound.GitHubAPIError
	if !errors.As(err, &ge) || ge.StatusCode != http.StatusNotFound {
		t.Fatalf("want GitHubAPIError 404, got %v", err)
	}
	if strings.Contains(err.Error(), tok.AccessToken) || strings.Contains(err.Error(), "wrong-secret") {
		t.Fatalf("error leaks a secret: %v", err)
	}
	if !hasRecord(t, store, "alice") {
		t.Fatal("record deleted although GitHub refused")
	}
	if _, ok := gh.ValidUserToken(tok.AccessToken); !ok {
		t.Fatal("token died although the revoke was refused")
	}
}

func TestRevoke_NoRevokerKeepsRecord(t *testing.T) {
	gh := githubtest.New(t)
	store := outbound.NewMemoryUserTokenStore()
	u := newUserTokens(t, gh, store)
	if err := u.Save(context.Background(), "alice", gh.IssueUserToken("alice")); err != nil {
		t.Fatal(err)
	}
	if err := u.Revoke(context.Background(), "alice"); !errors.Is(err, outbound.ErrNoRevoker) {
		t.Fatalf("want ErrNoRevoker, got %v", err)
	}
	if !hasRecord(t, store, "alice") {
		t.Fatal("record deleted without a revoke")
	}
}

func TestRevoke_UnreadableRecordIsKept(t *testing.T) {
	gh := githubtest.New(t)
	store := outbound.NewMemoryUserTokenStore()
	if _, err := store.PutUserToken(context.Background(), &outbound.PutUserTokenRequest{Provider: "github", Subject: "alice", Sealed: []byte("oaenc1:garbage-garbage-garbage")}); err != nil {
		t.Fatal(err)
	}
	u := withRevoker(t, gh, store)
	if err := u.Revoke(context.Background(), "alice"); !errors.Is(err, keys.ErrSealedOpen) {
		t.Fatalf("want ErrSealedOpen, got %v", err)
	}
	if !hasRecord(t, store, "alice") || gh.RevokeCalls() != 0 {
		t.Fatal("unreadable record was deleted or sent to GitHub")
	}
}

// RevokeGrant removes the person's whole authorization, so a second
// token they hold for the app dies too.
// See: https://docs.github.com/en/rest/apps/oauth-applications#delete-an-app-authorization
func TestRevoke_GrantRevokesEveryTokenForThePerson(t *testing.T) {
	gh := githubtest.New(t)
	u := withRevoker(t, gh, outbound.NewMemoryUserTokenStore())
	u.Revoker.(*outbound.GitHubRevoker).RevokeGrant = true
	stored, elsewhere, bob := gh.IssueUserToken("alice"), gh.IssueUserToken("alice"), gh.IssueUserToken("bob")
	if err := u.Save(context.Background(), "alice", stored); err != nil {
		t.Fatal(err)
	}
	if err := u.Revoke(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	if _, ok := gh.ValidUserToken(elsewhere.AccessToken); ok {
		t.Fatal("alice's other token survived a grant revoke")
	}
	if _, ok := gh.ValidUserToken(bob.AccessToken); !ok {
		t.Fatal("bob's token was revoked")
	}
}

// deletingStore deletes the record just before the first update lands,
// as a Revoke on another replica would during a refresh.
type deletingStore struct {
	*outbound.MemoryUserTokenStore
	once bool
}

func (d *deletingStore) PutUserToken(ctx context.Context, req *outbound.PutUserTokenRequest) (*outbound.PutUserTokenResponse, error) {
	if req.ExpectedVersion > 0 && !d.once {
		d.once = true
		_, _ = d.DeleteUserToken(ctx, &outbound.DeleteUserTokenRequest{Provider: req.Provider, Subject: req.Subject})
	}
	return d.MemoryUserTokenStore.PutUserToken(ctx, req)
}

// A person who disconnects while another replica refreshes must not get
// the refreshed token handed to them, and the record must stay gone.
func TestRevoke_RefreshRacingADisconnectReturnsNotFound(t *testing.T) {
	gh := githubtest.New(t)
	store := &deletingStore{MemoryUserTokenStore: outbound.NewMemoryUserTokenStore()}
	u := newUserTokens(t, gh, store)
	saveExpired(t, gh, u, "alice")

	if _, err := u.TokenSource("alice").Token(); !errors.Is(err, outbound.ErrUserTokenNotFound) {
		t.Fatalf("want ErrUserTokenNotFound, got %v", err)
	}
	if hasRecord(t, store, "alice") {
		t.Fatal("refresh revived a deleted record")
	}
}

// GitHub answers 404 for revoking a token that is already revoked (seen in
// make testgh), the same status as for wrong client credentials. The fake
// matches, and Revoke never sends a second revoke to find out.
func TestRevoke_AlreadyRevokedTokenIs404(t *testing.T) {
	gh := githubtest.New(t)
	tok := gh.IssueUserToken("alice")
	r := &outbound.GitHubRevoker{ClientID: gh.ClientID, ClientSecret: gh.ClientSecret, BaseURL: gh.URL}
	if _, err := r.RevokeToken(context.Background(), &outbound.RevokeTokenRequest{Token: tok}); err != nil {
		t.Fatal(err)
	}
	_, err := r.RevokeToken(context.Background(), &outbound.RevokeTokenRequest{Token: tok})
	var ge *outbound.GitHubAPIError
	if !errors.As(err, &ge) || ge.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %v", err)
	}
}
