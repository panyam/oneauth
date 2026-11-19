package outbound

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/oauth2"
)

// ErrNoRevoker is returned by UserTokens.Revoke when UserTokens.Revoker
// is nil. Delete removes a token without revoking it.
var ErrNoRevoker = errors.New("outbound: no revoker configured")

// RevokeTokenRequest is the input to TokenRevoker.RevokeToken.
type RevokeTokenRequest struct {
	// Token is the stored token, with its access and refresh tokens.
	Token *oauth2.Token
}

// RevokeTokenResponse is the output of TokenRevoker.RevokeToken.
type RevokeTokenResponse struct{}

// TokenRevoker revokes a person's token at its provider, so it stops
// working even if a copy exists outside the store. It returns nil only
// when the provider confirms the revocation.
type TokenRevoker interface {
	RevokeToken(ctx context.Context, req *RevokeTokenRequest) (*RevokeTokenResponse, error)
}

// Revoke disconnects subject: it revokes the stored token at the
// provider with Revoker, then deletes the record. Errors:
//
//   - nil when there is no record, since there is nothing to revoke.
//   - ErrNoRevoker when Revoker is nil. The record is kept.
//   - keys.ErrSealedOpen (wrapped) when the record doesn't open. The
//     record is kept, since the token may still be live at the
//     provider; Delete removes it anyway.
//   - the revoker's error when the provider refuses. The record is
//     kept, so Revoke can be retried.
//
// It holds the same per-subject lock as StoredUserToken, so a refresh in
// this process can't write a new token back after the revoke.
func (u *UserTokens) Revoke(ctx context.Context, subject string) error {
	if u.Revoker == nil {
		return ErrNoRevoker
	}
	mu, _ := u.locks.LoadOrStore(subject, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	defer mu.(*sync.Mutex).Unlock()

	tok, _, err := u.load(ctx, subject)
	if errors.Is(err, ErrUserTokenNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := u.Revoker.RevokeToken(ctx, &RevokeTokenRequest{Token: tok}); err != nil {
		return fmt.Errorf("outbound: revoke for %s/%s: %w", u.Provider, subject, err)
	}
	return u.Delete(ctx, subject)
}

// GitHubRevoker revokes GitHub user tokens through the OAuth app
// endpoints, authenticated with the app's client ID and secret.
//
// By default it calls DELETE /applications/{client_id}/token, which
// revokes the one token. With RevokeGrant it calls
// DELETE /applications/{client_id}/grant instead, which also removes
// the person's authorization of the app and every token it issued to
// them, so the next connect shows the consent screen again.
//
// Only 204 counts as success. GitHub answers 404 both for a token that is
// already revoked and for wrong client credentials (checked by make
// testgh), so a 404 can't be read as "already revoked" and is an error.
// UserTokens.Revoke stays idempotent anyway, since it deletes the record
// after a revoke and finds nothing to revoke the second time.
//
// See: https://docs.github.com/en/rest/apps/oauth-applications
type GitHubRevoker struct {
	ClientID     string
	ClientSecret string

	// BaseURL is the REST API base. Empty means DefaultGitHubAPI.
	BaseURL string

	// RevokeGrant revokes the whole authorization rather than one token.
	RevokeGrant bool

	// HTTPClient makes the request. Nil means http.DefaultClient.
	HTTPClient *http.Client
}

// RevokeToken sends the access token to GitHub's revoke endpoint.
// Failures come back as *GitHubAPIError with GitHub's message, never the
// token or the client secret.
func (g *GitHubRevoker) RevokeToken(ctx context.Context, req *RevokeTokenRequest) (*RevokeTokenResponse, error) {
	if req == nil || req.Token == nil || req.Token.AccessToken == "" {
		return nil, fmt.Errorf("outbound: revoke needs an access token")
	}
	what := "token"
	if g.RevokeGrant {
		what = "grant"
	}
	base := g.BaseURL
	if base == "" {
		base = DefaultGitHubAPI
	}
	url := fmt.Sprintf("%s/applications/%s/%s", strings.TrimRight(base, "/"), g.ClientID, what)
	body, err := json.Marshal(map[string]string{"access_token": req.Token.AccessToken})
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hreq.SetBasicAuth(g.ClientID, g.ClientSecret)
	hreq.Header.Set("Accept", "application/vnd.github+json")
	hreq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	hreq.Header.Set("Content-Type", "application/json")
	client := g.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("outbound: revoke request: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNoContent {
		return &RevokeTokenResponse{}, nil
	}
	var e struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &e)
	if e.Message == "" {
		e.Message = http.StatusText(resp.StatusCode)
	}
	return nil, &GitHubAPIError{StatusCode: resp.StatusCode, Message: e.Message}
}

var _ TokenRevoker = (*GitHubRevoker)(nil)
