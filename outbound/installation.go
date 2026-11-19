package outbound

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/utils"
	"golang.org/x/oauth2"
)

// DefaultGitHubAPI is the API base for github.com. GitHub Enterprise Server
// uses https://HOST/api/v3.
const DefaultGitHubAPI = "https://api.github.com"

// DefaultRefreshBefore is how long before expiry a cached token is
// replaced. GitHub installation tokens last an hour; five minutes keeps a
// token handed out now from expiring during a slow request or clone.
const DefaultRefreshBefore = 5 * time.Minute

// GitHubAppInstallation is a TokenSource for one installation of a GitHub
// App. Token signs a short RS256 JWT with the App's private key, posts it
// to /app/installations/{id}/access_tokens, and caches the token until
// RefreshBefore ahead of its expires_at. Concurrent callers share one
// fetch.
//
// Set the fields before the first Token call and don't change them after.
//
// See: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation
type GitHubAppInstallation struct {
	// AppID is the JWT's iss: the App's numeric ID or its Client ID
	// ("Iv1..."). GitHub accepts either.
	AppID string

	// InstallationID names the installation, from the installation webhook
	// or GET /app/installations.
	InstallationID int64

	// Key is the App's RSA private key, at least 2048 bits.
	Key *rsa.PrivateKey

	// BaseURL is the REST API base. Empty means DefaultGitHubAPI.
	BaseURL string

	// Repositories and Permissions narrow the token below what the
	// installation grants, as GitHub's request body allows. Empty means the
	// installation's full grant.
	Repositories []string
	Permissions  map[string]string

	// HTTPClient makes the exchange. Nil means http.DefaultClient. Token
	// has no context, so set a Timeout here.
	HTTPClient *http.Client

	// RefreshBefore overrides DefaultRefreshBefore.
	RefreshBefore time.Duration

	// Now overrides time.Now, for tests.
	Now func() time.Time

	mu     sync.Mutex
	cached *oauth2.Token
}

// GitHubAPIError is a non-success answer from the GitHub API. Message is
// GitHub's own message. The JWT, the key and any token stay out of it.
type GitHubAPIError struct {
	StatusCode int
	Message    string
}

func (e *GitHubAPIError) Error() string {
	return fmt.Sprintf("github: %d %s", e.StatusCode, e.Message)
}

// NewGitHubAppInstallation parses keyPEM and returns a source for the
// installation. GitHub hands out App keys as PKCS#1 ("RSA PRIVATE KEY");
// PKCS#8 is accepted too.
func NewGitHubAppInstallation(appID string, installationID int64, keyPEM []byte) (*GitHubAppInstallation, error) {
	if appID == "" || installationID <= 0 {
		return nil, fmt.Errorf("outbound: app ID and installation ID are required")
	}
	key, err := ParseRSAPrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	return &GitHubAppInstallation{AppID: appID, InstallationID: installationID, Key: key}, nil
}

// ParseRSAPrivateKeyPEM reads a PKCS#1 or PKCS#8 RSA private key of at
// least utils.MinRSAKeyBits.
func ParseRSAPrivateKeyPEM(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("outbound: private key is not PEM")
	}
	var key any
	var err error
	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else {
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("outbound: parse private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("outbound: GitHub App keys are RSA, got %T", key)
	}
	if err := utils.CheckRSAKeySize(rsaKey); err != nil {
		return nil, err
	}
	return rsaKey, nil
}

// AppJWT signs the App's JWT: iat 60 seconds in the past for clock drift,
// exp 9 minutes ahead (GitHub allows at most 10), iss AppID. Callers use it
// directly for /app endpoints, such as listing installations.
func (g *GitHubAppInstallation) AppJWT() (string, error) {
	if g.Key == nil {
		return "", fmt.Errorf("outbound: GitHub App key is not set")
	}
	now := g.now()
	claims := jwt.MapClaims{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": g.AppID,
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(g.Key)
}

// Token returns the cached installation token, or fetches a new one when
// none is cached or the cached one is within RefreshBefore of expiry. The
// returned Expiry is RefreshBefore ahead of GitHub's (see copyCached).
func (g *GitHubAppInstallation) Token() (*oauth2.Token, error) {
	return g.TokenContext(context.Background())
}

// TokenContext is Token with a context for the exchange request. Callers
// waiting on another caller's fetch wait for it under that caller's
// context.
func (g *GitHubAppInstallation) TokenContext(ctx context.Context) (*oauth2.Token, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cached != nil && g.now().Before(g.cached.Expiry.Add(-g.refreshBefore())) {
		return g.copyCached(), nil
	}
	tok, err := g.fetch(ctx)
	if err != nil {
		return nil, err
	}
	g.cached = tok
	return g.copyCached(), nil
}

// Invalidate drops the cached token, so the next Token call fetches a new
// one. Call it when the API answers 401 with a token that should still be
// live, as after the installation is suspended and restored.
func (g *GitHubAppInstallation) Invalidate() {
	g.mu.Lock()
	g.cached = nil
	g.mu.Unlock()
}

func (g *GitHubAppInstallation) fetch(ctx context.Context) (*oauth2.Token, error) {
	appJWT, err := g.AppJWT()
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if len(g.Repositories) > 0 || len(g.Permissions) > 0 {
		b, err := json.Marshal(map[string]any{
			"repositories": g.Repositories,
			"permissions":  g.Permissions,
		})
		if err != nil {
			return nil, err
		}
		body = strings.NewReader(string(b))
	}
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", g.baseURL(), g.InstallationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := g.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("outbound: installation token request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("outbound: installation token response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Message == "" {
			e.Message = http.StatusText(resp.StatusCode)
		}
		return nil, &GitHubAPIError{StatusCode: resp.StatusCode, Message: e.Message}
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("outbound: installation token response is not JSON")
	}
	if out.Token == "" || out.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("outbound: installation token response lacks token or expires_at")
	}
	return &oauth2.Token{AccessToken: out.Token, TokenType: "Bearer", Expiry: out.ExpiresAt}, nil
}

// copyCached hands out the cached token with Expiry moved RefreshBefore
// earlier. oauth2.NewClient wraps sources in a ReuseTokenSource, which
// keeps a token until 10 seconds before Expiry; reporting the earlier time
// keeps the margin when the source is used that way. GitHub's own expiry
// is in Extra("expires_at").
func (g *GitHubAppInstallation) copyCached() *oauth2.Token {
	t := *g.cached
	t.Expiry = g.cached.Expiry.Add(-g.refreshBefore())
	return t.WithExtra(map[string]any{"expires_at": g.cached.Expiry})
}

func (g *GitHubAppInstallation) baseURL() string {
	if g.BaseURL == "" {
		return DefaultGitHubAPI
	}
	return strings.TrimRight(g.BaseURL, "/")
}

func (g *GitHubAppInstallation) refreshBefore() time.Duration {
	if g.RefreshBefore > 0 {
		return g.RefreshBefore
	}
	return DefaultRefreshBefore
}

func (g *GitHubAppInstallation) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

var _ oauth2.TokenSource = (*GitHubAppInstallation)(nil)
