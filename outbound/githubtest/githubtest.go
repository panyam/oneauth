// Package githubtest is a fake GitHub for tests of code using
// outbound.GitHubAppInstallation and outbound.StoredUserToken. It checks a
// GitHub App's JWT the way GitHub does, issues installation tokens and
// rotating user tokens, revokes them as the OAuth app endpoints do, and
// answers a bearer-protected endpoint for each
// kind of token, so a test can check that a token it was handed works.
//
// Consumers' tests can use it too, as keystoretest and appstoretest are
// used.
package githubtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// Server is the fake. Its fields are fixed once New returns, except the
// TTLs and Now, which a test may set before issuing tokens.
type Server struct {
	*httptest.Server

	// AppID is the App's ID; JWTs must carry it as iss.
	AppID string

	// AppKey is the App's private key. AppKeyPEM gives it as GitHub
	// hands it out.
	AppKey *rsa.PrivateKey

	// InstallationID is the one installation the fake knows. Others are
	// 404, as on GitHub.
	InstallationID int64

	// ClientID and ClientSecret are the App's OAuth client, for refresh.
	ClientID     string
	ClientSecret string

	// InstallationTokenTTL and UserTokenTTL default to GitHub's one hour
	// and eight hours.
	InstallationTokenTTL time.Duration
	UserTokenTTL         time.Duration

	// Now overrides time.Now, for expiry checks and issued expiries.
	Now func() time.Time

	mu                 sync.Mutex
	installationTokens map[string]time.Time // token -> expiry
	userTokens         map[string]userGrant // access token -> grant
	refreshTokens      map[string]string    // refresh token -> subject; deleted on use
	installationCalls  int
	refreshCalls       int
	revokeCalls        int
	lastJWTClaims      jwt.MapClaims
}

type userGrant struct {
	subject string
	expiry  time.Time
	refresh string
}

// New starts a fake with a fresh 2048-bit App key, App ID "12345" and
// installation 1. It is closed when the test ends.
func New(t testing.TB) *Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("githubtest: generate key: %v", err)
	}
	s := &Server{
		AppID:                "12345",
		AppKey:               key,
		InstallationID:       1,
		ClientID:             "Iv1.fakeclient",
		ClientSecret:         "fake-client-secret",
		InstallationTokenTTL: time.Hour,
		UserTokenTTL:         8 * time.Hour,
		installationTokens:   map[string]time.Time{},
		userTokens:           map[string]userGrant{},
		refreshTokens:        map[string]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", s.handleInstallationToken)
	mux.HandleFunc("POST /login/oauth/access_token", s.handleOAuthToken)
	mux.HandleFunc("GET /installation/repositories", s.handleInstallationRepos)
	mux.HandleFunc("GET /user", s.handleUser)
	mux.HandleFunc("DELETE /applications/{client_id}/token", s.handleRevoke)
	mux.HandleFunc("DELETE /applications/{client_id}/grant", s.handleRevoke)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// AppKeyPEM returns the App key as PKCS#1 PEM ("RSA PRIVATE KEY"), the
// form GitHub's App settings page downloads.
func (s *Server) AppKeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(s.AppKey)})
}

// OAuthConfig returns a client config for the App's OAuth side, pointed at
// the fake's token endpoint.
func (s *Server) OAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.ClientID,
		ClientSecret: s.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   s.URL + "/login/oauth/authorize",
			TokenURL:  s.URL + "/login/oauth/access_token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}

// IssueUserToken mints a user token for subject, as a connect flow would
// receive, with a single-use refresh token.
func (s *Server) IssueUserToken(subject string) *oauth2.Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issueUserLocked(subject)
}

// ExpireUserToken makes access token tok expired at the fake, as if its
// eight hours had passed. Its refresh token still works.
func (s *Server) ExpireUserToken(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g, ok := s.userTokens[tok]; ok {
		g.expiry = s.now().Add(-time.Second)
		s.userTokens[tok] = g
	}
}

// InstallationCalls is how many installation-token exchanges succeeded.
func (s *Server) InstallationCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.installationCalls
}

// RefreshCalls is how many refresh requests arrived, accepted or not.
func (s *Server) RefreshCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshCalls
}

// RevokeCalls is how many revoke requests arrived, accepted or not.
func (s *Server) RevokeCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokeCalls
}

// LastJWTClaims returns the claims of the last App JWT the fake accepted.
func (s *Server) LastJWTClaims() jwt.MapClaims {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastJWTClaims
}

// ValidInstallationToken reports whether tok is a live installation token.
func (s *Server) ValidInstallationToken(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.installationTokens[tok]
	return ok && s.now().Before(exp)
}

// ValidUserToken returns the subject tok was issued to, if it is live.
func (s *Server) ValidUserToken(tok string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.userTokens[tok]
	if !ok || !s.now().Before(g.expiry) {
		return "", false
	}
	return g.subject, true
}

// handleInstallationToken checks the App JWT as GitHub does: RS256 only,
// signed by the App key, iss the App ID, exp no more than ten minutes
// after iat, and not expired.
func (s *Server) handleInstallationToken(w http.ResponseWriter, r *http.Request) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		apiError(w, http.StatusUnauthorized, "A JSON web token could not be decoded")
		return
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return &s.AppKey.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithTimeFunc(s.now),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(60*time.Second),
	)
	if err != nil {
		apiError(w, http.StatusUnauthorized, "A JSON web token could not be decoded")
		return
	}
	iss, _ := claims["iss"].(string)
	if iss != s.AppID {
		// Real GitHub looks the App up by iss and answers 404 for one it
		// doesn't know (seen in the live smoke test).
		apiError(w, http.StatusNotFound, "Integration not found")
		return
	}
	iat, _ := claims.GetIssuedAt()
	exp, _ := claims.GetExpirationTime()
	if iat == nil || exp.Sub(iat.Time) > 10*time.Minute {
		apiError(w, http.StatusUnauthorized, "'Expiration time' claim ('exp') is too far in the future")
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id != s.InstallationID {
		apiError(w, http.StatusNotFound, "Not Found")
		return
	}
	s.mu.Lock()
	tok := "ghs_" + randHex()
	exp2 := s.now().Add(s.InstallationTokenTTL).UTC().Truncate(time.Second)
	s.installationTokens[tok] = exp2
	s.installationCalls++
	s.lastJWTClaims = claims
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"token": tok, "expires_at": exp2.Format(time.RFC3339)})
}

// handleOAuthToken serves the refresh grant. Like GitHub, it answers
// errors with 200 and an "error" field, and a refresh token works once.
func (s *Server) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshCalls++
	w.Header().Set("Content-Type", "application/json")
	if r.PostForm.Get("client_id") != s.ClientID || r.PostForm.Get("client_secret") != s.ClientSecret {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "incorrect_client_credentials"})
		return
	}
	if r.PostForm.Get("grant_type") != "refresh_token" {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type"})
		return
	}
	subject, ok := s.refreshTokens[r.PostForm.Get("refresh_token")]
	if !ok {
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "bad_refresh_token", "error_description": "The refresh token passed is incorrect or expired."})
		return
	}
	delete(s.refreshTokens, r.PostForm.Get("refresh_token"))
	tok := s.issueUserLocked(subject)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  tok.AccessToken,
		"token_type":    "bearer",
		"expires_in":    int(s.UserTokenTTL.Seconds()),
		"refresh_token": tok.RefreshToken,
		"scope":         "",
	})
}

// handleRevoke serves DELETE /applications/{client_id}/token and /grant.
// It needs the app's client ID and secret as basic auth. /token revokes
// the access token and its refresh token; /grant revokes every token
// issued to that person. Success is 204. An unknown token is 422, as
// GitHub's docs list for a validation failure.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeCalls++
	id, secret, ok := r.BasicAuth()
	if !ok || id != s.ClientID || secret != s.ClientSecret || r.PathValue("client_id") != s.ClientID {
		apiError(w, http.StatusNotFound, "Not Found")
		return
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	g, ok := s.userTokens[body.AccessToken]
	if !ok {
		apiError(w, http.StatusUnprocessableEntity, "Validation Failed")
		return
	}
	if strings.HasSuffix(r.URL.Path, "/grant") {
		for tok, other := range s.userTokens {
			if other.subject == g.subject {
				delete(s.userTokens, tok)
			}
		}
		for rt, subject := range s.refreshTokens {
			if subject == g.subject {
				delete(s.refreshTokens, rt)
			}
		}
	} else {
		delete(s.userTokens, body.AccessToken)
		delete(s.refreshTokens, g.refresh)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleInstallationRepos(w http.ResponseWriter, r *http.Request) {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !s.ValidInstallationToken(tok) {
		apiError(w, http.StatusUnauthorized, "Bad credentials")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 0, "repositories": []any{}})
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	subject, ok := s.ValidUserToken(tok)
	if !ok {
		apiError(w, http.StatusUnauthorized, "Bad credentials")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"login": subject})
}

func (s *Server) issueUserLocked(subject string) *oauth2.Token {
	tok := &oauth2.Token{
		AccessToken:  "ghu_" + randHex(),
		TokenType:    "bearer",
		RefreshToken: "ghr_" + randHex(),
		Expiry:       s.now().Add(s.UserTokenTTL),
	}
	s.userTokens[tok.AccessToken] = userGrant{subject: subject, expiry: tok.Expiry, refresh: tok.RefreshToken}
	s.refreshTokens[tok.RefreshToken] = subject
	return tok
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func apiError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": msg, "documentation_url": "https://docs.github.com/rest"})
}

func randHex() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("githubtest: %v", err))
	}
	return hex.EncodeToString(b)
}
