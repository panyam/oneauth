package main

// Reference-server defaults that fail closed (issue 88): no open admin API
// without saying so, no plain http on a public host without saying so, an
// issuer that matches the metadata, pages that load no third-party script,
// and a dashboard that doesn't list every registered client.
//
// References:
//   - CWE-306 (https://cwe.mitre.org/data/definitions/306.html)
//   - CWE-319 cleartext transmission (https://cwe.mitre.org/data/definitions/319.html)
//   - CWE-829 untrusted third-party script (https://cwe.mitre.org/data/definitions/829.html)
//   - RFC 8414 §3.3 issuer match (https://www.rfc-editor.org/rfc/rfc8414#section-3.3)
//   - OAuth 2.1 §1.5 TLS (https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13#section-1.5)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/admin"
	"github.com/panyam/oneauth/core"
)

func TestHardening_OpenAdminNeedsAcknowledgement(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml    string
		wantErr bool
	}{
		"unset type":              {"jwt:\n  secret_key: x\n", true},
		"none without allow_open": {"admin_auth:\n  type: none\n", true},
		"unknown type":            {"admin_auth:\n  type: oidc\n", true},
		"none with allow_open":    {"admin_auth:\n  type: none\n  allow_open: true\n", false},
		"api-key":                 {"admin_auth:\n  type: api-key\n  api_key:\n    key: k\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := buildAdminAuth(loadYAML(t, tc.yaml))
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
	a, err := buildAdminAuth(loadYAML(t, "admin_auth:\n  type: none\n  allow_open: true\n"))
	require.NoError(t, err)
	_, isNoAuth := a.(*admin.NoAuth)
	assert.True(t, isNoAuth)
}

func TestHardening_PlainHTTPOnAPublicHostRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml    string
		wantErr bool
	}{
		"http public_url on a public host": {"server:\n  public_url: http://auth.example.com\n", true},
		"no public_url, bind-all, no TLS":  {"server:\n  host: 0.0.0.0\n", true},
		"https public_url":                 {"server:\n  public_url: https://auth.example.com\n", false},
		"http on localhost":                {"server:\n  public_url: http://localhost:8080\n", false},
		"http on 127.0.0.1":                {"server:\n  public_url: http://127.0.0.1:8080\n", false},
		"plain http allowed explicitly":    {"server:\n  public_url: http://oneauth:8080\n  allow_insecure_http: true\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkTransport(loadYAML(t, tc.yaml))
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// See: https://www.rfc-editor.org/rfc/rfc8414#section-3.3
func TestHardening_IssuerDefaultsToThePublicURL(t *testing.T) {
	cfg := loadYAML(t, "server:\n  public_url: https://as.example.com\n")
	assert.Equal(t, "https://as.example.com", cfg.JWT.Issuer)
	cfg = loadYAML(t, "server:\n  public_url: https://as.example.com\njwt:\n  issuer: https://custom.example\n")
	assert.Equal(t, "https://custom.example", cfg.JWT.Issuer, "an explicit issuer is kept")
}

// See: https://cwe.mitre.org/data/definitions/829.html
func TestHardening_PagesLoadNoThirdPartyScript(t *testing.T) {
	rr := httptest.NewRecorder()
	renderTemplate(rr, "index.html", map[string]any{"Title": "Home"})
	body := rr.Body.String()
	assert.NotContains(t, body, "cdn.tailwindcss.com")
	assert.Contains(t, body, `href="/static/app.css"`)

	assert.NotContains(t, serverCSP, "unsafe-inline")
	assert.NotContains(t, serverCSP, "tailwind")
	assert.Contains(t, serverCSP, "frame-ancestors 'none'")

	css := httptest.NewRecorder()
	staticHandler().ServeHTTP(css, httptest.NewRequest(http.MethodGet, "/static/app.css", nil))
	require.Equal(t, http.StatusOK, css.Code)
	assert.Contains(t, css.Header().Get("Content-Type"), "text/css")
	assert.Contains(t, css.Body.String(), ".bg-indigo-600")
}

// Any signed-in user could see every registered client on the dashboard.
func TestHardening_DashboardDoesNotListClients(t *testing.T) {
	rr := httptest.NewRecorder()
	renderTemplate(rr, "dashboard.html", map[string]any{
		"Title": "Dashboard", "User": "alice", "UserID": "u1", "UserEmail": "alice@example.com",
		"Apps": []*core.AppRegistration{{ClientID: "app_secret_client_id", ClientName: "Someone Else's App"}},
	})
	require.Equal(t, http.StatusOK, rr.Code)
	assert.False(t, strings.Contains(rr.Body.String(), "app_secret_client_id"))
}

// An access token signed with the server's secret is not a browser session:
// pasted into the oa_token cookie it must not sign anyone in, or a client
// holding a user's scoped token could approve consent as that user.
//
// See: https://www.rfc-editor.org/rfc/rfc8725#section-3.11
func TestHardening_AccessTokenIsNotASessionCookie(t *testing.T) {
	secret := "server-secret-that-is-32-bytes!!"
	mint := func(typ string) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "alice", "type": typ, "exp": time.Now().Add(time.Hour).Unix(),
		})
		s, err := tok.SignedString([]byte(secret))
		require.NoError(t, err)
		return s
	}
	for typ, want := range map[string]string{"access": "", "session": "alice"} {
		r := httptest.NewRequest(http.MethodGet, "/authorize", nil)
		r.AddCookie(&http.Cookie{Name: "oa_token", Value: mint(typ)})
		assert.Equal(t, want, getUserIDFromCookie(r, secret), "type %s", typ)
	}
}

// See: https://www.rfc-editor.org/rfc/rfc7518#section-3.2
func TestHardening_HS256SecretMustBeLongEnough(t *testing.T) {
	for secret, wantErr := range map[string]bool{
		"":                                 true,
		"short":                            true,
		"exactly-32-bytes-long-secret-ok!": false,
	} {
		cfg := loadYAML(t, "jwt:\n  secret_key: \""+secret+"\"\n")
		err := checkSigningSecret(cfg)
		assert.Equal(t, wantErr, err != nil, "secret %q", secret)
	}
	// With asymmetric signing the HMAC secret only signs browser sessions,
	// which still need it.
	cfg := loadYAML(t, "jwt:\n  signing_alg: RS256\n  ephemeral_signing_key: true\n")
	assert.Error(t, checkSigningSecret(cfg))
}
