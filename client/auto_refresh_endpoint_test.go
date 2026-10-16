package client

// The automatic refresh (GetToken, and the transport's refresh-then-retry)
// against a standard authorization server: it posts to the discovered token
// endpoint with the RFC 6749 §6 form, authenticates a confidential client
// with the secret from WithClientSecret, and a retried request keeps its
// body.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-6
// See: https://github.com/panyam/oneauth/issues/395

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type refreshSeen struct {
	path, contentType, grantType, clientID, formSecret string
	basicUser, basicPass                               string
	hasBasic                                           bool
}

// refreshAS answers refresh_token requests on both the standard /token path
// and the legacy JSON path, recording what each request carried.
func refreshAS(t *testing.T, seen *refreshSeen) *httptest.Server {
	t.Helper()
	answer := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(OAuth2TokenResponse{
			AccessToken: "new-access", RefreshToken: "new-refresh", TokenType: "Bearer", ExpiresIn: 3600,
		})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		seen.path, seen.contentType = r.URL.Path, r.Header.Get("Content-Type")
		seen.grantType, seen.clientID, seen.formSecret = r.FormValue("grant_type"), r.FormValue("client_id"), r.FormValue("client_secret")
		seen.basicUser, seen.basicPass, seen.hasBasic = r.BasicAuth()
		answer(w)
	})
	mux.HandleFunc("/auth/cli/token", func(w http.ResponseWriter, r *http.Request) {
		var req OAuth2TokenRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		seen.path, seen.contentType = r.URL.Path, r.Header.Get("Content-Type")
		seen.grantType, seen.clientID, seen.formSecret = req.GrantType, req.ClientID, req.ClientSecret
		answer(w)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func expiringCredential(clientID string) *ServerCredential {
	return &ServerCredential{
		AccessToken: "old-access", RefreshToken: "old-refresh", ClientID: clientID,
		ExpiresAt: time.Now().Add(time.Minute),
	}
}

// With a discovered token endpoint the automatic refresh uses it, form
// encoded, instead of the oneauth-only legacy path.
func TestAutoRefresh_UsesTheDiscoveredTokenEndpoint(t *testing.T) {
	var seen refreshSeen
	srv := refreshAS(t, &seen)
	store := newMockCredentialStore()
	store.creds[srv.URL] = expiringCredential("my-app")

	c := NewAuthClient(srv.URL, store, WithASMetadata(&ASMetadata{TokenEndpoint: srv.URL + "/token"}))
	token, err := c.GetToken()

	require.NoError(t, err)
	assert.Equal(t, "new-access", token)
	assert.Equal(t, "/token", seen.path)
	assert.Contains(t, seen.contentType, "application/x-www-form-urlencoded")
	assert.Equal(t, "refresh_token", seen.grantType)
	assert.Equal(t, "my-app", seen.clientID)
	assert.False(t, seen.hasBasic, "a public client sends no credentials")
	assert.Equal(t, "my-app", store.creds[srv.URL].ClientID)
}

// A confidential client authenticates its automatic refresh, with the method
// the AS advertises, and the secret never reaches the credential store.
func TestAutoRefresh_ConfidentialClientAuthenticates(t *testing.T) {
	for name, tc := range map[string]struct {
		methods   []string
		wantBasic bool
	}{
		"client_secret_basic": {[]string{"client_secret_basic"}, true},
		"client_secret_post":  {[]string{"client_secret_post"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			var seen refreshSeen
			srv := refreshAS(t, &seen)
			store := newMockCredentialStore()
			store.creds[srv.URL] = expiringCredential("conf-app")

			c := NewAuthClient(srv.URL, store, WithClientSecret("s3cret"),
				WithASMetadata(&ASMetadata{TokenEndpoint: srv.URL + "/token", TokenEndpointAuthMethods: tc.methods}))
			_, err := c.GetToken()
			require.NoError(t, err)

			if tc.wantBasic {
				assert.True(t, seen.hasBasic)
				assert.Equal(t, "conf-app", seen.basicUser)
				assert.Equal(t, "s3cret", seen.basicPass)
				assert.Empty(t, seen.formSecret)
			} else {
				assert.False(t, seen.hasBasic)
				assert.Equal(t, "conf-app", seen.clientID)
				assert.Equal(t, "s3cret", seen.formSecret)
			}
			raw, err := json.Marshal(store.creds[srv.URL])
			require.NoError(t, err)
			assert.NotContains(t, string(raw), "s3cret", "the secret must not be stored with the credential")
		})
	}
}

// Without discovery the legacy JSON path is kept, and it carries the secret
// too.
func TestAutoRefresh_LegacyPathCarriesTheSecret(t *testing.T) {
	var seen refreshSeen
	srv := refreshAS(t, &seen)
	store := newMockCredentialStore()
	store.creds[srv.URL] = expiringCredential("conf-app")

	_, err := NewAuthClient(srv.URL, store, WithClientSecret("s3cret")).GetToken()

	require.NoError(t, err)
	assert.Equal(t, "/auth/cli/token", seen.path)
	assert.Equal(t, "conf-app", seen.clientID)
	assert.Equal(t, "s3cret", seen.formSecret)
}

// A request whose first attempt got a 401 is retried after the refresh with
// its body intact.
func TestRefreshRetry_ReplaysTheRequestBody(t *testing.T) {
	var calls atomic.Int32
	var bodies []string
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/cli/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(OAuth2TokenResponse{AccessToken: "fresh", RefreshToken: "r2", TokenType: "Bearer", ExpiresIn: 3600})
	})
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	store := newMockCredentialStore()
	store.creds[srv.URL] = &ServerCredential{AccessToken: "stale", RefreshToken: "r1", ExpiresAt: time.Now().Add(time.Hour)}

	resp, err := NewAuthClient(srv.URL, store).HTTPClient().Post(srv.URL+"/api", "text/plain", strings.NewReader("payload"))
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, []string{"payload", "payload"}, bodies, "the retry must resend the body")
}

// A body that can't be rewound isn't resent empty. The caller gets the 401.
func TestRefreshRetry_UnrewindableBodyIsNotResentEmpty(t *testing.T) {
	var bodies []string
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/cli/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(OAuth2TokenResponse{AccessToken: "fresh", RefreshToken: "r2", TokenType: "Bearer", ExpiresIn: 3600})
	})
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	store := newMockCredentialStore()
	store.creds[srv.URL] = &ServerCredential{AccessToken: "stale", RefreshToken: "r1", ExpiresAt: time.Now().Add(time.Hour)}

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api", io.NopCloser(strings.NewReader("payload")))
	require.NoError(t, err)
	require.Nil(t, req.GetBody, "precondition: this body can't be rewound")
	resp, err := NewAuthClient(srv.URL, store).HTTPClient().Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, []string{"payload"}, bodies)
	assert.Equal(t, "fresh", store.creds[srv.URL].AccessToken, "the refresh itself still happens, for the next request")
}
