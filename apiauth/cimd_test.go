package apiauth_test

// Client ID Metadata Documents: a client_id that is an https URL names a
// JSON document the AS fetches for the client's metadata, so the client
// needs no registration.
//
// See: https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/
// See: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
// See: https://github.com/panyam/oneauth/issues/532

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

// cimdServer serves one metadata document at /client.json over TLS. Tests
// change what it answers through its fields.
type cimdServer struct {
	*httptest.Server
	mu      sync.Mutex
	doc     map[string]any
	raw     string // overrides doc when set
	status  int
	headers map[string]string
	hits    atomic.Int32
	cookies atomic.Int32
}

func newCIMDServer(t *testing.T) *cimdServer {
	t.Helper()
	s := &cimdServer{status: http.StatusOK, headers: map[string]string{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		if r.Header.Get("Cookie") != "" {
			s.cookies.Add(1)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		for k, v := range s.headers {
			w.Header().Set(k, v)
		}
		if s.status == http.StatusFound {
			http.Redirect(w, r, s.URL+"/elsewhere.json", http.StatusFound)
			return
		}
		w.WriteHeader(s.status)
		if s.raw != "" {
			_, _ = w.Write([]byte(s.raw))
			return
		}
		_ = json.NewEncoder(w).Encode(s.doc)
	}))
	t.Cleanup(s.Close)
	s.doc = map[string]any{
		"client_id":     s.ClientID(),
		"client_name":   "Example MCP Client",
		"redirect_uris": []string{"http://127.0.0.1:3000/callback"},
	}
	return s
}

func (s *cimdServer) ClientID() string { return s.URL + "/client.json" }

func (s *cimdServer) set(edit func(doc map[string]any)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	edit(s.doc)
}

func (s *cimdServer) answer(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
}

// cimdClock is a settable clock for cache tests.
type cimdClock struct{ t time.Time }

func (c *cimdClock) now() time.Time      { return c.t }
func (c *cimdClock) add(d time.Duration) { c.t = c.t.Add(d) }
func newCIMDClock() *cimdClock           { return &cimdClock{t: time.Unix(1_800_000_000, 0)} }
func storeFor(s *cimdServer) *apiauth.CIMDAppStore {
	return &apiauth.CIMDAppStore{AppRegistrationStore: core.NewInMemoryAppStore(), HTTPClient: s.Client()}
}

func getApp(store core.AppRegistrationStore, clientID string) (*core.AppRegistration, error) {
	resp, err := store.GetApp(context.Background(), &core.GetAppRequest{ClientID: clientID})
	if err != nil {
		return nil, err
	}
	return resp.App, nil
}

func TestCIMD_ResolvesAPublicClientFromItsDocument(t *testing.T) {
	s := newCIMDServer(t)
	s.set(func(d map[string]any) {
		d["logo_uri"] = "https://cdn.example/logo.png"
		d["policy_uri"] = "https://app.example/privacy"
		d["scope"] = "read"
	})
	app, err := getApp(storeFor(s), s.ClientID())
	require.NoError(t, err)
	assert.Equal(t, s.ClientID(), app.ClientID)
	assert.Equal(t, "Example MCP Client", app.ClientName)
	assert.Equal(t, []string{"http://127.0.0.1:3000/callback"}, app.RedirectURIs)
	assert.Equal(t, "none", app.TokenEndpointAuthMethod, "no auth method means none, never RFC 7591's client_secret_basic default (draft §4.1)")
	assert.Equal(t, []string{"authorization_code"}, app.GrantTypes)
	assert.Equal(t, []string{"code"}, app.ResponseTypes)
	assert.Equal(t, "read", app.Scope)
	assert.Equal(t, "https://app.example/privacy", app.PolicyURI)
	assert.Empty(t, app.LogoURI, "a logo would have to be prefetched and self-hosted (draft §10.9), so it is dropped")
	assert.Zero(t, s.cookies.Load(), "the fetch sends no cookies (draft §11.1)")
}

func TestCIMD_OtherClientIDsGoToTheWrappedStore(t *testing.T) {
	inner := core.NewInMemoryAppStore()
	_, err := inner.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{ClientID: "app_1", ClientName: "Registered"}})
	require.NoError(t, err)
	store := &apiauth.CIMDAppStore{AppRegistrationStore: inner}
	app, err := getApp(store, "app_1")
	require.NoError(t, err)
	assert.Equal(t, "Registered", app.ClientName)

	_, err = getApp(&apiauth.CIMDAppStore{}, "app_1")
	assert.ErrorIs(t, err, core.ErrAppNotFound, "no wrapped store means no registered clients")
}

// A URL that looks like a CIMD client_id never reaches the wrapped store,
// even when the store happens to hold it.
func TestCIMD_URLClientIDsNeverReachTheWrappedStore(t *testing.T) {
	inner := core.NewInMemoryAppStore()
	_, err := inner.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{ClientID: "https://evil.example", ClientName: "Shadow"}})
	require.NoError(t, err)
	_, err = getApp(&apiauth.CIMDAppStore{AppRegistrationStore: inner}, "https://evil.example")
	assert.ErrorIs(t, err, apiauth.ErrInvalidClientMetadata)
}

// See: https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-03.html#section-3
func TestCIMD_URLRules(t *testing.T) {
	cases := map[string]string{
		"userinfo":       "https://user:pw@app.example/client.json",
		"fragment":       "https://app.example/client.json#x",
		"empty fragment": "https://app.example/client.json#",
		"no path":        "https://app.example",
		"root path":      "https://app.example/",
		"dot segment":    "https://app.example/a/./client.json",
		"dotdot segment": "https://app.example/a/../client.json",
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, apiauth.ValidateClientIDMetadataDocumentURL(id), apiauth.ErrInvalidClientMetadata)
		})
	}
	assert.ErrorIs(t, apiauth.ValidateClientIDMetadataDocumentURL("http://app.example/client.json"), apiauth.ErrInvalidClientMetadata, "https only")
	assert.NoError(t, apiauth.ValidateClientIDMetadataDocumentURL("https://app.example/client.json?v=2"), "a query is only a SHOULD NOT")
	assert.NoError(t, apiauth.ValidateClientIDMetadataDocumentURL("https://app.example:8443/clients/mcp"))
}

func TestCIMD_RefusesTheIssuerAsAClientID(t *testing.T) {
	s := newCIMDServer(t)
	store := storeFor(s)
	store.Issuer = s.ClientID()
	_, err := getApp(store, s.ClientID())
	assert.ErrorIs(t, err, apiauth.ErrInvalidClientMetadata)
	assert.Zero(t, s.hits.Load(), "refused before any fetch")
}

// See: https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-03.html#section-4.1
func TestCIMD_DocumentRules(t *testing.T) {
	cases := map[string]func(d map[string]any){
		"client_id mismatch":           func(d map[string]any) { d["client_id"] = d["client_id"].(string) + "x" },
		"client_id missing":            func(d map[string]any) { delete(d, "client_id") },
		"no redirect_uris":             func(d map[string]any) { delete(d, "redirect_uris") },
		"no client_name (MCP)":         func(d map[string]any) { delete(d, "client_name") },
		"client_secret":                func(d map[string]any) { d["client_secret"] = "s" },
		"client_secret_expires_at":     func(d map[string]any) { d["client_secret_expires_at"] = 0 },
		"client_secret_basic":          func(d map[string]any) { d["token_endpoint_auth_method"] = "client_secret_basic" },
		"client_secret_post":           func(d map[string]any) { d["token_endpoint_auth_method"] = "client_secret_post" },
		"client_secret_jwt":            func(d map[string]any) { d["token_endpoint_auth_method"] = "client_secret_jwt" },
		"unknown auth method":          func(d map[string]any) { d["token_endpoint_auth_method"] = "tls_client_auth" },
		"private_key_jwt without keys": func(d map[string]any) { d["token_endpoint_auth_method"] = "private_key_jwt" },
		"jwks and jwks_uri":            func(d map[string]any) { d["jwks_uri"] = "https://app.example/jwks"; d["jwks"] = publicJWKS() },
		"jwks with a private key": func(d map[string]any) {
			d["jwks"] = map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "secret"}}}
		},
		"jwks with a symmetric key": func(d map[string]any) {
			d["jwks"] = map[string]any{"keys": []any{map[string]any{"kty": "oct", "k": "c2VjcmV0"}}}
		},
		"jwks without keys":          func(d map[string]any) { d["jwks"] = map[string]any{"keys": []any{}} },
		"no supported grant type":    func(d map[string]any) { d["grant_types"] = []string{"client_credentials"} },
		"no supported response type": func(d map[string]any) { d["response_types"] = []string{"id_token"} },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			s := newCIMDServer(t)
			s.set(edit)
			_, err := getApp(storeFor(s), s.ClientID())
			assert.ErrorIs(t, err, apiauth.ErrInvalidClientMetadata)
		})
	}
}

// A shared-secret method gets its own message, so the client's developer
// learns why (draft §4.1).
func TestCIMD_SharedSecretMethodsSayWhy(t *testing.T) {
	for _, m := range []string{"client_secret_basic", "client_secret_post", "client_secret_jwt"} {
		s := newCIMDServer(t)
		s.set(func(d map[string]any) { d["token_endpoint_auth_method"] = m })
		_, err := getApp(storeFor(s), s.ClientID())
		assert.ErrorContains(t, err, "shared secret", m)
	}
}

func TestCIMD_NotJSONIsInvalid(t *testing.T) {
	s := newCIMDServer(t)
	s.raw = "<html>not json</html>"
	_, err := getApp(storeFor(s), s.ClientID())
	assert.ErrorIs(t, err, apiauth.ErrInvalidClientMetadata)
}

func publicJWKS() map[string]any {
	return map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "kid": "k1", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}}}
}

func TestCIMD_PrivateKeyJWTWithEitherKeySource(t *testing.T) {
	s := newCIMDServer(t)
	s.set(func(d map[string]any) {
		d["token_endpoint_auth_method"] = "private_key_jwt"
		d["jwks"] = publicJWKS()
	})
	app, err := getApp(storeFor(s), s.ClientID())
	require.NoError(t, err)
	assert.Equal(t, "private_key_jwt", app.TokenEndpointAuthMethod)
	assert.JSONEq(t, `{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}`, string(app.JWKS))

	s2 := newCIMDServer(t)
	s2.set(func(d map[string]any) {
		d["token_endpoint_auth_method"] = "private_key_jwt"
		d["jwks_uri"] = "https://app.example/jwks.json"
	})
	app, err = getApp(storeFor(s2), s2.ClientID())
	require.NoError(t, err)
	assert.Equal(t, "https://app.example/jwks.json", app.JWKSURI)
	assert.Empty(t, app.JWKS)
}

func TestCIMD_GrantAndResponseTypesAreCutToTheServers(t *testing.T) {
	s := newCIMDServer(t)
	s.set(func(d map[string]any) {
		d["grant_types"] = []string{"authorization_code", "refresh_token", "client_credentials"}
		d["response_types"] = []string{"code", "id_token"}
	})
	app, err := getApp(storeFor(s), s.ClientID())
	require.NoError(t, err)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, app.GrantTypes)
	assert.Equal(t, []string{"code"}, app.ResponseTypes)
}

// See: https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-03.html#section-6
func TestCIMD_FetchRules(t *testing.T) {
	t.Run("over 5 KB", func(t *testing.T) {
		s := newCIMDServer(t)
		s.set(func(d map[string]any) { d["client_uri"] = "https://app.example/" + strings.Repeat("a", 5<<10) })
		_, err := getApp(storeFor(s), s.ClientID())
		assert.ErrorIs(t, err, apiauth.ErrInvalidClientMetadata)
	})
	t.Run("over 5 KB even when the first 5 KB parse", func(t *testing.T) {
		s := newCIMDServer(t)
		doc, _ := json.Marshal(s.doc)
		s.raw = string(doc) + strings.Repeat(" ", 5<<10)
		_, err := getApp(storeFor(s), s.ClientID())
		assert.ErrorIs(t, err, apiauth.ErrInvalidClientMetadata)
	})
	t.Run("a redirect is not followed", func(t *testing.T) {
		s := newCIMDServer(t)
		s.answer(http.StatusFound)
		_, err := getApp(storeFor(s), s.ClientID())
		assert.ErrorIs(t, err, apiauth.ErrInvalidClientMetadata)
		assert.Equal(t, int32(1), s.hits.Load(), "only the client_id URL was fetched")
	})
	t.Run("404 is terminal", func(t *testing.T) {
		s := newCIMDServer(t)
		s.answer(http.StatusNotFound)
		_, err := getApp(storeFor(s), s.ClientID())
		assert.ErrorIs(t, err, apiauth.ErrInvalidClientMetadata)
	})
	t.Run("5xx is transient", func(t *testing.T) {
		s := newCIMDServer(t)
		s.answer(http.StatusServiceUnavailable)
		_, err := getApp(storeFor(s), s.ClientID())
		assert.ErrorIs(t, err, apiauth.ErrClientMetadataUnavailable)
	})
	t.Run("unreachable is transient", func(t *testing.T) {
		s := newCIMDServer(t)
		id := s.ClientID()
		store := storeFor(s)
		s.Close()
		_, err := getApp(store, id)
		assert.ErrorIs(t, err, apiauth.ErrClientMetadataUnavailable)
	})
	t.Run("the guarded client refuses a loopback host", func(t *testing.T) {
		s := newCIMDServer(t)
		_, err := getApp(&apiauth.CIMDAppStore{}, s.ClientID())
		assert.ErrorIs(t, err, apiauth.ErrClientMetadataUnavailable)
		assert.Zero(t, s.hits.Load(), "the dial was refused (draft §10.7)")
	})
}

func TestCIMD_CachesForMaxAgeWithinBounds(t *testing.T) {
	cases := []struct {
		cacheControl string
		fresh, stale time.Duration
	}{
		{"", 4 * time.Minute, 6 * time.Minute},             // 5 minute default
		{"max-age=600", 9 * time.Minute, 11 * time.Minute}, // honored
		{"max-age=5", 50 * time.Second, 70 * time.Second},  // raised to 1 minute
		{"no-store", 50 * time.Second, 70 * time.Second},   // 1 minute
		{"max-age=999999", 23 * time.Hour, 25 * time.Hour}, // cut to 24 hours
		{"public, max-age=120", 100 * time.Second, 3 * time.Minute},
	}
	for _, c := range cases {
		t.Run(c.cacheControl, func(t *testing.T) {
			s := newCIMDServer(t)
			s.headers["Cache-Control"] = c.cacheControl
			clock := newCIMDClock()
			store := storeFor(s)
			store.Now = clock.now
			_, err := getApp(store, s.ClientID())
			require.NoError(t, err)
			clock.add(c.fresh)
			_, err = getApp(store, s.ClientID())
			require.NoError(t, err)
			assert.Equal(t, int32(1), s.hits.Load(), "still fresh after %s", c.fresh)
			clock.add(c.stale - c.fresh)
			_, err = getApp(store, s.ClientID())
			require.NoError(t, err)
			assert.Equal(t, int32(2), s.hits.Load(), "refetched after %s", c.stale)
		})
	}
}

func TestCIMD_TransientFailureServesTheCachedCopy(t *testing.T) {
	s := newCIMDServer(t)
	clock := newCIMDClock()
	store := storeFor(s)
	store.Now = clock.now
	_, err := getApp(store, s.ClientID())
	require.NoError(t, err)

	s.answer(http.StatusBadGateway)
	clock.add(10 * time.Minute)
	app, err := getApp(store, s.ClientID())
	require.NoError(t, err, "a transient failure keeps the trust cached earlier (draft §6.1)")
	assert.Equal(t, "Example MCP Client", app.ClientName)

	clock.add(24 * time.Hour)
	_, err = getApp(store, s.ClientID())
	assert.ErrorIs(t, err, apiauth.ErrClientMetadataUnavailable, "but not past 24 hours")
}

func TestCIMD_TerminalFailureDropsTheCacheAndIsNotCached(t *testing.T) {
	s := newCIMDServer(t)
	clock := newCIMDClock()
	store := storeFor(s)
	store.Now = clock.now
	_, err := getApp(store, s.ClientID())
	require.NoError(t, err)

	s.answer(http.StatusNotFound)
	clock.add(10 * time.Minute)
	_, err = getApp(store, s.ClientID())
	require.ErrorIs(t, err, apiauth.ErrInvalidClientMetadata)

	s.answer(http.StatusOK)
	_, err = getApp(store, s.ClientID())
	require.NoError(t, err, "the error wasn't cached, so the next lookup fetches again")
	assert.Equal(t, int32(3), s.hits.Load())

	s.answer(http.StatusNotFound)
	clock.add(10 * time.Minute)
	_, err = getApp(store, s.ClientID())
	require.ErrorIs(t, err, apiauth.ErrInvalidClientMetadata)
	s.answer(http.StatusBadGateway)
	_, err = getApp(store, s.ClientID())
	assert.True(t, errors.Is(err, apiauth.ErrClientMetadataUnavailable), "the terminal failure dropped the cached copy: %v", err)
}

func TestCIMD_ReturnsACopy(t *testing.T) {
	s := newCIMDServer(t)
	store := storeFor(s)
	app, err := getApp(store, s.ClientID())
	require.NoError(t, err)
	app.ClientName = "changed"
	again, err := getApp(store, s.ClientID())
	require.NoError(t, err)
	assert.Equal(t, "Example MCP Client", again.ClientName)
}
