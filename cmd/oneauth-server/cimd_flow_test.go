package main

// code_flow.client_id_metadata_documents lets a client use an https URL as
// its client_id. The server fetches the client's metadata from that URL, so
// the client logs in through the code flow with no registration (issue
// 532).
//
// See: https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-03.html
// See: https://github.com/panyam/oneauth/issues/532

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/utils"
)

// cimdDocServer serves a client's metadata document over TLS.
type cimdDocServer struct {
	*httptest.Server
	mu     sync.Mutex
	doc    map[string]any
	status int
}

func (d *cimdDocServer) clientID() string { return d.URL + "/clients/mcp.json" }

func (d *cimdDocServer) answer(status int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.status = status
}

// newCIMDFixture starts a reference server with client ID metadata
// documents on, trusting a TLS server that serves the document edit
// returns. The fixture's client is that URL.
func newCIMDFixture(t *testing.T, edit func(clientID string, doc map[string]any)) (*loginFixture, *cimdDocServer) {
	t.Helper()
	docs := &cimdDocServer{status: http.StatusOK}
	docs.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		docs.mu.Lock()
		defer docs.mu.Unlock()
		if docs.status != http.StatusOK {
			w.WriteHeader(docs.status)
			return
		}
		if r.URL.Path != "/clients/mcp.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(docs.doc)
	}))
	t.Cleanup(docs.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: docs.Certificate().Raw}), 0o600))

	redirect := "http://127.0.0.1:9/callback"
	docs.doc = map[string]any{
		"client_id":     docs.clientID(),
		"client_name":   "Example MCP Client",
		"redirect_uris": []string{redirect},
		"logo_uri":      "https://cdn.example/logo.png",
	}
	if edit != nil {
		edit(docs.clientID(), docs.doc)
	}

	srv := httptest.NewUnstartedServer(nil)
	base := "http://" + srv.Listener.Addr().(*net.TCPAddr).String()
	cfg := loadYAML(t, fmt.Sprintf(`
server:
  public_url: %s
keystore:
  type: memory
user_stores:
  type: memory
jwt:
  secret_key: "cimd-flow-test-secret-32-bytes!!"
admin_auth:
  type: none
  allow_open: true
  allow_private_client_hosts: true
  client_fetch_ca_file: %s
code_flow:
  enabled: true
  client_id_metadata_documents: true
`, base, caFile))
	handler, cleanup, err := buildServer(cfg)
	require.NoError(t, err)
	t.Cleanup(cleanup)
	srv.Config.Handler = handler
	srv.Start()
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	f := &loginFixture{
		url: base,
		http: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		clientID: docs.clientID(),
		redirect: redirect,
	}
	f.postForm(t, "/auth/signup", "/auth/signup", url.Values{"email": {loginTestEmail}, "password": {loginTestPassword}})
	jar.SetCookies(mustURL(t, base), []*http.Cookie{{Name: "oa_token", Value: "", MaxAge: -1}})
	return f, docs
}

func TestCIMD_MetadataAdvertisesSupport(t *testing.T) {
	f, _ := newCIMDFixture(t, nil)
	_, body := f.get(t, "/.well-known/oauth-authorization-server")
	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &meta))
	assert.Equal(t, true, meta["client_id_metadata_document_supported"])
}

func TestCIMD_MetadataOmitsSupportWhenOff(t *testing.T) {
	f := newLoginFixture(t)
	_, body := f.get(t, "/.well-known/oauth-authorization-server")
	assert.NotContains(t, body, "client_id_metadata_document_supported")
}

// A public client with only a metadata document logs in and gets tokens.
// The consent page names the hosts, since nobody registered the client.
func TestCIMD_PublicClientCompletesTheCodeFlow(t *testing.T) {
	f, docs := newCIMDFixture(t, nil)
	authorize := f.authorizePath()

	resp := f.postForm(t, "/auth/login?next="+url.QueryEscape(authorize), "/auth/login", url.Values{
		"username": {loginTestEmail}, "password": {loginTestPassword}, "next": {authorize},
	})
	require.Equal(t, authorize, resp.Header.Get("Location"))
	resp, consent := f.get(t, authorize)
	require.Equal(t, http.StatusOK, resp.StatusCode, consent)
	assert.Contains(t, consent, "Authorize Example MCP Client")
	assert.Contains(t, consent, `id="client-host"`)
	assert.Contains(t, consent, mustURL(t, docs.URL).Host, "the page names the host that publishes the document (draft §10.6)")
	assert.Contains(t, consent, "<strong>127.0.0.1:9</strong>", "and the redirect host (MCP)")
	assert.NotContains(t, consent, "cdn.example/logo.png", "a CIMD client's logo isn't shown (draft §10.9)")

	tok := redeemCodeAt(t, f, approveCode(t, f, authorize))
	assert.NotEmpty(t, tok["access_token"])
	assert.NotEmpty(t, tok["refresh_token"])
	assert.True(t, f.refreshWorks(t, tok["refresh_token"].(string)), "refresh works for the URL client")
}

// A document that breaks the rules gets the error page at /authorize,
// never a redirect to a URI the server can't trust (draft §6.1).
func TestCIMD_InvalidDocumentShowsTheErrorPage(t *testing.T) {
	f, _ := newCIMDFixture(t, func(clientID string, doc map[string]any) { doc["client_id"] = clientID + "-other" })
	authorize := f.authorizePath()
	f.postForm(t, "/auth/login?next="+url.QueryEscape(authorize), "/auth/login", url.Values{
		"username": {loginTestEmail}, "password": {loginTestPassword}, "next": {authorize},
	})
	resp, body := f.get(t, authorize)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, body)
	assert.Empty(t, resp.Header.Get("Location"))
}

// signedAssertion mints a private_key_jwt assertion for clientID (RFC 7523).
func signedAssertion(t *testing.T, key *ecdsa.PrivateKey, kid, clientID, aud string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": clientID, "sub": clientID, "aud": aud,
		"jti": fmt.Sprintf("j-%d", time.Now().UnixNano()),
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
	})
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	require.NoError(t, err)
	return signed
}

func redeemWithAssertion(t *testing.T, f *loginFixture, code, assertion string) (int, map[string]any) {
	t.Helper()
	resp, err := f.http.PostForm(f.url+"/api/token", url.Values{
		"grant_type":            {"authorization_code"},
		"code":                  {code},
		"redirect_uri":          {f.redirect},
		"client_id":             {f.clientID},
		"code_verifier":         {strings.Repeat("v", 43)},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	})
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	return resp.StatusCode, body
}

// A private_key_jwt client may carry its public keys inline in the
// document (RFC 7591 §2 jwks). The token endpoint verifies its assertion
// with them, and refuses one signed by another key.
func TestCIMD_PrivateKeyJWTWithInlineJWKS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk, err := utils.PublicKeyToJWK("cimd-k1", "ES256", &key.PublicKey)
	require.NoError(t, err)
	f, _ := newCIMDFixture(t, func(_ string, doc map[string]any) {
		doc["token_endpoint_auth_method"] = "private_key_jwt"
		doc["jwks"] = map[string]any{"keys": []any{jwk}}
	})
	aud := f.url + "/api/token"

	code := approveCode(t, f, f.authorizePath())
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	status, body := redeemWithAssertion(t, f, code, signedAssertion(t, other, "cimd-k1", f.clientID, aud))
	assert.Equal(t, http.StatusUnauthorized, status, "an assertion signed by a key not in the document: %v", body)

	code = approveCode(t, f, f.authorizePath())
	status, body = redeemWithAssertion(t, f, code, signedAssertion(t, key, "cimd-k1", f.clientID, aud))
	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.NotEmpty(t, body["access_token"])

	code = approveCode(t, f, f.authorizePath())
	resp, err := f.http.PostForm(f.url+"/api/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.redirect},
		"client_id": {f.clientID}, "code_verifier": {strings.Repeat("v", 43)},
	})
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "a private_key_jwt client can't redeem without its assertion")
}

// When the document can't be fetched and nothing is cached, the token
// endpoint answers 503 (draft §6.1), not invalid_client and not a 500.
func TestCIMD_UnreachableDocumentIs503AtTheTokenEndpoint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk, err := utils.PublicKeyToJWK("cimd-k1", "ES256", &key.PublicKey)
	require.NoError(t, err)
	f, docs := newCIMDFixture(t, func(_ string, doc map[string]any) {
		doc["token_endpoint_auth_method"] = "private_key_jwt"
		doc["jwks"] = map[string]any{"keys": []any{jwk}}
	})
	// A different client_id on the same host, never fetched before, whose
	// document server answers 503.
	f.clientID = docs.URL + "/clients/other.json"
	docs.answer(http.StatusServiceUnavailable)
	status, body := redeemWithAssertion(t, f, "no-such-code", signedAssertion(t, key, "cimd-k1", f.clientID, f.url+"/api/token"))
	assert.Equal(t, http.StatusServiceUnavailable, status, "%v", body)
	assert.Equal(t, "temporarily_unavailable", body["error"])
}

// A document that is invalid at the token endpoint is invalid_client, not
// the 500 a failed registry lookup gives.
func TestCIMD_InvalidDocumentIsInvalidClientAtTheTokenEndpoint(t *testing.T) {
	f, docs := newCIMDFixture(t, nil)
	f.clientID = docs.URL + "/clients/missing.json"
	resp, err := f.http.PostForm(f.url+"/api/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {"no-such-code"}, "redirect_uri": {f.redirect},
		"client_id": {f.clientID}, "code_verifier": {strings.Repeat("v", 43)},
	})
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "%v", body)
	assert.Equal(t, "invalid_client", body["error"])
}

func TestCIMD_RefusedUnderFAPI2(t *testing.T) {
	cfg := &Config{FAPI2: true}
	cfg.CodeFlow.ClientIDMetadataDocuments = true
	assert.ErrorContains(t, checkClientIDMetadataDocuments(cfg), "fapi2")
	cfg.FAPI2 = false
	assert.NoError(t, checkClientIDMetadataDocuments(cfg))
}
