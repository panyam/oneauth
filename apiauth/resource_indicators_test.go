package apiauth_test

// RFC 8707 resource indicators at the AS (issue 521). With
// OneAuthConfig.AllowedResources set, a client names the resource server a
// token is for with `resource`, and the token's aud is that resource, so it
// can't be replayed at another one. A resource the AS doesn't serve is
// invalid_target. The MCP authorization spec has clients send `resource` on
// every authorization and token request.
//
// See: https://www.rfc-editor.org/rfc/rfc8707#section-2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
)

const (
	mcpA = "https://mcp-a.example/mcp"
	mcpB = "https://mcp-b.example/mcp"
)

func resourceCCFixture(t *testing.T, allowed ...string) http.Handler {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	_, _ = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID: "svc", Key: []byte("svc-secret-key-long-enough"), Algorithm: "HS256",
	}})
	return newAPIAuthFixture(apiauth.OneAuthConfig{
		KeyStore: ks, SigningKey: []byte("server-jwt-secret-key-32chars!!"), SigningAlg: "HS256",
		Issuer: "https://as.example", Audience: "https://default-aud.example", AllowedResources: allowed,
	}, nil)
}

func ccWithResources(t *testing.T, h http.Handler, resources ...string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"svc-secret-key-long-enough"}}
	for _, r := range resources {
		form.Add("resource", r)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	body := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, body
}

func audOf(t *testing.T, token string) any {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(token, claims)
	require.NoError(t, err)
	return claims["aud"]
}

func TestResourceIndicators_ClientCredentialsBindsTheAudience(t *testing.T) {
	h := resourceCCFixture(t, mcpA, mcpB)

	status, body := ccWithResources(t, h, mcpA)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, mcpA, audOf(t, body["access_token"].(string)))

	status, body = ccWithResources(t, h, mcpA, mcpB)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, []any{mcpA, mcpB}, audOf(t, body["access_token"].(string)), "§2: one aud per resource")

	status, body = ccWithResources(t, h)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, "https://default-aud.example", audOf(t, body["access_token"].(string)), "no resource keeps the default audience")
}

func TestResourceIndicators_UnknownOrMalformedResourceIsInvalidTarget(t *testing.T) {
	h := resourceCCFixture(t, mcpA)
	for name, r := range map[string]string{
		"not served":   mcpB,
		"a fragment":   mcpA + "#frag",
		"not absolute": "/mcp",
	} {
		status, body := ccWithResources(t, h, r)
		assert.Equal(t, http.StatusBadRequest, status, name)
		assert.Equal(t, "invalid_target", body["error"], name)
	}
}

// Without AllowedResources the AS ignores `resource` as it always has, so
// clients that send it (every MCP client) keep working against a
// deployment that hasn't listed its resource servers.
func TestResourceIndicators_IgnoredWithoutAnAllowlist(t *testing.T) {
	status, body := ccWithResources(t, resourceCCFixture(t), mcpA)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, "https://default-aud.example", audOf(t, body["access_token"].(string)))
}

func resourceOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	return newOIDCFixtureWith(t, nil, func(c *apiauth.OneAuthConfig) { c.AllowedResources = []string{mcpA, mcpB} })
}

func refreshWithResources(t *testing.T, fx *oidcFixture, refreshToken string, resources ...string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {authcodeTestClientID}}
	for _, r := range resources {
		form.Add("resource", r)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	fx.ServeHTTP(rr, req)
	body := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, body
}

// redeemWithResources sends q through /authorize and redeems the code,
// with tokenResources as the token request's resource parameters.
func redeemWithResources(t *testing.T, fx *oidcFixture, q url.Values, tokenResources ...string) (int, map[string]any) {
	t.Helper()
	rr := httptest.NewRecorder()
	authorizeMux(fx, false).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code, "redirect %s", loc)
	form := url.Values{"code": {code}}
	for _, r := range tokenResources {
		form.Add("resource", r)
	}
	tr := httptest.NewRecorder()
	fx.ServeHTTP(tr, tokenRedeemForm(t, form))
	body := map[string]any{}
	_ = json.Unmarshal(tr.Body.Bytes(), &body)
	return tr.Code, body
}

func TestResourceIndicators_CodeGrantCarriesTheAuthorizedResources(t *testing.T) {
	fx := resourceOIDCFixture(t)
	q := claimsParams("read", "")
	q["resource"] = []string{mcpA, mcpB}

	status, body := redeemWithResources(t, fx, q)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, []any{mcpA, mcpB}, audOf(t, body["access_token"].(string)), "no resource at the token request: every authorized one")

	status, body = redeemWithResources(t, fx, q, mcpB)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, mcpB, audOf(t, body["access_token"].(string)), "§2.2: the token request may narrow")

	refreshed, rbody := refreshWithResources(t, fx, body["refresh_token"].(string), mcpA)
	require.Equal(t, http.StatusOK, refreshed, rbody)
	assert.Equal(t, mcpA, audOf(t, rbody["access_token"].(string)), "the refresh token keeps the whole grant, not the narrowed token")
}

func TestResourceIndicators_TokenRequestsCannotWiden(t *testing.T) {
	fx := resourceOIDCFixture(t)
	q := claimsParams("read", "")
	q.Set("resource", mcpA)

	status, body := redeemWithResources(t, fx, q, mcpB)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_target", body["error"], "code redemption")

	status, body = redeemWithResources(t, fx, q)
	require.Equal(t, http.StatusOK, status, body)
	status, body = refreshWithResources(t, fx, body["refresh_token"].(string), mcpB)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_target", body["error"], "refresh")
}

// /authorize refuses a resource the AS doesn't serve at the client's
// redirect URI, as RFC 8707 §2 says, rather than issuing a code for it.
func TestResourceIndicators_AuthorizeRefusesAnUnknownResource(t *testing.T) {
	fx := resourceOIDCFixture(t)
	q := claimsParams("read", "")
	q.Set("resource", "https://elsewhere.example/mcp")
	rr := httptest.NewRecorder()
	authorizeMux(fx, false).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "invalid_target", loc.Query().Get("error"))
	assert.Empty(t, loc.Query().Get("code"))
}

// The consent page posts the request back, so each resource has to be a
// hidden input or Approve issues a code for none of them.
func TestResourceIndicators_ConsentFormCarriesResources(t *testing.T) {
	fx := resourceOIDCFixture(t)
	q := claimsParams("read", "")
	q["resource"] = []string{mcpA, mcpB}
	rr := httptest.NewRecorder()
	authorizeMux(fx, true).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), `<input type="hidden" name="resource" value="`+mcpA+`">`)
	assert.Contains(t, rr.Body.String(), `<input type="hidden" name="resource" value="`+mcpB+`">`)
}
