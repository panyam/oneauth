package apiauth

// Error descriptions the AS sends stay inside RFC 6749's character set,
// and the implicit flow carries the OIDC claims request into its access
// token. The OIDF implicit plans found both (issue 526).
//
// References:
//   - RFC 6749 §4.1.2.1, §5.2 (https://www.rfc-editor.org/rfc/rfc6749#section-5.2): error_description is %x20-21 / %x23-5B / %x5D-7E
//   - OIDC Core §5.5 (https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter)
//   - See: https://github.com/panyam/oneauth/issues/526

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requireRFC6749Description(t *testing.T, desc string) {
	t.Helper()
	require.NotEmpty(t, desc)
	for _, r := range desc {
		ok := r == 0x20 || r == 0x21 || (r >= 0x23 && r <= 0x5B) || (r >= 0x5D && r <= 0x7E)
		assert.True(t, ok, "error_description %q has %q, outside RFC 6749's set", desc, r)
	}
}

// See: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1
func TestErrorDescription_AuthorizationErrorStaysInTheRFC6749Set(t *testing.T) {
	fx := newImplicitFixture(t, true, "id_token token")
	_, frag := fx.authorize(t, "id_token token", "openid", "")
	assert.Equal(t, "invalid_request", frag.Get("error"))
	assert.Contains(t, frag.Get("error_description"), "nonce")
	requireRFC6749Description(t, frag.Get("error_description"))
}

// See: https://www.rfc-editor.org/rfc/rfc6749#section-5.2
func TestErrorDescription_TokenEndpointErrorStaysInTheRFC6749Set(t *testing.T) {
	h := NewTokenEndpointHandler(NewOneAuth(OneAuthConfig{SigningKey: []byte("token-endpoint-secret-32-bytes!!"), SigningAlg: "HS256"}))
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader("grant_type=password&scope=a&scope=b"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Contains(t, body["error_description"], "scope")
	requireRFC6749Description(t, body["error_description"])
}

// The implicit `id_token token` access token carries the claims request,
// so userinfo returns the claims it named, as for the code flow.
// See: https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
func TestImplicit_AccessTokenCarriesTheClaimsRequest(t *testing.T) {
	fx := newImplicitFixture(t, true, "id_token token")
	v := url.Values{
		"client_id": {"imp"}, "redirect_uri": {"https://app.example/cb"}, "response_type": {"id_token token"},
		"scope": {"openid"}, "state": {"st"}, "nonce": {"n-1"},
		"claims": {`{"userinfo":{"name":{"essential":true}}}`},
	}
	rr := httptest.NewRecorder()
	fx.mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+v.Encode(), nil))
	require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	frag, err := url.ParseQuery(loc.Fragment)
	require.NoError(t, err)
	require.NotEmpty(t, frag.Get("access_token"), frag.Encode())

	info, err := fx.oa.Validator.ValidateToken(context.Background(), &ValidateTokenRequest{Token: frag.Get("access_token")})
	require.NoError(t, err)
	assert.Contains(t, info.Info.CustomClaims[UserinfoClaimsClaim], "name")
}
