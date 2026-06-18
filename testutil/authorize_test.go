package testutil_test

// Tests for testutil's RFC 6749 §4.1 authorize-flow surface (#297):
// the WithAuthorizeEnabled / WithAuthorizeAutoApproveSubject /
// WithAuthorizeRedirectOverride options, the AS-metadata extensions,
// and the conformance hooks that let scenarios drive misbehaving-AS
// branches a correct production AS cannot simulate.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/panyam/oneauth/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pkcePair returns a fixed S256 (verifier, challenge) pair suitable
// for driving /authorize flows without re-deriving the transformation
// in every test.
func pkcePair() (verifier, challenge string) {
	verifier = "testutil-verifier-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// authorizeReq drives a GET /authorize against the given server.URL
// with the supplied PKCE challenge + state and follows zero redirects.
// Returns the Location header.
func authorizeReq(t *testing.T, baseURL, clientID, redirectURI, state, challenge string) *url.URL {
	t.Helper()
	form := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"read"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	c := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(baseURL + "/authorize?" + form.Encode())
	require.NoError(t, err)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	require.Equal(t, http.StatusFound, resp.StatusCode, "auto-approve MUST 302-redirect")
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	return loc
}

// TestAuthorize_EmitsIssWhenSupportedTrue pins RFC 9207 §2 — when
// WithIssParameterSupported(true) is paired with WithAuthorizeEnabled,
// the /authorize redirect MUST carry iss=<issuer>. This is the
// `auth-iss-param-redirect-carries-iss` conformance check from
// mcpkit issue 382.
func TestAuthorize_EmitsIssWhenSupportedTrue(t *testing.T) {
	s := testutil.NewTestAuthServer(t,
		testutil.WithAuthorizeEnabled(true),
		testutil.WithIssParameterSupported(true),
	)
	_, challenge := pkcePair()
	loc := authorizeReq(t, s.URL(), "client-x", "http://app.example/cb", "state-1", challenge)

	q := loc.Query()
	assert.NotEmpty(t, q.Get("code"))
	assert.Equal(t, "state-1", q.Get("state"))
	assert.Equal(t, s.Issuer(), q.Get("iss"), "iss MUST equal the AS issuer (RFC 9207 §2)")
}

// TestAuthorize_OmitsIssWhenSupportedFalse pins the inverse — when the
// AS advertises authorization_response_iss_parameter_supported=false
// (or doesn't advertise it at all), the redirect MUST NOT carry iss.
// Emitting iss without advertising support would be a spec violation.
func TestAuthorize_OmitsIssWhenSupportedFalse(t *testing.T) {
	s := testutil.NewTestAuthServer(t, testutil.WithAuthorizeEnabled(true))
	_, challenge := pkcePair()
	loc := authorizeReq(t, s.URL(), "client-x", "http://app.example/cb", "state-2", challenge)

	assert.Empty(t, loc.Query().Get("iss"), "iss MUST be omitted when the AS does not advertise support")
}

// TestAuthorize_RedirectOverrideCanStripIss pins the conformance hook:
// a scenario can suppress iss to test the
// `auth-iss-param-advertised-but-not-emitted` failure mode that a
// correct production AS cannot simulate. This is the test-fixture
// surface mcpkit's conformance pillar drives.
func TestAuthorize_RedirectOverrideCanStripIss(t *testing.T) {
	s := testutil.NewTestAuthServer(t,
		testutil.WithAuthorizeEnabled(true),
		testutil.WithIssParameterSupported(true),
		testutil.WithAuthorizeRedirectOverride(func(values url.Values) { values.Del("iss") }),
	)
	_, challenge := pkcePair()
	loc := authorizeReq(t, s.URL(), "client-x", "http://app.example/cb", "state-3", challenge)

	assert.Empty(t, loc.Query().Get("iss"), "RedirectOverride MUST be able to strip iss for negative scenarios")
	assert.NotEmpty(t, loc.Query().Get("code"), "code MUST still be emitted on success")
}

// TestAuthorize_RedirectOverrideCanInjectIss is the mirror — a
// scenario can ADD a (foreign or correct) iss when the AS does NOT
// advertise support, to test the
// `auth-iss-param-not-advertised-but-emitted` failure mode.
func TestAuthorize_RedirectOverrideCanInjectIss(t *testing.T) {
	s := testutil.NewTestAuthServer(t,
		testutil.WithAuthorizeEnabled(true),
		testutil.WithAuthorizeRedirectOverride(func(values url.Values) {
			values.Set("iss", "https://attacker.example")
		}),
	)
	_, challenge := pkcePair()
	loc := authorizeReq(t, s.URL(), "client-x", "http://app.example/cb", "state-4", challenge)

	assert.Equal(t, "https://attacker.example", loc.Query().Get("iss"), "RedirectOverride MUST be able to inject iss for negative scenarios")
}

// TestAuthorize_MetadataAdvertisesEndpointAndGrants pins the AS-
// metadata advertisement contract: when authorize is enabled the
// discovery document MUST surface authorization_endpoint, list "code"
// in response_types_supported, and list "authorization_code" in
// grant_types_supported. Conformance drivers parse this to decide
// which flows to run.
func TestAuthorize_MetadataAdvertisesEndpointAndGrants(t *testing.T) {
	s := testutil.NewTestAuthServer(t, testutil.WithAuthorizeEnabled(true))

	resp, err := http.Get(s.URL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()
	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))

	assert.Equal(t, s.URL()+"/authorize", meta["authorization_endpoint"])

	responseTypes, _ := meta["response_types_supported"].([]any)
	assert.Contains(t, responseTypes, "code", "response_types_supported MUST include 'code' when authorize is enabled")

	grants, _ := meta["grant_types_supported"].([]any)
	assert.Contains(t, grants, "authorization_code", "grant_types_supported MUST include 'authorization_code' when authorize is enabled")
}

// TestAuthorize_MetadataOmitsEndpointWhenDisabled pins the default-off
// posture: callers who don't opt into authorize MUST NOT see the
// endpoint advertised. Prevents a misbehaving deployment from
// silently advertising a flow it doesn't actually support.
func TestAuthorize_MetadataOmitsEndpointWhenDisabled(t *testing.T) {
	s := testutil.NewTestAuthServer(t)

	resp, err := http.Get(s.URL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()
	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))

	assert.Empty(t, meta["authorization_endpoint"], "authorization_endpoint MUST be omitted when WithAuthorizeEnabled is off")
}
