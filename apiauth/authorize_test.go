package apiauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pkceFixture returns a (verifier, challenge) pair the tests use to
// drive PKCE paths without re-deriving the S256 transformation each
// time.
func pkceFixture(t *testing.T) (verifier, challenge string) {
	t.Helper()
	verifier = "test-verifier-0123456789abcdef0123456789abcdef0123"
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// newHandlerForTest returns an AuthorizationHandler backed by a fresh
// in-memory store, with no AppStore (callers that want redirect_uri
// allowlist enforcement set RedirectURIValidator).
func newHandlerForTest(t *testing.T) (*AuthorizationHandler, *core.InMemoryAuthorizationCodeStore) {
	t.Helper()
	store := core.NewInMemoryAuthorizationCodeStore()
	return &AuthorizationHandler{
		Store:     store,
		IssuerURL: "https://issuer.example",
	}, store
}

func newRequest(t *testing.T, method, path string, form url.Values) *http.Request {
	t.Helper()
	if method == http.MethodGet {
		r := httptest.NewRequest(method, path+"?"+form.Encode(), nil)
		return r
	}
	r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// TestParseAndValidate_HappyPath pins that a well-formed request
// returns the parsed shape and no error signal.
func TestParseAndValidate_HappyPath(t *testing.T) {
	h, _ := newHandlerForTest(t)
	_, challenge := pkceFixture(t)
	form := url.Values{
		"client_id":             {"client-x"},
		"redirect_uri":          {"https://app.example/cb"},
		"response_type":         {"code"},
		"scope":                 {"read write"},
		"state":                 {"state-1"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req, displayErr, errCode, _ := h.ParseAndValidate(newRequest(t, http.MethodGet, "/authorize", form))
	require.Empty(t, errCode, "happy path must produce no error")
	assert.False(t, displayErr)
	require.NotNil(t, req)
	assert.Equal(t, "client-x", req.ClientID)
	assert.Equal(t, "https://app.example/cb", req.RedirectURI)
	assert.Equal(t, []string{"read", "write"}, req.Scopes())
	assert.Equal(t, "state-1", req.State)
}

// TestParseAndValidate_MissingClientID pins the §4.1.2.1 "display, do
// not redirect" rule when client_id is missing — the caller must NOT
// forward the error via redirect.
func TestParseAndValidate_MissingClientID(t *testing.T) {
	h, _ := newHandlerForTest(t)
	form := url.Values{"redirect_uri": {"https://app.example/cb"}, "response_type": {"code"}}
	_, displayErr, errCode, _ := h.ParseAndValidate(newRequest(t, http.MethodGet, "/authorize", form))
	assert.True(t, displayErr, "missing client_id MUST be displayed, not redirected (RFC 6749 §4.1.2.1)")
	assert.Equal(t, "invalid_request", errCode)
}

// TestParseAndValidate_MissingRedirectURI mirrors §4.1.2.1 — missing
// redirect_uri MUST NOT trigger a redirect.
func TestParseAndValidate_MissingRedirectURI(t *testing.T) {
	h, _ := newHandlerForTest(t)
	form := url.Values{"client_id": {"client-x"}, "response_type": {"code"}}
	_, displayErr, errCode, _ := h.ParseAndValidate(newRequest(t, http.MethodGet, "/authorize", form))
	assert.True(t, displayErr)
	assert.Equal(t, "invalid_request", errCode)
}

// TestParseAndValidate_UnsupportedResponseType pins the §4.1.2.1 rule
// that an invalid response_type IS redirected to the client with
// `unsupported_response_type`.
func TestParseAndValidate_UnsupportedResponseType(t *testing.T) {
	h, _ := newHandlerForTest(t)
	_, challenge := pkceFixture(t)
	form := url.Values{
		"client_id":             {"client-x"},
		"redirect_uri":          {"https://app.example/cb"},
		"response_type":         {"token"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	_, displayErr, errCode, _ := h.ParseAndValidate(newRequest(t, http.MethodGet, "/authorize", form))
	assert.False(t, displayErr, "unsupported response_type IS redirected per RFC 6749 §4.1.2.1")
	assert.Equal(t, "unsupported_response_type", errCode)
}

// TestParseAndValidate_MissingPKCE pins that we reject missing
// code_challenge (OAuth 2.1 / our mandatory-PKCE policy).
func TestParseAndValidate_MissingPKCE(t *testing.T) {
	h, _ := newHandlerForTest(t)
	form := url.Values{
		"client_id":     {"client-x"},
		"redirect_uri":  {"https://app.example/cb"},
		"response_type": {"code"},
	}
	_, displayErr, errCode, desc := h.ParseAndValidate(newRequest(t, http.MethodGet, "/authorize", form))
	assert.False(t, displayErr, "missing PKCE is redirected per RFC 6749 §4.1.2.1")
	assert.Equal(t, "invalid_request", errCode)
	assert.Contains(t, desc, "code_challenge")
}

// TestParseAndValidate_PlainPKCERejected pins that we reject
// code_challenge_method=plain by default — OAuth 2.1 §7.5 retired plain.
// The opt-in path (AllowPlainPKCE=true) is exercised by
// TestParseAndValidate_PlainPKCEAcceptedWhenAllowed.
func TestParseAndValidate_PlainPKCERejected(t *testing.T) {
	h, _ := newHandlerForTest(t)
	form := url.Values{
		"client_id":             {"client-x"},
		"redirect_uri":          {"https://app.example/cb"},
		"response_type":         {"code"},
		"code_challenge":        {"any-challenge"},
		"code_challenge_method": {"plain"},
	}
	_, _, errCode, desc := h.ParseAndValidate(newRequest(t, http.MethodGet, "/authorize", form))
	assert.Equal(t, "invalid_request", errCode)
	assert.Contains(t, desc, "S256")
	assert.Contains(t, desc, "AllowPlainPKCE", "error message should point operators at the flag")
}

// TestParseAndValidate_PlainPKCEAcceptedWhenAllowed pins the
// capability-gating umbrella #344 opt-in path: when the AS opts in via
// AllowPlainPKCE, /authorize accepts plain; the verifier check at
// redemption (core.VerifyPKCE) handles plain by direct compare.
func TestParseAndValidate_PlainPKCEAcceptedWhenAllowed(t *testing.T) {
	h, _ := newHandlerForTest(t)
	h.AllowPlainPKCE = true
	form := url.Values{
		"client_id":             {"client-x"},
		"redirect_uri":          {"https://app.example/cb"},
		"response_type":         {"code"},
		"code_challenge":        {"any-challenge"},
		"code_challenge_method": {"plain"},
	}
	_, _, errCode, _ := h.ParseAndValidate(newRequest(t, http.MethodGet, "/authorize", form))
	assert.Empty(t, errCode, "plain PKCE MUST be accepted when AllowPlainPKCE=true")

	// Verifier check at redemption: plain compares verifier == challenge.
	assert.True(t, core.VerifyPKCE(core.CodeChallengeMethodPlain, "any-challenge", "any-challenge"),
		"plain verify MUST pass when verifier == challenge")
	assert.False(t, core.VerifyPKCE(core.CodeChallengeMethodPlain, "any-challenge", "wrong"),
		"plain verify MUST fail when verifier != challenge")
}

// TestParseAndValidate_UnsupportedPKCEMethod pins that unknown methods
// (not S256, not plain) are always rejected, even when AllowPlainPKCE
// is true. AllowPlainPKCE is a §7.5 escape hatch, not a "permit
// anything" knob.
func TestParseAndValidate_UnsupportedPKCEMethod(t *testing.T) {
	h, _ := newHandlerForTest(t)
	h.AllowPlainPKCE = true
	form := url.Values{
		"client_id":             {"client-x"},
		"redirect_uri":          {"https://app.example/cb"},
		"response_type":         {"code"},
		"code_challenge":        {"any-challenge"},
		"code_challenge_method": {"S512"},
	}
	_, _, errCode, desc := h.ParseAndValidate(newRequest(t, http.MethodGet, "/authorize", form))
	assert.Equal(t, "invalid_request", errCode)
	assert.Contains(t, desc, "unsupported")
}

// TestParseAndValidate_RedirectURIAllowlist pins that the configured
// RedirectURIValidator rejects unregistered redirect_uri values with
// the §4.1.2.1 "do not redirect" rule.
func TestParseAndValidate_RedirectURIAllowlist(t *testing.T) {
	h, _ := newHandlerForTest(t)
	h.RedirectURIValidator = func(ctx context.Context, clientID, redirectURI string) error {
		if clientID == "client-x" && redirectURI == "https://app.example/cb" {
			return nil
		}
		return errors.New("unknown client_id or redirect_uri")
	}
	_, challenge := pkceFixture(t)
	form := url.Values{
		"client_id":             {"client-x"},
		"redirect_uri":          {"https://attacker.example/cb"},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	_, displayErr, errCode, _ := h.ParseAndValidate(newRequest(t, http.MethodGet, "/authorize", form))
	assert.True(t, displayErr, "unregistered redirect_uri MUST be displayed, never redirected (RFC 6749 §4.1.2.1)")
	assert.Equal(t, "unauthorized_client", errCode)
}

// TestIssueCode_PersistsBinding pins that IssueCode stores every field
// the redemption handler will later verify.
func TestIssueCode_PersistsBinding(t *testing.T) {
	h, store := newHandlerForTest(t)
	_, challenge := pkceFixture(t)
	req := &AuthorizationRequest{
		ClientID:            "client-x",
		RedirectURI:         "https://app.example/cb",
		Scope:               "read write",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}
	code, err := h.IssueCode(context.Background(), req, "user-1", nil)
	require.NoError(t, err)
	require.NotEmpty(t, code)

	getResp, err := store.GetAuthorizationCode(context.Background(), &core.GetAuthorizationCodeRequest{Code: code})
	require.NoError(t, err)
	assert.Equal(t, "client-x", getResp.Code.ClientID)
	assert.Equal(t, "https://app.example/cb", getResp.Code.RedirectURI)
	assert.Equal(t, "user-1", getResp.Code.Subject)
	assert.Equal(t, challenge, getResp.Code.CodeChallenge)
	assert.Equal(t, "S256", getResp.Code.CodeChallengeMethod)
	assert.Equal(t, []string{"read", "write"}, getResp.Code.Scopes)
}

// TestIssueCode_ExpirySetsExpiresAt pins the configurable expiry
// window — defaults to 60s, overridable via Expiry.
func TestIssueCode_ExpirySetsExpiresAt(t *testing.T) {
	h, store := newHandlerForTest(t)
	h.Expiry = 3 * time.Second
	req := &AuthorizationRequest{ClientID: "c", RedirectURI: "https://app/cb", CodeChallenge: "x", CodeChallengeMethod: "S256"}
	code, err := h.IssueCode(context.Background(), req, "u", nil)
	require.NoError(t, err)

	getResp, err := store.GetAuthorizationCode(context.Background(), &core.GetAuthorizationCodeRequest{Code: code})
	require.NoError(t, err)
	delta := getResp.Code.ExpiresAt.Sub(getResp.Code.IssuedAt)
	assert.InDelta(t, (3 * time.Second).Seconds(), delta.Seconds(), 1.0, "ExpiresAt MUST match the configured Expiry")
}

// TestSuccessRedirect_EmitsIssWhenConfigured pins RFC 9207 §2 — when
// EmitIssParameter is true the redirect carries `iss=<IssuerURL>`.
func TestSuccessRedirect_EmitsIssWhenConfigured(t *testing.T) {
	h, _ := newHandlerForTest(t)
	h.EmitIssParameter = true
	req := &AuthorizationRequest{RedirectURI: "https://app.example/cb", State: "abc"}
	redirect, err := h.SuccessRedirect(req, "code-1")
	require.NoError(t, err)

	u, _ := url.Parse(redirect)
	q := u.Query()
	assert.Equal(t, "code-1", q.Get("code"))
	assert.Equal(t, "abc", q.Get("state"))
	assert.Equal(t, "https://issuer.example", q.Get("iss"), "iss MUST be emitted when EmitIssParameter is true (RFC 9207 §2)")
}

// TestSuccessRedirect_OmitsIssWhenNotConfigured pins the inverse — no
// iss when EmitIssParameter is false. Setting iss when not advertising
// it in metadata would be a spec violation.
func TestSuccessRedirect_OmitsIssWhenNotConfigured(t *testing.T) {
	h, _ := newHandlerForTest(t)
	req := &AuthorizationRequest{RedirectURI: "https://app.example/cb"}
	redirect, err := h.SuccessRedirect(req, "code-1")
	require.NoError(t, err)
	assert.NotContains(t, redirect, "iss=", "iss MUST be omitted when EmitIssParameter is false")
}

// TestRedirectOverride_CanStripIss pins the conformance hook — a
// scenario can drop iss to test the "advertises iss but doesn't emit"
// failure mode that a correct production AS can't simulate.
func TestRedirectOverride_CanStripIss(t *testing.T) {
	h, _ := newHandlerForTest(t)
	h.EmitIssParameter = true
	h.RedirectOverride = func(values url.Values) { values.Del("iss") }
	req := &AuthorizationRequest{RedirectURI: "https://app.example/cb"}
	redirect, err := h.SuccessRedirect(req, "code-1")
	require.NoError(t, err)
	assert.NotContains(t, redirect, "iss=")
}

// TestErrorRedirect_PreservesState pins the §4.1.2.1 requirement that
// the AS round-trips `state` on error redirects so the client can
// correlate the failure to its original request.
func TestErrorRedirect_PreservesState(t *testing.T) {
	h, _ := newHandlerForTest(t)
	req := &AuthorizationRequest{RedirectURI: "https://app.example/cb", State: "preserved"}
	redirect, err := h.ErrorRedirect(req, "access_denied", "user denied")
	require.NoError(t, err)
	u, _ := url.Parse(redirect)
	assert.Equal(t, "access_denied", u.Query().Get("error"))
	assert.Equal(t, "preserved", u.Query().Get("state"))
}

// TestAppendQuery_PreservesExistingParams pins that a redirect_uri
// with its own query (e.g. ?tenant=acme) keeps those params alongside
// code+state+iss.
func TestAppendQuery_PreservesExistingParams(t *testing.T) {
	values := url.Values{"code": {"abc"}, "state": {"xyz"}}
	result, err := appendQuery("https://app.example/cb?tenant=acme", values)
	require.NoError(t, err)
	u, _ := url.Parse(result)
	q := u.Query()
	assert.Equal(t, "acme", q.Get("tenant"), "existing query MUST be preserved")
	assert.Equal(t, "abc", q.Get("code"))
	assert.Equal(t, "xyz", q.Get("state"))
}
