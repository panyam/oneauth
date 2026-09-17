package apiauth_test

// Tests for the RFC 9126 pushed authorization request endpoint: what /par
// accepts, what it hands back, and what /authorize does with the reference
// afterwards.
//
// References:
//   - RFC 9126 §2.1 (https://www.rfc-editor.org/rfc/rfc9126#section-2.1) — the push
//   - RFC 9126 §2.2 (https://www.rfc-editor.org/rfc/rfc9126#section-2.2) — the response
//   - RFC 9126 §4 (https://www.rfc-editor.org/rfc/rfc9126#section-4) — using the request_uri
//   - RFC 9449 §10.1 (https://www.rfc-editor.org/rfc/rfc9449#section-10.1) — DPoP with PAR
//   - See: https://github.com/panyam/oneauth/issues/337

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/utils"
)

const (
	parClientID    = "par-client"
	parRedirectURI = "https://app.example/cb"
	parEndpointURL = "https://as.example.com/par"
)

type parFixture struct {
	handler *apiauth.PARHandler
	authz   *apiauth.AuthorizationHandler
	store   core.PushedAuthorizationRequestStore
	codes   core.AuthorizationCodeStore
}

func newPARFixture(t *testing.T, opts ...func(*apiauth.PARHandler)) *parFixture {
	t.Helper()
	store := core.NewInMemoryPushedAuthorizationRequestStore()
	codes := core.NewInMemoryAuthorizationCodeStore()
	authz := &apiauth.AuthorizationHandler{
		Store:       codes,
		PushedStore: store,
		IssuerURL:   "https://as.example.com",
		RedirectURIValidator: func(ctx context.Context, clientID, redirectURI string) error {
			return nil
		},
	}
	h := &apiauth.PARHandler{Authorization: authz, Store: store}
	for _, opt := range opts {
		opt(h)
	}
	return &parFixture{handler: h, authz: authz, store: store, codes: codes}
}

func parForm(overrides url.Values) url.Values {
	form := url.Values{
		"client_id":             {parClientID},
		"response_type":         {"code"},
		"redirect_uri":          {parRedirectURI},
		"scope":                 {"read"},
		"code_challenge":        {core.ComputeCodeChallenge(authcodeTestVerifier)},
		"code_challenge_method": {core.CodeChallengeMethodS256},
	}
	for k, v := range overrides {
		if v == nil {
			delete(form, k)
			continue
		}
		form[k] = v
	}
	return form
}

// push posts a pushed authorization request, attaching a DPoP proof when
// one is supplied.
func (f *parFixture) push(t *testing.T, form url.Values, proof string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, parEndpointURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	rr := httptest.NewRecorder()
	f.handler.ServeHTTP(rr, req)
	return rr
}

func (f *parFixture) pushOK(t *testing.T, form url.Values, proof string) string {
	t.Helper()
	rr := f.push(t, form, proof)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	return body["request_uri"].(string)
}

// authorize drives GET /authorize with a request_uri, returning what the
// handler resolved.
func (f *parFixture) authorize(t *testing.T, requestURI, clientID string) (*apiauth.AuthorizationRequest, string, string) {
	t.Helper()
	target := "/authorize?request_uri=" + url.QueryEscape(requestURI)
	if clientID != "" {
		target += "&client_id=" + url.QueryEscape(clientID)
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	parsed, _, errCode, errDescription := f.authz.ParseAndValidate(req)
	return parsed, errCode, errDescription
}

// See: https://www.rfc-editor.org/rfc/rfc9126#section-2.2
func TestPAR_SuccessResponseShape(t *testing.T) {
	fx := newPARFixture(t)

	rr := fx.push(t, parForm(nil), "")

	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.Contains(t, rr.Header().Get("Cache-Control"), "no-store")

	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	requestURI, _ := body["request_uri"].(string)
	assert.True(t, strings.HasPrefix(requestURI, core.PushedRequestURIPrefix),
		"request_uri should use the URN form RFC 9126 §2.2 suggests")
	assert.Greater(t, body["expires_in"], float64(0))
}

// §2.2 requires a value that cannot be guessed, pointing at RFC 6749
// §10.10. Two pushes must not produce anything an attacker could predict
// from the first.
func TestPAR_RequestURIsAreUnpredictable(t *testing.T) {
	fx := newPARFixture(t)
	seen := map[string]bool{}

	for range 20 {
		uri := fx.pushOK(t, parForm(nil), "")
		require.False(t, seen[uri], "request_uri %q was reused", uri)
		seen[uri] = true
		random := strings.TrimPrefix(uri, core.PushedRequestURIPrefix)
		assert.GreaterOrEqual(t, len(random), 43, "at least 256 bits of base64url randomness")
	}
}

// §2.1: request_uri is the one parameter that must not be pushed.
func TestPAR_RejectsPushedRequestURI(t *testing.T) {
	fx := newPARFixture(t)

	rr := fx.push(t, parForm(url.Values{"request_uri": {core.PushedRequestURIPrefix + "nested"}}), "")

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "invalid_request", errorCode(t, rr))
}

// §4 requires a pushed request to be validated as any other authorization
// request would be, so a push missing PKCE fails at the push rather than
// surfacing later in the browser.
func TestPAR_ValidatesLikeTheAuthorizationEndpoint(t *testing.T) {
	fx := newPARFixture(t)

	rr := fx.push(t, parForm(url.Values{"code_challenge": nil, "code_challenge_method": nil}), "")

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "invalid_request", errorCode(t, rr))
	assert.Contains(t, rr.Body.String(), "code_challenge")
}

func TestPAR_RequiresClientID(t *testing.T) {
	fx := newPARFixture(t)

	rr := fx.push(t, parForm(url.Values{"client_id": nil}), "")

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "invalid_request", errorCode(t, rr))
}

// The payload is why PAR exists: parameters too large or too sensitive for
// a browser URL have to survive the round trip untouched, including ones
// this server does not interpret.
func TestPAR_PayloadRoundTripsThroughAuthorize(t *testing.T) {
	fx := newPARFixture(t)
	const details = `[{"type":"payment_initiation","instructedAmount":{"currency":"EUR","amount":"123.50"}}]`
	requestURI := fx.pushOK(t, parForm(url.Values{
		"authorization_details": {details},
		"state":                 {"xyz"},
		"scope":                 {"read write"},
	}), "")

	resolved, errCode, _ := fx.authorize(t, requestURI, parClientID)

	require.Empty(t, errCode)
	require.NotNil(t, resolved)
	assert.Equal(t, "read write", resolved.Scope)
	assert.Equal(t, "xyz", resolved.State)

	stored, err := fx.store.GetPushedAuthorizationRequest(context.Background(), &core.GetPushedAuthorizationRequestRequest{RequestURI: requestURI})
	require.NoError(t, err)
	assert.Equal(t, details, stored.Request.Payload.Get("authorization_details"),
		"an extension parameter the handler does not parse MUST still reach the store")
}

// §2.2 binds the reference to the client that pushed it, which is what
// stops one client from spending another's pushed request.
func TestPAR_RejectsAnotherClientsRequestURI(t *testing.T) {
	fx := newPARFixture(t)
	requestURI := fx.pushOK(t, parForm(nil), "")

	_, errCode, description := fx.authorize(t, requestURI, "someone-else")

	assert.Equal(t, "invalid_request", errCode)
	assert.Contains(t, description, "not issued to this client")
}

func TestPAR_RejectsUnknownAndExpiredRequestURIs(t *testing.T) {
	fx := newPARFixture(t)

	_, errCode, description := fx.authorize(t, core.PushedRequestURIPrefix+"nope", parClientID)
	assert.Equal(t, "invalid_request", errCode)
	assert.Contains(t, description, "unknown")

	expired := &core.PushedAuthorizationRequest{
		RequestURI: core.PushedRequestURIPrefix + "stale",
		ClientID:   parClientID,
		Payload:    parForm(nil),
		CreatedAt:  time.Now().Add(-2 * time.Minute),
		ExpiresAt:  time.Now().Add(-time.Minute),
	}
	_, err := fx.store.CreatePushedAuthorizationRequest(context.Background(), &core.CreatePushedAuthorizationRequestRequest{Request: expired})
	require.NoError(t, err)

	_, errCode, description = fx.authorize(t, expired.RequestURI, parClientID)
	assert.Equal(t, "invalid_request", errCode)
	assert.Contains(t, description, "expired")
}

// The tension §4 leaves to the server: a reference is single-use, but our
// consent screen reads it twice (render, then approve) and a user may
// reload in between. Consumption tracks code issuance, so both reads work
// and the second authorization does not.
func TestPAR_ConsumedOnlyWhenACodeIsIssued(t *testing.T) {
	fx := newPARFixture(t)
	requestURI := fx.pushOK(t, parForm(nil), "")

	// Render consent, then reload it. Neither spends the reference.
	for range 2 {
		resolved, errCode, _ := fx.authorize(t, requestURI, parClientID)
		require.Empty(t, errCode)
		require.NotNil(t, resolved)
	}

	resolved, _, _ := fx.authorize(t, requestURI, parClientID)
	_, err := fx.authz.IssueCode(context.Background(), resolved, "user-1", []string{"read"})
	require.NoError(t, err)

	_, errCode, description := fx.authorize(t, requestURI, parClientID)
	assert.Equal(t, "invalid_request", errCode)
	assert.Contains(t, description, "already been used")
}

// With PAR the stored payload is authoritative, so the consent screen's
// hidden inputs stop being an attack surface: changing them changes
// nothing.
func TestPAR_StoredPayloadBeatsTamperedFormInputs(t *testing.T) {
	fx := newPARFixture(t)
	requestURI := fx.pushOK(t, parForm(url.Values{"scope": {"read"}}), "")

	form := url.Values{
		"request_uri":  {requestURI},
		"client_id":    {parClientID},
		"scope":        {"read write admin"},
		"redirect_uri": {"https://attacker.example/cb"},
	}
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resolved, _, errCode, _ := fx.authz.ParseAndValidate(req)

	require.Empty(t, errCode)
	require.NotNil(t, resolved)
	assert.Equal(t, "read", resolved.Scope, "the pushed scope MUST win over the posted one")
	assert.Equal(t, parRedirectURI, resolved.RedirectURI, "the pushed redirect_uri MUST win over the posted one")
}

// RFC 9126 §4 lets a server require PAR. A direct authorization request
// then fails rather than quietly taking the less protected path.
func TestPAR_RequirePushedRequestsRefusesDirectAuthorize(t *testing.T) {
	fx := newPARFixture(t)
	fx.authz.RequirePushedRequests = true

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+parForm(nil).Encode(), nil)
	_, _, errCode, description := fx.authz.ParseAndValidate(req)

	assert.Equal(t, "invalid_request", errCode)
	assert.Contains(t, description, "pushed authorization request")
}

// An /authorize that receives a request_uri with no store behind it must
// refuse rather than ignore the parameter and process the URL parameters,
// which would silently downgrade the request.
func TestPAR_RequestURIRejectedWhenPARIsNotConfigured(t *testing.T) {
	fx := newPARFixture(t)
	fx.authz.PushedStore = nil

	_, errCode, description := fx.authorize(t, core.PushedRequestURIPrefix+"anything", parClientID)

	assert.Equal(t, "invalid_request", errCode)
	assert.Contains(t, description, "not supported")
}

// --- RFC 9449 §10.1: DPoP with PAR ---

func newDPoPPARFixture(t *testing.T) *parFixture {
	t.Helper()
	return newPARFixture(t, func(h *apiauth.PARHandler) {
		h.DPoP = apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{EndpointURL: parEndpointURL})
	})
}

// §10.1 requires an AS supporting both to accept the key as the dpop_jkt
// parameter.
func TestPARDPoP_AcceptsJKTParameter(t *testing.T) {
	fx := newDPoPPARFixture(t)

	requestURI := fx.pushOK(t, parForm(url.Values{"dpop_jkt": {rfc7638ExampleThumbprint}}), "")

	resolved, errCode, _ := fx.authorize(t, requestURI, parClientID)
	require.Empty(t, errCode)
	assert.Equal(t, rfc7638ExampleThumbprint, resolved.DPoPJKT)
}

// §10.1 also requires accepting a proof on the push itself, and says the AS
// MUST then behave as if dpop_jkt had been supplied. A proof is the
// stronger form: it demonstrates possession rather than naming a
// thumbprint anyone could copy from a previous request.
func TestPARDPoP_AcceptsProofHeaderAndBindsTheCode(t *testing.T) {
	fx := newDPoPPARFixture(t)
	key, sign := newProofSigner(t)
	expected, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)

	requestURI := fx.pushOK(t, parForm(nil), sign(proofOpts{url: parEndpointURL}))

	resolved, errCode, _ := fx.authorize(t, requestURI, parClientID)
	require.Empty(t, errCode)
	assert.Equal(t, expected, resolved.DPoPJKT,
		"a DPoP header on the push MUST bind the code exactly as dpop_jkt would")
}

// §10.1: when both are present and disagree, the request MUST be rejected.
// Letting either win would let whichever an attacker controls decide the
// binding.
func TestPARDPoP_RejectsMismatchBetweenHeaderAndParameter(t *testing.T) {
	fx := newDPoPPARFixture(t)
	_, sign := newProofSigner(t)

	rr := fx.push(t, parForm(url.Values{"dpop_jkt": {rfc7638ExampleThumbprint}}), sign(proofOpts{url: parEndpointURL}))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "invalid_request", errorCode(t, rr))
	assert.Contains(t, rr.Body.String(), "does not match")
}

func TestPARDPoP_AcceptsMatchingHeaderAndParameter(t *testing.T) {
	fx := newDPoPPARFixture(t)
	key, sign := newProofSigner(t)
	thumbprint, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)

	rr := fx.push(t, parForm(url.Values{"dpop_jkt": {thumbprint}}), sign(proofOpts{url: parEndpointURL}))

	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
}

func TestPARDPoP_RejectsInvalidProof(t *testing.T) {
	fx := newDPoPPARFixture(t)
	_, sign := newProofSigner(t)

	rr := fx.push(t, parForm(nil), sign(proofOpts{url: "https://attacker.example/par"}))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "invalid_dpop_proof", errorCode(t, rr))
}
