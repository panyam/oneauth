package apiauth_test

// Tests for `dpop_jkt` (RFC 9449 §10): binding an authorization code to the
// client's DPoP key at the front channel, so the code is redeemable only by
// that key rather than by whoever intercepts it.
//
// References:
//   - RFC 9449 §10 (https://www.rfc-editor.org/rfc/rfc9449#section-10)
//   - RFC 7638 §3.1 (https://www.rfc-editor.org/rfc/rfc7638#section-3.1) — the published thumbprint
//   - See: https://github.com/panyam/oneauth/issues/374

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

// rfc7638ExampleThumbprint is the JWK thumbprint published in RFC 7638 §3.1,
// and the same value RFC 9449 Figure 25 carries as `dpop_jkt`. Using the
// RFC's own bytes checks that we treat the parameter as an opaque
// base64url thumbprint rather than reformatting it.
const rfc7638ExampleThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

const jktTokenEndpointURL = "https://as.example.com/api/token"

// newJKTFixture builds an AS that accepts the authorization_code grant and
// validates DPoP proofs on the token endpoint.
func newJKTFixture(t *testing.T) (*apiAuthFixture, core.AuthorizationCodeStore) {
	t.Helper()
	codeStore := core.NewInMemoryAuthorizationCodeStore()
	fx := newAPIAuthFixture(apiauth.OneAuthConfig{
		SigningKey:             []byte("dpopjkt-test-secret-32chars-min!!"),
		SigningAlg:             "HS256",
		Issuer:                 "test-issuer",
		AuthorizationCodeStore: codeStore,
		DPoP:                   apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{EndpointURL: jktTokenEndpointURL}),
	}, nil)
	return fx, codeStore
}

// seedBoundCode persists a code carrying dpop_jkt, or an unbound one when
// jkt is empty.
func seedBoundCode(t *testing.T, store core.AuthorizationCodeStore, code, jkt string) {
	t.Helper()
	_, err := store.CreateAuthorizationCode(context.Background(), &core.CreateAuthorizationCodeRequest{
		Code: &core.AuthorizationCode{
			Code:                code,
			ClientID:            authcodeTestClientID,
			RedirectURI:         authcodeTestRedirect,
			Scopes:              []string{"read"},
			Subject:             authcodeTestSubject,
			CodeChallenge:       core.ComputeCodeChallenge(authcodeTestVerifier),
			CodeChallengeMethod: core.CodeChallengeMethodS256,
			DPoPJKT:             jkt,
			IssuedAt:            time.Now(),
			ExpiresAt:           time.Now().Add(time.Minute),
		},
	})
	require.NoError(t, err)
}

// redeem posts the token request for code, attaching proof when non-empty.
func redeem(t *testing.T, fx *apiAuthFixture, code, proof string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {authcodeTestVerifier},
		"redirect_uri":  {authcodeTestRedirect},
		"client_id":     {authcodeTestClientID},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	rr := httptest.NewRecorder()
	fx.TokenEndpoint.ServeHTTP(rr, req)
	return rr
}

func errorCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	code, _ := body["error"].(string)
	return code
}

func TestDPoPJKT_MatchingKeyRedeemsTheCode(t *testing.T) {
	fx, store := newJKTFixture(t)
	key, sign := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)
	seedBoundCode(t, store, "code-bound", jkt)

	rr := redeem(t, fx, "code-bound", sign(proofOpts{url: jktTokenEndpointURL}))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "DPoP", body["token_type"])
}

// The attack §10 closes: an intercepted code redeemed with the attacker's own
// key would otherwise yield a token bound to the attacker, which then works
// everywhere the victim's token would have.
func TestDPoPJKT_RejectsRedemptionWithAnotherKey(t *testing.T) {
	fx, store := newJKTFixture(t)
	key, _ := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)
	seedBoundCode(t, store, "code-bound", jkt)
	_, attacker := newProofSigner(t)

	rr := redeem(t, fx, "code-bound", attacker(proofOpts{url: jktTokenEndpointURL}))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "invalid_grant", errorCode(t, rr))
}

func TestDPoPJKT_RejectsRedemptionWithNoProof(t *testing.T) {
	fx, store := newJKTFixture(t)
	key, _ := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)
	seedBoundCode(t, store, "code-bound", jkt)

	rr := redeem(t, fx, "code-bound", "")

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "invalid_grant", errorCode(t, rr))
}

// A failed redemption must leave the code usable, or an attacker who
// intercepts a code could burn it by presenting their own key first and deny
// the legitimate client its token.
func TestDPoPJKT_FailedRedemptionDoesNotConsumeTheCode(t *testing.T) {
	fx, store := newJKTFixture(t)
	key, sign := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)
	seedBoundCode(t, store, "code-bound", jkt)
	_, attacker := newProofSigner(t)

	require.Equal(t, http.StatusBadRequest, redeem(t, fx, "code-bound", attacker(proofOpts{url: jktTokenEndpointURL})).Code)
	rr := redeem(t, fx, "code-bound", sign(proofOpts{url: jktTokenEndpointURL}))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

// Codes issued without dpop_jkt keep redeeming as they always have, with or
// without a proof, which is what makes the parameter adoptable per client.
func TestDPoPJKT_UnboundCodeIsUnaffected(t *testing.T) {
	fx, store := newJKTFixture(t)
	seedBoundCode(t, store, "code-plain", "")
	seedBoundCode(t, store, "code-plain-2", "")
	_, sign := newProofSigner(t)

	plain := redeem(t, fx, "code-plain", "")
	require.Equal(t, http.StatusOK, plain.Code, plain.Body.String())

	withProof := redeem(t, fx, "code-plain-2", sign(proofOpts{url: jktTokenEndpointURL}))
	require.Equal(t, http.StatusOK, withProof.Code, withProof.Body.String())
}

// §10 makes the parameter OPTIONAL, so /authorize accepts a request without
// it and stores the value verbatim when present. The RFC's own published
// thumbprint stands in for a real one to check we do not reformat it.
func TestDPoPJKT_AuthorizeStoresTheParameter(t *testing.T) {
	store := core.NewInMemoryAuthorizationCodeStore()
	handler := &apiauth.AuthorizationHandler{Store: store, AllowPlainPKCE: false}

	code, err := handler.IssueCode(context.Background(), &apiauth.AuthorizationRequest{
		ClientID:            authcodeTestClientID,
		RedirectURI:         authcodeTestRedirect,
		ResponseType:        "code",
		Scope:               "read",
		CodeChallenge:       core.ComputeCodeChallenge(authcodeTestVerifier),
		CodeChallengeMethod: core.CodeChallengeMethodS256,
		DPoPJKT:             rfc7638ExampleThumbprint,
	}, authcodeTestSubject, []string{"read"})
	require.NoError(t, err)

	got, err := store.GetAuthorizationCode(context.Background(), &core.GetAuthorizationCodeRequest{Code: code})
	require.NoError(t, err)
	assert.Equal(t, rfc7638ExampleThumbprint, got.Code.DPoPJKT)
}
