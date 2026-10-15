package apiauth_test

// PAR with the token endpoint's DPoP validator. MountAuthorize hands
// OneAuth.DPoP to the PAR handler, and behind a proxy that validator has
// EndpointURL pinned to the token endpoint, so the pushed endpoint has to
// work out its own htu. It also has to answer a nonce challenge the way the
// token endpoint does.
//
// References:
//   - RFC 9449 §8 (https://www.rfc-editor.org/rfc/rfc9449#section-8)
//   - RFC 9449 §10.1 (https://www.rfc-editor.org/rfc/rfc9449#section-10.1)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

const sharedTokenEndpointURL = "https://as.example.com/api/token"

func newSharedValidatorPARFixture(t *testing.T, cfg apiauth.DPoPConfig) *parFixture {
	t.Helper()
	cfg.EndpointURL = sharedTokenEndpointURL
	return newPARFixture(t, func(h *apiauth.PARHandler) {
		h.DPoP = apiauth.NewDPoPProofValidator(cfg)
	})
}

func TestPARDPoP_SharedValidatorChecksThePushedEndpoint(t *testing.T) {
	fx := newSharedValidatorPARFixture(t, apiauth.DPoPConfig{})
	_, sign := newProofSigner(t)

	requestURI := fx.pushOK(t, parForm(nil), sign(proofOpts{url: parEndpointURL}))

	resolved, errCode, _ := fx.authorize(t, requestURI, parClientID)
	require.Empty(t, errCode)
	assert.NotEmpty(t, resolved.DPoPJKT)
}

// A proof made for the token endpoint must not be accepted at /par.
func TestPARDPoP_SharedValidatorRejectsTokenEndpointHTU(t *testing.T) {
	fx := newSharedValidatorPARFixture(t, apiauth.DPoPConfig{})
	_, sign := newProofSigner(t)

	rr := fx.push(t, parForm(nil), sign(proofOpts{url: sharedTokenEndpointURL}))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "invalid_dpop_proof", decodeJSON(t, rr)["error"])
}

// §8: the AS answers a proof without a required nonce with use_dpop_nonce
// and a DPoP-Nonce header, at every endpoint that takes proofs.
func TestPARDPoP_NonceChallenge(t *testing.T) {
	source := apiauth.NewNonceSource(apiauth.NonceConfig{})
	fx := newSharedValidatorPARFixture(t, apiauth.DPoPConfig{NonceSource: source, NoncePolicy: alwaysNonce})
	_, sign := newProofSigner(t)

	rr := fx.push(t, parForm(nil), sign(proofOpts{url: parEndpointURL}))
	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, apiauth.ErrorUseDPoPNonce, decodeJSON(t, rr)["error"])
	nonce := rr.Header().Get("DPoP-Nonce")
	require.NotEmpty(t, nonce)

	fx.pushOK(t, parForm(nil), sign(proofOpts{url: parEndpointURL, nonce: nonce}))
}

// The same wiring through MountAuthorize, which is how production builds it.
func TestMountAuthorize_PARSharesTheTokenEndpointValidator(t *testing.T) {
	apps := core.NewInMemoryAppStore()
	_, err := apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID: parClientID, RedirectURIs: []string{parRedirectURI}, TokenEndpointAuthMethod: "none",
	}})
	require.NoError(t, err)
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		AuthorizationCodeStore: core.NewInMemoryAuthorizationCodeStore(),
		AppStore:               apps,
		DPoP:                   apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{EndpointURL: sharedTokenEndpointURL}),
	})
	mux := http.NewServeMux()
	apiauth.MountAuthorize(mux, apiauth.AuthorizeMountConfig{
		OneAuth:              oa,
		IssuerURL:            "https://as.example.com",
		PushedStore:          core.NewInMemoryPushedAuthorizationRequestStore(),
		SubjectFromRequest:   func(*http.Request) string { return "" },
		CSRFTokenFromRequest: func(*http.Request) string { return "" },
	})
	_, sign := newProofSigner(t)

	req := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(parForm(nil).Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", sign(proofOpts{url: parEndpointURL}))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.NotEmpty(t, body["request_uri"])
}
