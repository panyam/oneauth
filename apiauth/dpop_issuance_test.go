package apiauth_test

// Issuance tests for DPoP (RFC 9449 §5): what the token endpoint puts in the
// response and in the token when a request carries a DPoP proof, and what it
// must keep doing when a request does not.
//
// References:
//   - RFC 9449 §5 (https://www.rfc-editor.org/rfc/rfc9449#section-5) — token request
//   - RFC 9449 §6 (https://www.rfc-editor.org/rfc/rfc9449#section-6) — cnf.jkt
//   - RFC 7800 (https://www.rfc-editor.org/rfc/rfc7800) — cnf claim semantics
//   - See: https://github.com/panyam/oneauth/issues/336

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

const dpopTokenEndpointURL = "https://as.example.com/api/token"

type dpopFixture struct {
	*apiAuthFixture
	refreshStore *inMemoryRefreshStore
}

// newDPoPFixture wires an AS with client_credentials and refresh enabled.
// dpop=false leaves OneAuthConfig.DPoP nil, which is how a deployment that
// has not opted into RFC 9449 is configured.
func newDPoPFixture(t *testing.T, dpop bool, customClaims apiauth.CustomClaimsFunc) *dpopFixture {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	_, _ = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID:  "dpop-client",
		Key:       []byte("dpop-client-secret"),
		Algorithm: "HS256",
	}})
	store := newInMemoryRefreshStore()

	cfg := apiauth.OneAuthConfig{
		KeyStore:     ks,
		SigningKey:   []byte("server-jwt-secret-key-32chars!!"),
		SigningAlg:   "HS256",
		Issuer:       "dpop-test-issuer",
		RefreshStore: store,
		CustomClaims: customClaims,
	}
	if dpop {
		cfg.DPoP = apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{EndpointURL: dpopTokenEndpointURL})
	}
	return &dpopFixture{apiAuthFixture: newAPIAuthFixture(cfg, nil), refreshStore: store}
}

// postWithProof posts a form-encoded token request, attaching proof as the
// DPoP header when non-empty.
func postWithProof(t *testing.T, fx *dpopFixture, form url.Values, proof string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	rr := httptest.NewRecorder()
	fx.TokenEndpoint.ServeHTTP(rr, req)
	return rr
}

func clientCredentialsForm() url.Values {
	return url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"dpop-client"},
		"client_secret": {"dpop-client-secret"},
		"scope":         {"read"},
	}
}

func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	return body
}

// accessTokenClaims reads the payload without verifying, which is what a test
// wants: the signature is covered elsewhere, and a decode here keeps the
// assertion about the claim, not about key wiring.
func accessTokenClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

// assertBoundTo checks the token response and the token itself agree on the
// binding. Checking only one of the two would miss the failure that matters:
// a token bound in its claims but reported as Bearer is presented without a
// proof and rejected by every resource server.
func assertBoundTo(t *testing.T, body map[string]any, jkt string) {
	t.Helper()
	assert.Equal(t, "DPoP", body["token_type"])
	claims := accessTokenClaims(t, body["access_token"].(string))
	cnf, ok := claims["cnf"].(map[string]any)
	require.True(t, ok, "access token is missing the cnf claim")
	assert.Equal(t, jkt, cnf["jkt"])
}

func TestDPoPIssuance_ClientCredentialsBindsAccessToken(t *testing.T) {
	fx := newDPoPFixture(t, true, nil)
	key, proof := newProofSigner(t)
	expected, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)

	rr := postWithProof(t, fx, clientCredentialsForm(), proof(proofOpts{url: dpopTokenEndpointURL}))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assertBoundTo(t, decodeJSON(t, rr), expected)
}

// The bearer path is the one every existing client is on, so it has to come
// back byte-identical after DPoP is wired.
func TestDPoPIssuance_WithoutProofStaysBearer(t *testing.T) {
	fx := newDPoPFixture(t, true, nil)

	rr := postWithProof(t, fx, clientCredentialsForm(), "")

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	body := decodeJSON(t, rr)
	assert.Equal(t, "Bearer", body["token_type"])
	assert.NotContains(t, accessTokenClaims(t, body["access_token"].(string)), "cnf")
}

// An AS that has not opted into DPoP ignores the header and issues a bearer
// token, rather than failing a request it could serve (RFC 9449 §5).
func TestDPoPIssuance_ValidatorNotWiredIgnoresProof(t *testing.T) {
	fx := newDPoPFixture(t, false, nil)
	_, proof := newProofSigner(t)

	rr := postWithProof(t, fx, clientCredentialsForm(), proof(proofOpts{url: dpopTokenEndpointURL}))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	body := decodeJSON(t, rr)
	assert.Equal(t, "Bearer", body["token_type"])
	assert.NotContains(t, accessTokenClaims(t, body["access_token"].(string)), "cnf")
}

// A client that asked for a bound token must not be handed a bearer token
// when its proof fails: it would present that token without a proof, and the
// binding it believed it had would not exist.
func TestDPoPIssuance_InvalidProofRejectsTheRequest(t *testing.T) {
	fx := newDPoPFixture(t, true, nil)
	_, proof := newProofSigner(t)

	rr := postWithProof(t, fx, clientCredentialsForm(), proof(proofOpts{url: "https://attacker.example.net/api/token"}))

	require.Equal(t, http.StatusBadRequest, rr.Code)
	body := decodeJSON(t, rr)
	assert.Equal(t, "invalid_dpop_proof", body["error"])
	assert.NotContains(t, body, "access_token")
}

// See: https://www.rfc-editor.org/rfc/rfc9449#section-5 (refresh tokens
// issued to public clients are bound to the proof key)
func TestDPoPIssuance_BoundRefreshTokenRequiresItsOwnKey(t *testing.T) {
	fx := newDPoPFixture(t, true, nil)
	key, proof := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)

	created, err := fx.refreshStore.CreateRefreshToken(context.Background(), &core.CreateRefreshTokenRequest{
		Subject:      "user-1",
		ClientID:     "dpop-client",
		Scopes:       []string{"read"},
		Confirmation: &core.Confirmation{JKT: jkt},
	})
	require.NoError(t, err)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {created.Token.Token}}

	t.Run("matching key rotates", func(t *testing.T) {
		rr := postWithProof(t, fx, form, proof(proofOpts{url: dpopTokenEndpointURL}))
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assertBoundTo(t, decodeJSON(t, rr), jkt)
	})

	t.Run("stolen refresh token is useless without the key", func(t *testing.T) {
		stolen, err := fx.refreshStore.CreateRefreshToken(context.Background(), &core.CreateRefreshTokenRequest{
			Subject: "user-1", Confirmation: &core.Confirmation{JKT: jkt},
		})
		require.NoError(t, err)
		stolenForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {stolen.Token.Token}}

		_, attackerProof := newProofSigner(t)
		rr := postWithProof(t, fx, stolenForm, attackerProof(proofOpts{url: dpopTokenEndpointURL}))
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, "invalid_grant", decodeJSON(t, rr)["error"])

		rr = postWithProof(t, fx, stolenForm, "")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, "invalid_grant", decodeJSON(t, rr)["error"])
	})
}

// A refresh token issued before the client adopted DPoP still works, and the
// access token it mints binds to the key the client now proves.
func TestDPoPIssuance_UnboundRefreshTokenAcceptsAProof(t *testing.T) {
	fx := newDPoPFixture(t, true, nil)
	key, proof := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)

	created, err := fx.refreshStore.CreateRefreshToken(context.Background(), &core.CreateRefreshTokenRequest{
		Subject: "user-2", ClientID: "dpop-client", Scopes: []string{"read"},
	})
	require.NoError(t, err)

	rr := postWithProof(t, fx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {created.Token.Token},
	}, proof(proofOpts{url: dpopTokenEndpointURL}))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	body := decodeJSON(t, rr)
	assertBoundTo(t, body, jkt)

	rotated, err := fx.refreshStore.GetRefreshToken(context.Background(), &core.GetRefreshTokenRequest{
		Token: body["refresh_token"].(string),
	})
	require.NoError(t, err)
	assert.Nil(t, rotated.Token.Confirmation, "a refresh token's binding is fixed at issuance, not renegotiated on rotation")
}

// CustomClaimsFunc is deployment-supplied, so it must not be able to write a
// binding the AS never verified: a forged cnf would make a bearer token look
// sender-constrained to every resource server that trusts this issuer.
func TestDPoPIssuance_CustomClaimsCannotForgeCnf(t *testing.T) {
	forge := func(subject string, scopes []string) (map[string]any, error) {
		return map[string]any{"cnf": map[string]any{"jkt": "attacker-supplied-thumbprint"}}, nil
	}
	fx := newDPoPFixture(t, true, forge)

	rr := postWithProof(t, fx, clientCredentialsForm(), "")

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	claims := accessTokenClaims(t, decodeJSON(t, rr)["access_token"].(string))
	assert.NotContains(t, claims, "cnf")
}
