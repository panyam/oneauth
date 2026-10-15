package apiauth_test

// Requiring DPoP at the authorization server. FAPI 2.0 has the AS issue only
// sender-constrained access tokens, and RFC 9449 §5.2 lets a client register
// dpop_bound_access_tokens, after which the AS must reject that client's
// token requests that carry no DPoP proof. Either way a client that leaves
// the proof off gets an error, never a bearer token.
//
// References:
//   - RFC 9449 §5.2 (https://www.rfc-editor.org/rfc/rfc9449#section-5.2)
//   - FAPI 2.0 Security Profile §5.3.2.1 (https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.2.1)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
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
)

// newRequireDPoPFixture wires two confidential clients: "dpop-client" and
// "bound-client", the latter registered with dpop_bound_access_tokens.
func newRequireDPoPFixture(t *testing.T, requireAll, withValidator bool) *dpopFixture {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	apps := core.NewInMemoryAppStore()
	for id, bound := range map[string]bool{"dpop-client": false, "bound-client": true} {
		_, _ = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
			ClientID: id, Key: []byte(id + "-secret"), Algorithm: "HS256",
		}})
		_, err := apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
			ClientID: id, SigningAlg: "HS256", TokenEndpointAuthMethod: "client_secret_post", DPoPBoundAccessTokens: bound,
		}})
		require.NoError(t, err)
	}
	store := newInMemoryRefreshStore()
	cfg := apiauth.OneAuthConfig{
		KeyStore:     ks,
		AppStore:     apps,
		SigningKey:   []byte("server-jwt-secret-key-32chars!!"),
		SigningAlg:   "HS256",
		Issuer:       "dpop-test-issuer",
		RefreshStore: store,
		RequireDPoP:  requireAll,
	}
	if withValidator {
		cfg.DPoP = apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{EndpointURL: dpopTokenEndpointURL})
	}
	return &dpopFixture{apiAuthFixture: newAPIAuthFixture(cfg, nil), refreshStore: store}
}

func credentialsFor(clientID string) url.Values {
	return url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientID + "-secret"},
		"scope":         {"read"},
	}
}

func assertProofRequired(t *testing.T, rr *httptest.ResponseRecorder, body map[string]any) {
	t.Helper()
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "invalid_dpop_proof", body["error"])
	assert.Nil(t, body["access_token"], "no bearer token may be issued in place of a bound one")
}

func TestRequireDPoP_ASWideRefusesBearer(t *testing.T) {
	fx := newRequireDPoPFixture(t, true, true)
	_, sign := newProofSigner(t)

	rr := postWithProof(t, fx, credentialsFor("dpop-client"), "")
	assertProofRequired(t, rr, decodeJSON(t, rr))

	rr = postWithProof(t, fx, credentialsFor("dpop-client"), sign(proofOpts{url: dpopTokenEndpointURL}))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, "DPoP", decodeJSON(t, rr)["token_type"])
}

// The refresh grant is checked too: an unbound refresh token issued before
// the policy changed must not be a way to keep getting bearer tokens.
func TestRequireDPoP_ASWideCoversRefresh(t *testing.T) {
	fx := newRequireDPoPFixture(t, true, true)
	created, err := fx.refreshStore.CreateRefreshToken(context.Background(), &core.CreateRefreshTokenRequest{
		Subject: "user-1", ClientID: "dpop-client", Scopes: []string{"read"},
	})
	require.NoError(t, err)

	rr := postWithProof(t, fx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {created.Token.Token}}, "")

	assertProofRequired(t, rr, decodeJSON(t, rr))
}

// RequireDPoP with no validator to check proofs can never issue anything.
// It fails loudly rather than quietly issuing bearer tokens.
func TestRequireDPoP_WithoutValidatorIsAServerError(t *testing.T) {
	fx := newRequireDPoPFixture(t, true, false)

	rr := postWithProof(t, fx, credentialsFor("dpop-client"), "")

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, "server_error", decodeJSON(t, rr)["error"])
}

func TestRequireDPoP_PerClientRegistration(t *testing.T) {
	fx := newRequireDPoPFixture(t, false, true)
	_, sign := newProofSigner(t)

	t.Run("bound client without a proof is refused", func(t *testing.T) {
		rr := postWithProof(t, fx, credentialsFor("bound-client"), "")
		assertProofRequired(t, rr, decodeJSON(t, rr))
	})
	t.Run("bound client with a proof gets a DPoP token", func(t *testing.T) {
		rr := postWithProof(t, fx, credentialsFor("bound-client"), sign(proofOpts{url: dpopTokenEndpointURL}))
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.Equal(t, "DPoP", decodeJSON(t, rr)["token_type"])
	})
	t.Run("other clients may still use bearer", func(t *testing.T) {
		rr := postWithProof(t, fx, credentialsFor("dpop-client"), "")
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.Equal(t, "Bearer", decodeJSON(t, rr)["token_type"])
	})
}

// The client is identified the same way however it authenticates, so HTTP
// Basic is no way around the registration.
func TestRequireDPoP_PerClientViaBasicAuth(t *testing.T) {
	fx := newRequireDPoPFixture(t, false, true)
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}}

	req := newFormRequest(form)
	req.SetBasicAuth("bound-client", "bound-client-secret")
	rr := serve(fx, req)

	assertProofRequired(t, rr, decodeJSON(t, rr))
}

func newFormRequest(form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func serve(fx *dpopFixture, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	fx.TokenEndpoint.ServeHTTP(rr, req)
	return rr
}

// The refresh grant doesn't authenticate the client, so the request's
// client_id can be left out or name someone else. The policy has to follow
// the client the refresh token was issued to, or a DPoP-only client's
// unbound refresh token (issued before it registered) redeems as Bearer.
func TestRequireDPoP_PerClientFollowsTheRefreshTokenOwner(t *testing.T) {
	fx := newRequireDPoPFixture(t, false, true)
	created, err := fx.refreshStore.CreateRefreshToken(context.Background(), &core.CreateRefreshTokenRequest{
		Subject: "user-1", ClientID: "bound-client", Scopes: []string{"read"},
	})
	require.NoError(t, err)

	for name, clientID := range map[string]string{"no client_id": "", "another client's id": "dpop-client"} {
		t.Run(name, func(t *testing.T) {
			form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {created.Token.Token}}
			if clientID != "" {
				form.Set("client_id", clientID)
			}
			rr := postWithProof(t, fx, form, "")
			assertProofRequired(t, rr, decodeJSON(t, rr))
		})
	}
}
