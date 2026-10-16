package apiauth_test

// The introspection endpoint reports a bound token's confirmation, so a
// resource server that validates remotely enforces the same DPoP binding as
// one that reads the JWT itself.
//
// References:
//   - RFC 9449 §6.2 (https://www.rfc-editor.org/rfc/rfc9449#section-6.2)
//   - RFC 7662 §2.2 (https://www.rfc-editor.org/rfc/rfc7662#section-2.2)
//   - RFC 7800 §3.1 (https://www.rfc-editor.org/rfc/rfc7800#section-3.1)
//   - See: https://github.com/panyam/oneauth/issues/434

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/utils"
)

func TestIntrospection_HTTPResponseCarriesCnf(t *testing.T) {
	handler, auth, _, _ := setupIntrospection(t)
	key, sign := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)
	tok, err := auth.Issuer().CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{
		Subject: "alice", Scopes: []string{"read"}, Confirmation: &core.Confirmation{JKT: jkt},
	})
	require.NoError(t, err)

	rr := postIntrospect(t, handler, tok.Token, "resource-server", "rs-secret")
	require.Equal(t, http.StatusOK, rr.Code)
	var resp struct {
		Active bool              `json:"active"`
		Cnf    map[string]string `json:"cnf"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.True(t, resp.Active)
	assert.Equal(t, jkt, resp.Cnf["jkt"])

	// A resource server validating through this endpoint now holds the
	// binding: the token works with its key's proof and not as Bearer.
	as := httptest.NewServer(handler)
	defer as.Close()
	mw := &apiauth.APIMiddleware{
		JWTSecretKey:  rsSecret,
		JWTIssuer:     rsIssuer,
		DPoP:          apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{BaseURL: rsBaseURL}),
		Introspection: &apiauth.IntrospectionValidator{IntrospectionURL: as.URL, ClientID: "resource-server", ClientSecret: "rs-secret"},
	}
	protected := mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	call := func(scheme, proof string) int {
		req := httptest.NewRequest(http.MethodGet, rsResourceURL+rsResource, nil)
		req.URL.Path = rsResource
		req.Header.Set("Authorization", scheme+" "+tok.Token)
		if proof != "" {
			req.Header.Set("DPoP", proof)
		}
		rr := httptest.NewRecorder()
		protected.ServeHTTP(rr, req)
		return rr.Code
	}
	assert.Equal(t, http.StatusOK, call("DPoP", resourceProof(t, sign, tok.Token)))
	assert.Equal(t, http.StatusUnauthorized, call("Bearer", ""), "§7.2: a bound token presented as Bearer")
}

// An unbound token carries no cnf at all: an empty object would claim a
// binding nothing enforces.
func TestIntrospection_UnboundTokenHasNoCnf(t *testing.T) {
	handler, auth, _, _ := setupIntrospection(t)
	token := mintIntrospectionToken(t, auth, "alice", []string{"read"})
	rr := postIntrospect(t, handler, token, "resource-server", "rs-secret")
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, true, resp["active"])
	assert.NotContains(t, resp, "cnf")
}
