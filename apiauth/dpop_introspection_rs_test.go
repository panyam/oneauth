package apiauth_test

// A resource server that validates opaque tokens by introspection enforces
// the binding the AS reports in `cnf`, exactly as it does for a JWT's own
// claim.
//
// References:
//   - RFC 9449 §6.2 (https://www.rfc-editor.org/rfc/rfc9449#section-6.2)
//   - RFC 9449 §7.2 (https://www.rfc-editor.org/rfc/rfc9449#section-7.2)
//   - See: https://github.com/panyam/oneauth/issues/88

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/utils"
)

func TestDPoPMiddleware_EnforcesCnfFromIntrospection(t *testing.T) {
	key, sign := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)
	const opaque = "opaque-bound-token"

	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		w.Header().Set("Content-Type", "application/json")
		if r.PostForm.Get("token") != opaque {
			_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": true, "sub": "alice", "scope": "read", "cnf": map[string]string{"jkt": jkt},
		})
	}))
	defer as.Close()

	mw := &apiauth.APIMiddleware{
		JWTSecretKey:  rsSecret,
		JWTIssuer:     rsIssuer,
		DPoP:          apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{BaseURL: rsBaseURL}),
		Introspection: &apiauth.IntrospectionValidator{IntrospectionURL: as.URL, ClientID: "rs", ClientSecret: "rs-secret"},
	}
	handler := mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	call := func(scheme, proof string) int {
		req := httptest.NewRequest(http.MethodGet, rsResourceURL+rsResource, nil)
		req.URL.Path = rsResource
		req.Header.Set("Authorization", scheme+" "+opaque)
		if proof != "" {
			req.Header.Set("DPoP", proof)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}
	_, otherKey := newProofSigner(t)

	assert.Equal(t, http.StatusOK, call("DPoP", resourceProof(t, sign, opaque)))
	assert.Equal(t, http.StatusUnauthorized, call("DPoP", resourceProof(t, otherKey, opaque)), "a proof from another key")
	assert.Equal(t, http.StatusUnauthorized, call("Bearer", ""), "§7.2: a bound token presented as Bearer")
}
