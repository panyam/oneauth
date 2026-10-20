package apiauth

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/panyam/oneauth/core"
)

// UserinfoHTTPHandler returns the OIDC Core §5.3 userinfo endpoint. It
// answers GET and POST (§5.3.1) with `sub` plus the claims
// OIDCConfig.UserClaims grants for the access token's scopes.
//
// mw authenticates the request; pass the deployment's resource-server
// middleware, with DPoP set when the AS issues DPoP-bound tokens, since a
// bound token presented to a middleware without it is refused. Nil uses
// HTTPMiddleware, which accepts Bearer tokens only. A token without the
// "openid" scope gets 403 insufficient_scope (RFC 6750 §3.1).
//
// Panics when OIDC is off: there is nothing for the endpoint to serve.
func (oa *OneAuth) UserinfoHTTPHandler(mw *APIMiddleware) http.Handler {
	if oa.OIDC == nil {
		panic("apiauth: UserinfoHTTPHandler: OneAuthConfig.OIDC is not set")
	}
	if mw == nil {
		mw = oa.HTTPMiddleware()
	}
	userClaims := oa.OIDC.UserClaims
	serve := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		claims, err := userinfoClaims(r.Context(), userClaims, GetSubjectFromAPIContext(r.Context()), GetScopesFromAPIContext(r.Context()))
		if err != nil {
			log.Printf("apiauth: userinfo: %v", err)
			http.Error(w, "could not load user claims", http.StatusInternalServerError)
			return
		}
		noStore(w)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(claims)
	})
	return mw.RequireScopes(core.ScopeOpenID)(serve)
}
