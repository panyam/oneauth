package apiauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"mime"
	"net/http"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/httpauth"
)

// UserinfoHTTPHandler returns the OIDC Core §5.3 userinfo endpoint. It
// answers GET and POST (§5.3.1) with `sub` plus the claims
// OIDCConfig.UserClaims grants for the access token's scopes.
//
// mw authenticates the request; pass the deployment's resource-server
// middleware, with DPoP set when the AS issues DPoP-bound tokens, since a
// bound token presented to a middleware without it is refused. Nil uses
// HTTPMiddleware, which accepts Bearer tokens only. A token without the
// "openid" scope gets 403 insufficient_scope (RFC 6750 §3.1). A POST may
// send the token as a form-encoded `access_token` body parameter instead
// (RFC 6750 §2.2). Userinfo adds the claims the token's §5.5 `claims`
// request named (UserinfoClaimsClaim) to the ones its scopes grant.
//
// A client registered with userinfo_signed_response_alg gets the claims as
// a JWT signed by OneAuth.IDTokenIssuer's UserinfoSigner, with
// Content-Type application/jwt (§5.3.2). If the registered algorithm
// can't be served, the response is 500 rather than unsigned JSON, so the
// client never gets a form it didn't register for. Without AppStore every
// client gets JSON.
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
		subject := GetSubjectFromAPIContext(r.Context())
		claims, err := userinfoClaims(r.Context(), userClaims, subject, GetScopesFromAPIContext(r.Context()), requestedUserinfoClaims(r.Context()))
		if err == nil {
			// The client sees the same sub as in its ID token (OIDC Core
			// §5.3.2), which is pairwise for a pairwise client.
			claims["sub"], err = oa.SubjectForClient(r.Context(), tokenInfoClientID(GetTokenInfoFromAPIContext(r.Context())), subject)
		}
		if err != nil {
			log.Printf("apiauth: userinfo: %v", err)
			http.Error(w, "could not load user claims", http.StatusInternalServerError)
			return
		}
		clientID := tokenInfoClientID(GetTokenInfoFromAPIContext(r.Context()))
		if alg := oa.userinfoSigningAlg(r.Context(), clientID); alg != "" {
			signed, err := oa.signUserinfo(r.Context(), clientID, alg, claims)
			if err != nil {
				log.Printf("apiauth: userinfo: %v", err)
				http.Error(w, "could not sign the userinfo response", http.StatusInternalServerError)
				return
			}
			noStore(w)
			w.Header().Set("Content-Type", "application/jwt")
			_, _ = w.Write([]byte(signed))
			return
		}
		noStore(w)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(claims)
	})
	return formBodyAccessToken(mw.RequireScopes(core.ScopeOpenID)(serve))
}

// userinfoSigningAlg returns the userinfo_signed_response_alg clientID
// registered, or "" for plain JSON. A client the store can't find gets
// JSON too: the token validated, so the client is gone or was never
// registered (the SDK's "cli").
func (oa *OneAuth) userinfoSigningAlg(ctx context.Context, clientID string) string {
	if oa.AppStore == nil || clientID == "" {
		return ""
	}
	resp, err := oa.AppStore.GetApp(ctx, &core.GetAppRequest{ClientID: clientID})
	if err != nil || resp == nil || resp.App == nil {
		return ""
	}
	return resp.App.UserinfoSignedResponseAlg
}

// signUserinfo signs claims for clientID with alg, through the
// IDTokenIssuer's UserinfoSigner.
func (oa *OneAuth) signUserinfo(ctx context.Context, clientID, alg string, claims map[string]any) (string, error) {
	signer, ok := oa.IDTokenIssuer.(UserinfoSigner)
	if !ok {
		return "", fmt.Errorf("client %s registered userinfo_signed_response_alg %s, but the ID token issuer can't sign userinfo", clientID, alg)
	}
	resp, err := signer.SignUserinfo(ctx, &SignUserinfoRequest{ClientID: clientID, Alg: alg, Claims: claims})
	if err != nil {
		return "", err
	}
	return resp.Token, nil
}

// UserinfoClaimsClaim is the access-token claim that carries the claim
// names the OIDC Core §5.5 `claims` parameter asked userinfo for. The code
// grant sets it, and CustomClaimsFunc can't, so a client gets only what
// it asked for at /authorize.
const UserinfoClaimsClaim = "oa_userinfo_claims"

// requestedUserinfoClaims reads UserinfoClaimsClaim from the validated
// token in ctx.
func requestedUserinfoClaims(ctx context.Context) []string {
	raw, ok := GetCustomClaimsFromContext(ctx)[UserinfoClaimsClaim].([]any)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			names = append(names, s)
		}
	}
	return names
}

// formBodyAccessToken accepts the access token as a form-encoded
// `access_token` body parameter on POST (RFC 6750 §2.2, which OIDC Core
// §5.3.1 lists), by moving it to an Authorization: Bearer header for next.
// Only a form body counts, and only on POST. A request that also sends an
// Authorization header gets 400 invalid_request, since RFC 6750 §2 allows
// one method per request. A DPoP-bound token sent this way is a Bearer
// presentation, which the middleware refuses (RFC 9449 §7.2).
func formBodyAccessToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && mt == "application/x-www-form-urlencoded" {
				httpauth.CapRequestBody(nil, r)
				if err := r.ParseForm(); err != nil {
					http.Error(w, "could not parse form body", http.StatusBadRequest)
					return
				}
				if token := r.PostForm.Get("access_token"); token != "" {
					if r.Header.Get("Authorization") != "" {
						w.Header().Set("WWW-Authenticate", `Bearer error="invalid_request", error_description="send the access token in one place only"`)
						http.Error(w, "send the access token in one place only", http.StatusBadRequest)
						return
					}
					r = r.Clone(r.Context())
					r.Header.Set("Authorization", "Bearer "+token)
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// tokenInfoClientID is the client the validated access token was issued
// to: its client_id claim, else azp, as tokenClientID reads them.
func tokenInfoClientID(info *TokenInfo) string {
	if info == nil {
		return ""
	}
	if v, _ := info.CustomClaims["client_id"].(string); v != "" {
		return v
	}
	v, _ := info.CustomClaims["azp"].(string)
	return v
}
