package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

type HandleUserFunc func(authtype string, provider string, token *oauth2.Token, userInfo map[string]any, w http.ResponseWriter, r *http.Request)

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(10 * time.Minute)
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Println("Error generating rand: ", err)
	}
	state := base64.URLEncoding.EncodeToString(b)
	// HttpOnly: script has no use for the state, and reading it would let
	// an XSS forge a callback. Lax still sends it on the IdP's top-level
	// redirect back.
	cookie := http.Cookie{Name: "oauthstate", Value: state, Path: "/", Expires: expiration, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}
	http.SetCookie(w, &cookie)
	return state
}

// OauthRedirector creates a redirect handler with PKCE enabled (default).
func OauthRedirector(oauthConfig *oauth2.Config) func(w http.ResponseWriter, r *http.Request) {
	return OauthRedirectorWithPKCE(oauthConfig)
}

// OauthRedirectorNoPKCE creates a redirect handler WITHOUT PKCE.
// Use only for OAuth providers that don't support PKCE.
func OauthRedirectorNoPKCE(oauthConfig *oauth2.Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		oauthRedirectNoPKCE(oauthConfig, w, r)
	}
}

// OauthRedirectorWithPKCE creates a redirect handler with PKCE support (RFC 7636).
// Its cookies are Secure, which browsers also accept on http://localhost.
func OauthRedirectorWithPKCE(oauthConfig *oauth2.Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		oauthRedirectWithPKCE(oauthConfig, w, r)
	}
}

// setCallbackCookie remembers ?callbackURL= so the callback knows where to
// send the person afterwards.
func setCallbackCookie(w http.ResponseWriter, r *http.Request) {
	callbackURL := r.URL.Query().Get("callbackURL")
	if callbackURL == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "oauthCallbackURL",
		Value:    callbackURL,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		MaxAge:   120, // keep this short
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func oauthRedirectNoPKCE(oauthConfig *oauth2.Config, w http.ResponseWriter, r *http.Request, opts ...oauth2.AuthCodeOption) {
	setCallbackCookie(w, r)
	oauthState := generateStateOauthCookie(w)
	http.Redirect(w, r, oauthConfig.AuthCodeURL(oauthState, opts...), http.StatusFound)
}

func oauthRedirectWithPKCE(oauthConfig *oauth2.Config, w http.ResponseWriter, r *http.Request, opts ...oauth2.AuthCodeOption) {
	setCallbackCookie(w, r)
	oauthState := generateStateOauthCookie(w)

	// PKCE: generate code_verifier, store in cookie, send challenge in auth URL
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		log.Printf("PKCE: failed to generate code verifier: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	SetPKCECookie(w, verifier)
	challenge := computeCodeChallenge(verifier)

	opts = append(opts,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, oauthConfig.AuthCodeURL(oauthState, opts...), http.StatusFound)
}

// RedirectWithPKCE starts an authorization code flow from a handler: it
// sets the oauthstate, PKCE verifier and (from ?callbackURL=) callback
// cookies, then redirects to cfg's authorize URL with an S256
// code_challenge. opts add parameters to the authorize URL, such as an
// OpenID Connect nonce. A provider outside this package, like
// oauth2/oidc, uses it so every provider sets the same cookies.
func RedirectWithPKCE(cfg *oauth2.Config, w http.ResponseWriter, r *http.Request, opts ...oauth2.AuthCodeOption) {
	oauthRedirectWithPKCE(cfg, w, r, opts...)
}

// VerifyState reports whether the callback's state parameter equals the
// oauthstate cookie RedirectWithPKCE set. A missing cookie or a mismatch
// is false, and a mismatch also clears the cookie so a retry starts over.
func VerifyState(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie("oauthstate")
	if err != nil || c.Value == "" {
		return false
	}
	if r.FormValue("state") != c.Value {
		http.SetCookie(w, &http.Cookie{Name: "oauthstate", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		return false
	}
	return true
}
