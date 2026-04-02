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
	cookie := http.Cookie{Name: "oauthstate", Value: state, Path: "/", Expires: expiration}
	http.SetCookie(w, &cookie)
	return state
}

// OauthRedirector creates a redirect handler with PKCE enabled (default).
func OauthRedirector(oauthConfig *oauth2.Config) func(w http.ResponseWriter, r *http.Request) {
	return OauthRedirectorWithPKCE(oauthConfig, false)
}

// OauthRedirectorNoPKCE creates a redirect handler WITHOUT PKCE.
// Use only for OAuth providers that don't support PKCE.
func OauthRedirectorNoPKCE(oauthConfig *oauth2.Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		callbackURL := r.URL.Query().Get("callbackURL")
		if callbackURL != "" {
			http.SetCookie(w, &http.Cookie{
				Name:    "oauthCallbackURL",
				Value:   callbackURL,
				Path:    "/",
				Expires: time.Now().Add(24 * time.Hour),
				MaxAge:  120,
			})
		}
		oauthState := generateStateOauthCookie(w)
		u := oauthConfig.AuthCodeURL(oauthState)
		http.Redirect(w, r, u, http.StatusFound)
	}
}

// OauthRedirectorWithPKCE creates a redirect handler with PKCE support (RFC 7636).
// When secure is true, the PKCE cookie is marked Secure (HTTPS only).
func OauthRedirectorWithPKCE(oauthConfig *oauth2.Config, secure bool) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Create oauthState cookie and callback url cookie so we know where to redirect back to
		callbackURL := r.URL.Query().Get("callbackURL")
		if callbackURL != "" {
			http.SetCookie(w, &http.Cookie{
				Name:    "oauthCallbackURL",
				Value:   callbackURL,
				Path:    "/",
				Expires: time.Now().Add(24 * time.Hour),
				MaxAge:  120, // keep this short
			})
		}
		oauthState := generateStateOauthCookie(w)

		// PKCE: generate code_verifier, store in cookie, send challenge in auth URL
		verifier, err := GenerateCodeVerifier()
		if err != nil {
			log.Printf("PKCE: failed to generate code verifier: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		SetPKCECookie(w, verifier, secure)
		challenge := ComputeCodeChallenge(verifier)

		u := oauthConfig.AuthCodeURL(oauthState,
			oauth2.SetAuthURLParam("code_challenge", challenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
		http.Redirect(w, r, u, http.StatusFound)
	}
}
