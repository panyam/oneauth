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
	var expiration = time.Now().Add(30 * 24 * time.Hour)
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Println("Error generating rand: ", err)
	}
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Path: "/", Expires: expiration}
	http.SetCookie(w, &cookie)
	return state
}

func OauthRedirector(oauthConfig *oauth2.Config) func(w http.ResponseWriter, r *http.Request) {
	log.Println("creating redirector= ")
	return func(w http.ResponseWriter, r *http.Request) {
		// Create oauthState cookie and callback url cookie so we know where to redirect back to
		callbackURL := r.URL.Query().Get("callbackURL")
		if callbackURL != "" {
			var expiration = time.Now().Add(24 * time.Hour)
			// cookie := http.Cookie{Name: "oauthCallbackURL", Value: callbackURL, Expires: expiration, Path: "/"}
			// http.SetCookie(w, &cookie)
			http.SetCookie(w, &http.Cookie{
				Name:  "oauthCallbackURL",
				Value: callbackURL,
				// Domain:  cookieDomain,
				Path:    "/",
				Expires: expiration,
				MaxAge:  120, // keep this short
			})
		}
		oauthState := generateStateOauthCookie(w)
		u := oauthConfig.AuthCodeURL(oauthState)
		http.Redirect(w, r, u, http.StatusFound)
	}
}
