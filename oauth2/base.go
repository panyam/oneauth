package oauth2

import (
	"net/http"
	"os"

	"golang.org/x/oauth2"
)

type BaseOAuth2 struct {
	ClientId       string
	ClientSecret   string
	CallbackURL    string
	HandleUser     HandleUserFunc
	AuthFailureUrl string
	oauthConfig    oauth2.Config
	mux            *http.ServeMux
}

func NewBaseOAuth2(clientId string, clientSecret string, callbackUrl string) *BaseOAuth2 {
	if clientId == "" {
		clientId = os.Getenv("OAUTH2_CLIENT_ID")
	}
	if clientSecret == "" {
		clientSecret = os.Getenv("OAUTH2_CLIENT_SECRET")
	}
	if callbackUrl == "" {
		callbackUrl = os.Getenv("OAUTH2_CALLBACK_URL")
	}
	out := &BaseOAuth2{
		ClientId:       clientId,
		ClientSecret:   clientSecret,
		CallbackURL:    callbackUrl,
		AuthFailureUrl: "/auth/failed",
		mux:            http.NewServeMux(),
		oauthConfig: oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			RedirectURL:  callbackUrl,
		},
	}
	out.setupHandlers()
	return out
}

func (b *BaseOAuth2) setupHandlers() {
	// rg.HandleFunc("/google", OauthRedirector(oauthConfig))
	b.mux.HandleFunc("", OauthRedirector(&b.oauthConfig))

	// An "easier" way to login by X if we already have the access tokens
	// If the access tokens have expired then the user would have to re login
	/*
		rg.HandleFunc("/login/", func(w http.ResponseWriter, r *http.Request) {
			var token oauth2.Token
			var err error
			if err = ctx.BindJSON(&token); err != nil {
				log.Println("Bind Error: ", err)
				// TOCHECK - should this be json?
				http.Error(w, err.Error(), http.StatusBadRequest)
			} else {
				userInfo, err := validateGithubAccessTokenToken(w, r, &token)
				if err != nil {
					// TOCHECK - should this be json?
					http.Error(w, "Could not validate access token", http.StatusBadRequest)
				} else {
					handleUser("X", &token, userInfo, w, r)
				}
			}
		}).Methods("POST")
	*/
}
