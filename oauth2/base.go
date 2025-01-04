package oauth2

import (
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type BaseOAuth2 struct {
	ClientId     string
	ClientSecret string
	CallbackURL  string
	HandleUser   HandleUserFunc
	oauthConfig  oauth2.Config
	mux          *http.ServeMux
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
		ClientId:     clientId,
		ClientSecret: clientSecret,
		CallbackURL:  callbackUrl,
		mux:          http.NewServeMux(),
		oauthConfig: oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			RedirectURL:  callbackUrl,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
	}
	out.setupHandlers()
	return out
}

func (b *BaseOAuth2) setupHandlers() {
	// rg.HandleFunc("/google", OauthRedirector(oauthConfig))
	b.mux.HandleFunc("", OauthRedirector(&b.oauthConfig))
}
