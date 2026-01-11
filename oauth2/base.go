package oauth2

import (
	"context"
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

	// HTTPClient is used for making HTTP requests during OAuth flows.
	// If nil, http.DefaultClient is used. This can be set for testing.
	HTTPClient *http.Client
}

// SetHTTPClient sets the HTTP client used for OAuth requests.
// This is primarily used for testing with mock servers.
func (b *BaseOAuth2) SetHTTPClient(client *http.Client) {
	b.HTTPClient = client
}

// getHTTPClient returns the HTTP client to use, defaulting to http.DefaultClient
func (b *BaseOAuth2) getHTTPClient() *http.Client {
	if b.HTTPClient != nil {
		return b.HTTPClient
	}
	return http.DefaultClient
}

// ExchangeContext returns a context configured with the HTTP client for token exchange
func (b *BaseOAuth2) ExchangeContext() context.Context {
	ctx := context.Background()
	if b.HTTPClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, b.HTTPClient)
	}
	return ctx
}

// SetOAuthEndpoint sets the OAuth endpoint (auth URL and token URL).
// This is primarily used for testing with mock servers.
func (b *BaseOAuth2) SetOAuthEndpoint(endpoint oauth2.Endpoint) {
	b.oauthConfig.Endpoint = endpoint
}

func (b *BaseOAuth2) Handler() http.Handler {
	return b.mux
}

func NewBaseOAuth2(clientId string, clientSecret string, callbackUrl string, handleUser HandleUserFunc) *BaseOAuth2 {
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
		HandleUser:     handleUser,
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
	b.mux.HandleFunc("/", OauthRedirector(&b.oauthConfig))

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
