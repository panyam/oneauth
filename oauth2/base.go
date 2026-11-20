package oauth2

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"

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

	// DisablePKCE disables Proof Key for Code Exchange (RFC 7636).
	// PKCE is enabled by default (zero value = enabled) because OAuth 2.1
	// requires it for all clients. Set to true only for providers that
	// don't support PKCE — a warning will be logged on startup.
	DisablePKCE bool

	// AllowedExtraScopes lists scopes a login link may add with ?scope=,
	// on top of Scopes(). It is how an app asks for more on a later connect
	// (for example GitHub's "repo" once a person connects a private repo).
	// A requested scope outside this list answers 400, so a crafted link
	// can't widen the grant. Empty means ?scope= is refused outright.
	AllowedExtraScopes []string
}

// Scopes returns the scopes every login asks for.
func (b *BaseOAuth2) Scopes() []string {
	return append([]string(nil), b.oauthConfig.Scopes...)
}

// SetScopes replaces the scopes every login asks for. Call it before
// serving; it isn't synchronized with requests in flight.
func (b *BaseOAuth2) SetScopes(scopes ...string) {
	b.oauthConfig.Scopes = append([]string(nil), scopes...)
}

// extraScopeOption reads ?scope= (space-separated) and returns an option
// setting the scope parameter to Scopes() plus the requested ones, or nil
// when none were requested. A scope not in AllowedExtraScopes is an error.
func (b *BaseOAuth2) extraScopeOption(r *http.Request) (oauth2.AuthCodeOption, error) {
	requested := strings.Fields(r.URL.Query().Get("scope"))
	if len(requested) == 0 {
		return nil, nil
	}
	scopes := b.Scopes()
	for _, sc := range requested {
		if slices.Contains(scopes, sc) {
			continue
		}
		if !slices.Contains(b.AllowedExtraScopes, sc) {
			return nil, fmt.Errorf("scope %q is not allowed", sc)
		}
		scopes = append(scopes, sc)
	}
	return oauth2.SetAuthURLParam("scope", strings.Join(scopes, " ")), nil
}

// redirect is the login handler. DisablePKCE is read per request, so it
// can be set after construction.
func (b *BaseOAuth2) redirect(w http.ResponseWriter, r *http.Request) {
	opt, err := b.extraScopeOption(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var opts []oauth2.AuthCodeOption
	if opt != nil {
		opts = append(opts, opt)
	}
	if b.DisablePKCE {
		oauthRedirectNoPKCE(&b.oauthConfig, w, r, opts...)
	} else {
		oauthRedirectWithPKCE(&b.oauthConfig, w, r, opts...)
	}
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

// SetOAuthEndpoint replaces the provider's authorize and token URLs. A
// test points them at a fake provider with it, alongside SetHTTPClient and
// the provider's UserInfoURL. For GitHub Enterprise, GithubOAuth2's
// SetEnterpriseURL sets all three. Call it before serving.
func (b *BaseOAuth2) SetOAuthEndpoint(endpoint oauth2.Endpoint) {
	b.oauthConfig.Endpoint = endpoint
}

func (b *BaseOAuth2) Handler() http.Handler {
	return b.mux
}

func NewBaseOAuth2(clientId string, clientSecret string, callbackUrl string, handleUser HandleUserFunc) *BaseOAuth2 {
	if clientId == "" {
		clientId = strings.TrimSpace(os.Getenv("OAUTH2_CLIENT_ID"))
	}
	if clientSecret == "" {
		clientSecret = strings.TrimSpace(os.Getenv("OAUTH2_CLIENT_SECRET"))
	}
	if callbackUrl == "" {
		callbackUrl = strings.TrimSpace(os.Getenv("OAUTH2_CALLBACK_URL"))
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
	if b.DisablePKCE {
		log.Printf("WARNING: PKCE disabled for OAuth2 provider (client_id=%s). "+
			"This is insecure for public clients (SPAs, mobile apps). "+
			"See: https://datatracker.ietf.org/doc/html/rfc7636", b.ClientId)
	}
	b.mux.HandleFunc("/", b.redirect)

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

// OAuthEndpoint returns the authorize and token URLs the provider uses.
func (b *BaseOAuth2) OAuthEndpoint() oauth2.Endpoint {
	return b.oauthConfig.Endpoint
}

// isLoopback reports whether host is localhost or a loopback IP.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
