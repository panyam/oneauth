// Package oidc is a sign-in provider for any OpenID Connect identity
// provider (Entra ID, Okta, Google Workspace, Keycloak), configured by
// issuer URL. It sits beside the GitHub and Google providers in
// github.com/panyam/oneauth/oauth2, mounts the same way, and calls the
// same HandleUserFunc. The difference is the user info: it comes from the
// verified ID token, never from an unauthenticated profile fetch.
//
// This package imports the root oneauth module for discovery and ID token
// verification (client.DiscoverASWithContext, client.VerifyIDToken). The
// parent oauth2 package does not, so an app using only GitHub or Google
// compiles none of it.
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/keys"
	signin "github.com/panyam/oneauth/oauth2"
)

const defaultTimeout = 10 * time.Second

// DefaultScopes are the scopes a sign-in asks for when Config.Scopes is
// empty. `openid` makes it an OpenID Connect request; `email` and
// `profile` ask for the claims an app usually needs to name the person.
var DefaultScopes = []string{"openid", "email", "profile"}

// NonceCookieName is the cookie holding the nonce between the redirect and
// the callback. The ID token must carry the same value (OIDC Core §3.1.2.1),
// which ties it to this browser's sign-in.
const NonceCookieName = "oidc_nonce"

// ErrNoDeviceEndpoint is returned by DeviceAuth when the provider's
// discovery document lists no device_authorization_endpoint.
var ErrNoDeviceEndpoint = errors.New("oidc: provider has no device_authorization_endpoint")

// Config configures a Provider. Issuer, ClientID and HandleUser are
// required. CallbackURL is required for the browser flow and unused by
// the device flow.
type Config struct {
	// Issuer is the provider's issuer URL, such as
	// https://login.microsoftonline.com/{tenant}/v2.0 or
	// http://localhost:8180/realms/myrealm. Discovery reads
	// {Issuer}/.well-known/openid-configuration, and the document's issuer
	// must equal this. It must be https; http is allowed only for a
	// loopback host, so a local Keycloak or a test server works.
	Issuer string

	ClientID     string
	ClientSecret string

	// CallbackURL is the absolute URL of the mounted handler's /callback/
	// route, registered with the provider as a redirect URI.
	CallbackURL string

	// Scopes replaces DefaultScopes. Include "openid".
	Scopes []string

	// ProviderName is the provider argument HandleUser receives. Default
	// "oidc".
	ProviderName string

	// HandleUser runs after the ID token verifies. Its userInfo is every
	// claim of the verified ID token. Use AllowList on it to decide who
	// may sign in.
	HandleUser signin.HandleUserFunc

	// AuthFailureURL is where a failed callback redirects. Default
	// "/auth/failed", as for the GitHub and Google providers.
	AuthFailureURL string

	// HTTPClient makes the discovery, JWKS, token and device requests.
	// Nil uses a client with a 10 second timeout.
	HTTPClient *http.Client
}

// Provider signs a person in through an OpenID Connect provider. Build one
// with New and mount Handler under a prefix, as for the GitHub provider:
// GET {prefix}/ starts a sign-in and {prefix}/callback/ finishes it.
// DeviceAuth and DeviceAccessToken sign a person in from a CLI.
//
// A Provider is safe for concurrent use once built.
type Provider struct {
	cfg    Config
	oauth  oauth2.Config
	meta   *client.ASMetadata
	keys   keys.KeyLookup
	client *http.Client
	mux    *http.ServeMux
}

// New runs discovery against cfg.Issuer and returns a Provider using the
// endpoints it lists. The discovery document is read once here and kept;
// the signing keys are fetched from its jwks_uri on first use and again
// when a token names a kid not yet seen, so a key rotation needs no
// restart. It fails when the issuer is not https (outside loopback), when
// discovery fails or names a different issuer, or when the document lacks
// an authorization, token or JWKS endpoint.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.ClientID == "" {
		return nil, errors.New("oidc: ClientID is required")
	}
	if cfg.HandleUser == nil {
		return nil, errors.New("oidc: HandleUser is required")
	}
	if err := checkIssuerURL(cfg.Issuer); err != nil {
		return nil, err
	}
	if cfg.ProviderName == "" {
		cfg.ProviderName = "oidc"
	}
	if cfg.AuthFailureURL == "" {
		cfg.AuthFailureURL = "/auth/failed"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = DefaultScopes
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}

	meta, err := client.DiscoverASWithContext(ctx, cfg.Issuer, client.WithHTTPClientForDiscovery(hc))
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}
	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" || meta.JWKSURI == "" {
		return nil, fmt.Errorf("oidc: discovery for %s lacks an authorization, token or jwks_uri endpoint", cfg.Issuer)
	}

	p := &Provider{
		cfg:  cfg,
		meta: meta,
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.CallbackURL,
			Scopes:       append([]string(nil), cfg.Scopes...),
			Endpoint: oauth2.Endpoint{
				AuthURL:       meta.AuthorizationEndpoint,
				TokenURL:      meta.TokenEndpoint,
				DeviceAuthURL: meta.DeviceAuthorizationEndpoint,
			},
		},
		keys:   keys.NewJWKSKeyStore(meta.JWKSURI, keys.WithHTTPClient(hc)),
		client: hc,
		mux:    http.NewServeMux(),
	}
	p.mux.HandleFunc("/", p.redirect)
	p.mux.HandleFunc("/callback/", p.callback)
	return p, nil
}

// Handler returns the routes to mount under a prefix with http.StripPrefix.
func (p *Provider) Handler() http.Handler { return p.mux }

// Metadata returns the discovery document New read.
func (p *Provider) Metadata() *client.ASMetadata { return p.meta }

func (p *Provider) redirect(w http.ResponseWriter, r *http.Request) {
	nonce, err := randomToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: NonceCookieName, Value: nonce, Path: "/", MaxAge: int(signin.PKCECookieTTL.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	signin.RedirectWithPKCE(&p.oauth, w, r, oauth2.SetAuthURLParam("nonce", nonce))
}

// callback checks state, exchanges the code with the PKCE verifier, and
// verifies the ID token against the nonce cookie before HandleUser runs.
// A bad or missing state, nonce cookie or verifier answers 400, since the
// browser didn't start this sign-in here. A failed exchange or ID token
// redirects to AuthFailureURL.
func (p *Provider) callback(w http.ResponseWriter, r *http.Request) {
	if !signin.VerifyState(w, r) {
		http.Error(w, "invalid oauth state", http.StatusBadRequest)
		return
	}
	nonceCookie, err := r.Cookie(NonceCookieName)
	if err != nil || nonceCookie.Value == "" {
		http.Error(w, "nonce missing; the sign-in may have expired", http.StatusBadRequest)
		return
	}
	verifier := signin.GetPKCEVerifier(r)
	if verifier == "" {
		http.Error(w, "PKCE verifier missing; the sign-in may have expired", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: NonceCookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	signin.ClearPKCECookie(w)

	if e := r.FormValue("error"); e != "" {
		slog.Info("oidc: provider returned an error", "error", e)
		http.Redirect(w, r, p.cfg.AuthFailureURL, http.StatusTemporaryRedirect)
		return
	}
	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, p.client)
	token, err := p.oauth.Exchange(ctx, r.FormValue("code"), oauth2.VerifierOption(verifier))
	if err == nil {
		var claims *client.IDTokenClaims
		claims, err = p.verify(ctx, token, nonceCookie.Value)
		if err == nil {
			p.cfg.HandleUser("oauth", p.cfg.ProviderName, token, claims.Claims, w, r)
			return
		}
	}
	slog.Info("oidc: sign-in failed", "err", err)
	http.Redirect(w, r, p.cfg.AuthFailureURL, http.StatusTemporaryRedirect)
}

// DeviceAuth starts an RFC 8628 device sign-in for a CLI. Show the person
// the response's VerificationURI (or VerificationURIComplete) and UserCode,
// then call DeviceAccessToken. It returns ErrNoDeviceEndpoint when
// discovery listed no device_authorization_endpoint.
func (p *Provider) DeviceAuth(ctx context.Context) (*oauth2.DeviceAuthResponse, error) {
	if p.oauth.Endpoint.DeviceAuthURL == "" {
		return nil, ErrNoDeviceEndpoint
	}
	// x/oauth2 sends only client_id here. RFC 8628 §3.1 has a
	// confidential client authenticate at this endpoint too, so the
	// secret goes in the form body (client_secret_post).
	var opts []oauth2.AuthCodeOption
	if p.cfg.ClientSecret != "" {
		opts = append(opts, oauth2.SetAuthURLParam("client_secret", p.cfg.ClientSecret))
	}
	return p.oauth.DeviceAuth(context.WithValue(ctx, oauth2.HTTPClient, p.client), opts...)
}

// DeviceAccessToken polls the token endpoint until the person approves,
// denies, or the device code expires, then verifies the ID token. The
// device flow has no nonce, so `nonce` isn't checked; signature, `iss`,
// `aud`, `exp` and `at_hash` are. Cancel ctx to stop polling.
func (p *Provider) DeviceAccessToken(ctx context.Context, da *oauth2.DeviceAuthResponse) (*oauth2.Token, *client.IDTokenClaims, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.client)
	token, err := p.oauth.DeviceAccessToken(ctx, da)
	if err != nil {
		return nil, nil, err
	}
	claims, err := p.verify(ctx, token, "")
	if err != nil {
		return nil, nil, err
	}
	return token, claims, nil
}

func (p *Provider) verify(ctx context.Context, token *oauth2.Token, nonce string) (*client.IDTokenClaims, error) {
	raw, _ := token.Extra("id_token").(string)
	if raw == "" {
		return nil, fmt.Errorf("%w: token response has no id_token", client.ErrInvalidIDToken)
	}
	return client.VerifyIDToken(ctx, &client.VerifyIDTokenRequest{
		IDToken:     raw,
		Issuer:      p.meta.Issuer,
		ClientID:    p.cfg.ClientID,
		Keys:        p.keys,
		Nonce:       nonce,
		AccessToken: token.AccessToken,
	})
}

func checkIssuerURL(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return fmt.Errorf("oidc: issuer %q is not an absolute URL", issuer)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("oidc: issuer %q must use https", issuer)
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
