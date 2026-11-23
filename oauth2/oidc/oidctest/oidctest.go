// Package oidctest is a fake OpenID Provider for tests of an app that
// signs people in through github.com/panyam/oneauth/oauth2/oidc, or through
// any other OpenID Connect client. It serves discovery, a JWKS with one
// RS256 key, the authorization code flow with PKCE, the device flow (RFC
// 8628), RP-initiated logout, and a Microsoft Graph getMemberObjects route
// for Entra's groups overage.
//
// A test stands in for the person. AddUser makes a person with the claims
// their ID token carries. SignInAs picks who signs in, so /authorize
// redirects straight back with a code and no login page. Approve and Deny
// answer a pending device code.
//
//	iss := oidctest.New(t, oidctest.WithClient("app", "secret", "http://127.0.0.1:8080/callback/"))
//	iss.AddUser("u-123", map[string]any{"email": "ada@example.com", "email_verified": true})
//	iss.SignInAs("u-123")
//	// oidc.Config{Issuer: iss.URL, ClientID: "app", ClientSecret: "secret", ...}
//
// Error answers follow RFC 6749 and RFC 8628, checked against Keycloak by
// tests/keycloak's oidctest comparison test. The fake is stricter than most
// providers in one way: /authorize requires an S256 code_challenge, since
// OAuth 2.1 and FAPI 2.0 require PKCE and oidc.Provider always sends it.
// It also answers slow_down to a device poll that comes sooner than the
// advertised interval, as Keycloak does.
//
// WithDiscovery, WithIDTokenClaims and WithTokenResponse edit what the
// fake sends, so a test can check that its app refuses a bad answer.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/panyam/oneauth/utils"
)

// KeyID is the kid of the fake's signing key, in its JWKS and in every ID
// token header.
const KeyID = "oidctest-1"

// GraphPath is where the fake serves Microsoft Graph. Point
// oidc.EntraGroups.GraphURL at Server.GraphURL to use it.
const GraphPath = "/graph/v1.0"

// DefaultDeviceInterval is the polling interval a device authorization
// response names, unless WithDeviceInterval changes it. One second is the
// smallest the integer field can say, and it keeps a polling test short.
// The fake answers slow_down to a poll that comes sooner.
const DefaultDeviceInterval = time.Second

// DefaultDeviceExpiry is how long a device code stays usable, unless
// WithDeviceExpiry changes it.
const DefaultDeviceExpiry = 5 * time.Minute

// Server is the fake. Its URL is the issuer, and the origin of every
// endpoint discovery lists. Close it with t.Cleanup, which New registers.
// A Server is safe for concurrent use.
type Server struct {
	*httptest.Server

	clients        map[string]string   // client id -> secret, "" for a public client
	redirects      map[string][]string // client id -> registered redirect URIs
	discovery      []func(map[string]any)
	idTokenClaims  []func(map[string]any)
	tokenResponse  []func(map[string]any)
	groupsOverage  bool
	deviceInterval time.Duration
	deviceExpiry   time.Duration

	mu       sync.Mutex
	users    map[string]map[string]any // by sub
	signedIn string                    // the sub SignInAs picked
	codes    map[string]*authCode
	devices  map[string]*deviceGrant // by device code
	byUser   map[string]string       // user code -> device code
	access   map[string]string       // access token -> sub
}

// Option configures a Server in New.
type Option func(*Server)

// WithClient registers a client. An empty secret makes a public client,
// which authenticates with client_id alone. A confidential client may send
// its secret as HTTP Basic auth or as client_secret in the form. Pass it
// once per client. New fails the test when no client is registered.
//
// redirectURIs are the URIs /authorize may send the browser back to, and
// /logout's post_logout_redirect_uri too. A request's URI must equal one
// exactly (RFC 9700 §4.1.1), or the fake answers 400 and redirects
// nowhere, as Keycloak does. A client used only for the device flow needs
// none.
func WithClient(id, secret string, redirectURIs ...string) Option {
	return func(s *Server) {
		s.clients[id] = secret
		s.redirects[id] = append(s.redirects[id], redirectURIs...)
	}
}

// WithDiscovery edits the discovery document before each response. Delete
// "device_authorization_endpoint" to test a provider without the device
// flow, or set "issuer" to test an issuer mismatch.
func WithDiscovery(edit func(doc map[string]any)) Option {
	return func(s *Server) { s.discovery = append(s.discovery, edit) }
}

// WithIDTokenClaims edits each ID token's claims just before signing, so
// the token still verifies. Use it to send a wrong nonce or audience.
func WithIDTokenClaims(edit func(claims map[string]any)) Option {
	return func(s *Server) { s.idTokenClaims = append(s.idTokenClaims, edit) }
}

// WithTokenResponse edits each successful token response just before it
// is sent. The signed ID token is resp["id_token"], so a test can delete
// it or change a byte of it.
func WithTokenResponse(edit func(resp map[string]any)) Option {
	return func(s *Server) { s.tokenResponse = append(s.tokenResponse, edit) }
}

// WithGroupsOverage makes ID tokens leave out a person's "groups" claim
// the way Entra ID does past 200 groups (OIDC Core §5.6.2 distributed
// claims). The token carries `_claim_names` naming groups and
// `_claim_sources` pointing at the fake's Graph getMemberObjects route,
// which answers the person's groups for the access token from the same
// sign-in. A person with no "groups" claim gets neither.
func WithGroupsOverage() Option {
	return func(s *Server) { s.groupsOverage = true }
}

// WithDeviceInterval sets the interval a device authorization response
// names. It is rounded down to whole seconds, and anything under one
// second becomes one, since clients treat 0 as "use the default of 5".
// A poll sooner than this after the previous one answers slow_down.
func WithDeviceInterval(d time.Duration) Option {
	return func(s *Server) { s.deviceInterval = d }
}

// WithDeviceExpiry sets how long a device code stays usable. A poll after
// that answers expired_token.
func WithDeviceExpiry(d time.Duration) Option {
	return func(s *Server) { s.deviceExpiry = d }
}

// New starts a fake issuer and closes it when the test ends.
func New(t testing.TB, opts ...Option) *Server {
	t.Helper()
	s := &Server{
		clients:        map[string]string{},
		redirects:      map[string][]string{},
		deviceInterval: DefaultDeviceInterval,
		deviceExpiry:   DefaultDeviceExpiry,
		users:          map[string]map[string]any{},
		codes:          map[string]*authCode{},
		devices:        map[string]*deviceGrant{},
		byUser:         map[string]string{},
		access:         map[string]string{},
	}
	for _, o := range opts {
		o(s)
	}
	if len(s.clients) == 0 {
		t.Fatal("oidctest: New needs at least one WithClient")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.serveDiscovery)
	mux.HandleFunc("GET /jwks", s.serveJWKS)
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("POST /device_authorization", s.deviceAuthorization)
	mux.HandleFunc("GET /device", s.verificationPage)
	mux.HandleFunc("GET /logout", s.logout)
	mux.HandleFunc("POST "+GraphPath+"/me/getMemberObjects", s.getMemberObjects)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// AddUser makes a person. claims are the extra claims their ID tokens
// carry, such as email, email_verified, name or groups. The fake sets iss,
// sub, aud, exp, iat, at_hash and nonce itself, and those win over the
// same names in claims. Adding a sub again replaces its claims.
func (s *Server) AddUser(sub string, claims map[string]any) {
	c := make(map[string]any, len(claims))
	for k, v := range claims {
		c[k] = v
	}
	s.mu.Lock()
	s.users[sub] = c
	s.mu.Unlock()
}

// SignInAs picks the person the next /authorize signs in. It stays picked
// until the next call. With no one picked, /authorize redirects back with
// error=login_required. It panics when sub was never added, since that is
// a mistake in the test.
func (s *Server) SignInAs(sub string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[sub]; !ok {
		panic("oidctest: SignInAs(" + sub + "): no such user; call AddUser first")
	}
	s.signedIn = sub
}

// GraphURL is the root to set as oidc.EntraGroups.GraphURL, so a test can
// resolve groups overage against this fake.
func (s *Server) GraphURL() string { return s.URL + GraphPath }

func (s *Server) serveDiscovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]any{
		"issuer":                                s.URL,
		"authorization_endpoint":                s.URL + "/authorize",
		"token_endpoint":                        s.URL + "/token",
		"jwks_uri":                              s.URL + "/jwks",
		"device_authorization_endpoint":         s.URL + "/device_authorization",
		"end_session_endpoint":                  s.URL + "/logout",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"grant_types_supported": []string{
			"authorization_code", "urn:ietf:params:oauth:grant-type:device_code",
		},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
	}
	for _, edit := range s.discovery {
		edit(doc)
	}
	writeJSON(w, http.StatusOK, doc)
}

func (s *Server) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, utils.JWKSet{Keys: []utils.JWK{
		utils.RSAPublicKeyToJWK(KeyID, "RS256", &signingKey().PublicKey),
	}})
}

// idToken signs an ID token for sub. nonce is empty in the device flow.
func (s *Server) idToken(sub, clientID, nonce, accessToken string) (string, error) {
	s.mu.Lock()
	user := s.users[sub]
	claims := jwt.MapClaims{}
	for k, v := range user {
		claims[k] = v
	}
	s.mu.Unlock()

	if _, has := claims["groups"]; has && s.groupsOverage {
		delete(claims, "groups")
		claims["_claim_names"] = map[string]any{"groups": "src1"}
		claims["_claim_sources"] = map[string]any{
			"src1": map[string]any{"endpoint": s.GraphURL() + "/me/getMemberObjects"},
		}
	}
	sum := sha256.Sum256([]byte(accessToken))
	now := time.Now()
	claims["iss"] = s.URL
	claims["sub"] = sub
	claims["aud"] = clientID
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(5 * time.Minute).Unix()
	claims["at_hash"] = base64.RawURLEncoding.EncodeToString(sum[:16])
	if nonce != "" {
		claims["nonce"] = nonce
	}
	for _, edit := range s.idTokenClaims {
		edit(claims)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = KeyID
	return tok.SignedString(signingKey())
}

// getMemberObjects answers Graph's POST /me/getMemberObjects with the
// groups of the person the bearer token belongs to.
func (s *Server) getMemberObjects(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	sub, known := s.access[tok]
	groups := s.users[sub]["groups"]
	s.mu.Unlock()
	if !ok || !known {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": map[string]any{"code": "InvalidAuthenticationToken", "message": "Access token is empty or invalid."},
		})
		return
	}
	value := []string{}
	switch g := groups.(type) {
	case []string:
		value = append(value, g...)
	case []any:
		for _, v := range g {
			if str, ok := v.(string); ok {
				value = append(value, str)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": value})
}

var (
	keyOnce sync.Once
	key     *rsa.PrivateKey
)

// signingKey is shared by every Server in the process, since a 2048-bit
// RSA key takes long enough to generate to slow a suite that starts many
// fakes. Each fake's tokens still carry its own iss.
func signingKey() *rsa.PrivateKey {
	keyOnce.Do(func() {
		var err error
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic("oidctest: generating the signing key: " + err.Error())
		}
	})
	return key
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("oidctest: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
