package apiauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// ClientAssertionTypeJWTBearer is the OAuth assertion-type URN that
// MUST appear in the `client_assertion_type` form parameter when
// authenticating via private_key_jwt (RSA/ECDSA-keyed) or
// client_secret_jwt (HMAC-keyed) per RFC 7521 §4.2. Any other value
// is rejected. The two methods share the same wire protocol — the
// assertion-validation pipeline picks the verification path from the
// registered KeyRecord's Algorithm.
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// MaxClientAssertionLifetime caps how far in the future a client
// assertion's `exp` may be from `iat`. RFC 7523 §3 item 4 leaves the
// upper bound to the AS; OIDC Core §9 hints "short-lived". 5 minutes
// is the conventional ceiling matching most major IdPs and bounds the
// JTIStore memory footprint.
const MaxClientAssertionLifetime = 5 * time.Minute

// ClientAssertionClockSkew is how far a client assertion's `iat`, `nbf`
// and `exp` may be off from the server's clock. FAPI 2.0 §5.3.2.1 asks
// the server to accept an `iat` or `nbf` up to 10 seconds in the future,
// since client clocks drift, and to refuse one more than 60 seconds
// ahead. The same tolerance lets an assertion through up to 10 seconds
// after its `exp`.
const ClientAssertionClockSkew = 10 * time.Second

var errInvalidClient = &clientError{"invalid_client"}

type clientError struct{ msg string }

func (e *clientError) Error() string { return e.msg }

// clientAuthenticator implements ClientAuthenticator. The secret path
// uses constant-time comparison; the assertion path verifies a JWT
// signed by the client's registered key (RFC 7523 §2.2 / OIDC Core §9).
type clientAuthenticator struct {
	keyLookup keys.KeyLookup
	jtiStore  JTIStore
	appStore  core.AppRegistrationStore
	jwks      *ClientJWKSFetcher
}

// ClientAuthenticatorOptions configures NewClientAuthenticatorWithOptions.
// Every field is optional.
type ClientAuthenticatorOptions struct {
	// AppStore binds the presented auth method to the registered one
	// (issue 360), and is where a client's jwks_uri is found. Without it,
	// a jwks_uri client can't authenticate.
	AppStore core.AppRegistrationStore
	// JTIStore records assertion jtis for replay protection. Nil means an
	// in-memory store, which a multi-node deployment should replace.
	JTIStore JTIStore
	// JWKSFetcher fetches the key sets of clients registered with
	// jwks_uri. Nil means a default ClientJWKSFetcher, which refuses
	// private addresses.
	JWKSFetcher *ClientJWKSFetcher
}

// NewClientAuthenticatorWithOptions is NewClientAuthenticator with every
// optional dependency, including the fetcher for jwks_uri clients
// (issue 507).
func NewClientAuthenticatorWithOptions(kl keys.KeyLookup, opts ClientAuthenticatorOptions) ClientAuthenticator {
	a := newClientAuthenticator(kl, opts.AppStore, opts.JTIStore).(*clientAuthenticator)
	if opts.JWKSFetcher != nil {
		a.jwks = opts.JWKSFetcher
	}
	return a
}

// NewClientAuthenticator creates a ClientAuthenticator backed by a
// KeyLookup, with an in-memory JTIStore for assertion replay protection.
// For multi-node deployments use NewClientAuthenticatorWithJTIStore to
// wire a distributed JTI store.
func NewClientAuthenticator(kl keys.KeyLookup) ClientAuthenticator {
	return newClientAuthenticator(kl, nil, nil)
}

// NewClientAuthenticatorWithJTIStore is like NewClientAuthenticator but
// lets callers supply a custom JTIStore (Redis-backed, etc.).
func NewClientAuthenticatorWithJTIStore(kl keys.KeyLookup, jti JTIStore) ClientAuthenticator {
	return newClientAuthenticator(kl, nil, jti)
}

// NewClientAuthenticatorWithAppStore is like NewClientAuthenticator but also
// binds the presented client-auth method to the client's registered
// token_endpoint_auth_method (issue 360). When appStore is non-nil, a client
// registered as a confidential method (e.g. private_key_jwt) MUST authenticate
// with that method's family; presenting a different family (e.g. a shared
// secret) is rejected invalid_client, closing an auth-method downgrade. When
// appStore is nil the binding is skipped and behavior matches
// NewClientAuthenticator.
func NewClientAuthenticatorWithAppStore(kl keys.KeyLookup, appStore core.AppRegistrationStore) ClientAuthenticator {
	return newClientAuthenticator(kl, appStore, nil)
}

func newClientAuthenticator(kl keys.KeyLookup, appStore core.AppRegistrationStore, jti JTIStore) ClientAuthenticator {
	if jti == nil {
		jti = NewInMemoryJTIStore()
	}
	return &clientAuthenticator{keyLookup: kl, jtiStore: jti, appStore: appStore, jwks: &ClientJWKSFetcher{}}
}

// AuthenticateClient verifies the supplied client credentials. When
// req.ClientAssertion is set the assertion path runs; otherwise the
// raw-secret path runs. The response's ClientID echoes the authenticated
// client (extracted from the assertion `iss` for private_key_jwt /
// client_secret_jwt, equal to the request ClientID for
// client_secret_post / client_secret_basic). The response's Method
// classifies which mechanism actually authenticated the client —
// "client_secret" for the raw-secret paths; "private_key_jwt" or
// "client_secret_jwt" for the assertion path, picked by whether the
// registered key is asymmetric or HMAC.
func (a *clientAuthenticator) AuthenticateClient(ctx context.Context, req *AuthenticateClientRequest) (*AuthenticateClientResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("AuthenticateClientRequest is required")
	}
	if a.keyLookup == nil {
		return nil, errInvalidClient
	}
	var resp *AuthenticateClientResponse
	var err error
	if req.ClientAssertion != "" {
		resp, err = a.authenticateAssertion(ctx, req)
	} else {
		resp, err = a.authenticateSecret(req)
	}
	if err != nil {
		return nil, err
	}
	if berr := a.enforceAuthMethodBinding(ctx, resp.ClientID, resp.Method); berr != nil {
		return nil, berr
	}
	return resp, nil
}

// enforceAuthMethodBinding rejects a client that authenticated with a method
// outside the family it registered as (issue 360). It is a no-op unless an
// AppStore is wired: without the registration there is no declared method to
// bind to. A client that is unregistered, unresolvable, or registered "none"
// (public) is not bound either — the confidential-client gate and the
// grant-level policy own those cases; this check only stops a *registered
// confidential* client from downgrading (e.g. a private_key_jwt client
// authenticating with a shared secret, or the reverse).
//
// Binding is at the family level: client_secret_basic and client_secret_post
// both satisfy a "client_secret" result because the authenticator does not
// learn which channel carried the secret. private_key_jwt and
// client_secret_jwt each bind exactly.
func (a *clientAuthenticator) enforceAuthMethodBinding(ctx context.Context, clientID, presentedMethod string) error {
	if a.appStore == nil || clientID == "" {
		return nil
	}
	appResp, err := a.appStore.GetApp(ctx, &core.GetAppRequest{ClientID: clientID})
	if err != nil || appResp == nil || appResp.App == nil {
		// Unregistered / unresolvable: no declared method to bind to.
		return nil
	}
	registered := appResp.App.TokenEndpointAuthMethod
	if !isConfidentialAuthMethod(registered) {
		// "none" (or empty): a public client. Binding does not apply.
		return nil
	}
	if !authMethodFamilyMatches(registered, presentedMethod) {
		return fmt.Errorf("%w: presented auth method %q does not match registered token_endpoint_auth_method %q",
			errInvalidClient, presentedMethod, registered)
	}
	return nil
}

// authMethodFamilyMatches reports whether a presented auth method (as
// classified in AuthenticateClientResponse.Method: "client_secret",
// "private_key_jwt", or "client_secret_jwt") satisfies the client's registered
// token_endpoint_auth_method. client_secret_basic and client_secret_post are
// one family ("client_secret") — the presented-method classification does not
// distinguish the two channels, and neither is a downgrade of the other. Any
// method not recognized here fails closed (no match), so an unexpected
// registered value cannot silently permit a mismatched credential.
func authMethodFamilyMatches(registered, presented string) bool {
	switch registered {
	case "client_secret_basic", "client_secret_post":
		return presented == "client_secret"
	case "private_key_jwt":
		return presented == "private_key_jwt"
	case "client_secret_jwt":
		return presented == "client_secret_jwt"
	default:
		return false
	}
}

func (a *clientAuthenticator) authenticateSecret(req *AuthenticateClientRequest) (*AuthenticateClientResponse, error) {
	resp, err := a.keyLookup.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: req.ClientID})
	if err != nil || resp == nil || resp.Record == nil {
		return nil, errInvalidClient
	}
	rec := resp.Record
	storedKey, ok := rec.Key.([]byte)
	if !ok {
		return nil, errInvalidClient
	}
	if !constantTimeEqual(string(storedKey), req.ClientSecret) {
		return nil, errInvalidClient
	}
	return &AuthenticateClientResponse{ClientID: req.ClientID, Method: "client_secret"}, nil
}

// authenticateAssertion validates a JWT client assertion per RFC 7523
// §3 + OIDC Core §9. Covers both private_key_jwt (asymmetric-keyed)
// and client_secret_jwt (HMAC-keyed) — the wire protocol is identical;
// only the signature-verification key shape differs:
//
//   - client_assertion_type MUST be the registered URN.
//   - The JWT MUST be signed with an alg matching the client's
//     registered alg (no alg-confusion). For HS-registered clients
//     this means HS256/HS384/HS512 only; for RSA/ECDSA-registered
//     clients, RS*/ES*/PS* only — never crossable.
//   - iss == sub == client_id.
//   - aud MUST match the configured audience (token endpoint URL or
//     AS issuer URL — the caller decides which).
//   - exp MUST be in the future and iat / nbf (if present) in the
//     past, each within ClientAssertionClockSkew; the
//     assertion lifetime (exp - iat) MUST NOT exceed
//     MaxClientAssertionLifetime.
//   - jti MUST NOT have been seen within the assertion lifetime.
func (a *clientAuthenticator) authenticateAssertion(ctx context.Context, req *AuthenticateClientRequest) (*AuthenticateClientResponse, error) {
	if req.ClientAssertionType != ClientAssertionTypeJWTBearer {
		return nil, fmt.Errorf("%w: client_assertion_type must be %s", errInvalidClient, ClientAssertionTypeJWTBearer)
	}
	if len(req.Audiences) == 0 {
		// Misconfiguration on the handler side, not a client problem.
		// Surface loudly rather than silently accept any aud.
		return nil, errors.New("client assertion validation requires Audiences to be set on the request")
	}

	// First parse without verification so we can pull `iss` and look
	// up the key + algorithm. RFC 7521 §4.1 requires iss == sub ==
	// client_id.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(req.ClientAssertion, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: malformed client_assertion: %v", errInvalidClient, err)
	}
	claims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: assertion claims unparseable", errInvalidClient)
	}

	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if iss == "" || sub == "" {
		return nil, fmt.Errorf("%w: assertion missing iss or sub", errInvalidClient)
	}
	if iss != sub {
		return nil, fmt.Errorf("%w: assertion iss must equal sub", errInvalidClient)
	}
	clientID := iss
	// If the caller supplied a ClientID (from form `client_id` param),
	// it MUST agree with the assertion. RFC 7521 §4.1 — the assertion
	// names the client; a contradicting form param is a forgery
	// attempt or a confused caller.
	if req.ClientID != "" && req.ClientID != clientID {
		return nil, fmt.Errorf("%w: client_id form param does not match assertion iss/sub", errInvalidClient)
	}

	verifyKey, alg, err := a.assertionKey(ctx, clientID, unverified.Header)
	if err != nil {
		return nil, err
	}

	// Lock the alg to what the client registered. Without this an
	// attacker could swap RS256 for HS256 and use the public key as
	// the HMAC secret (algorithm-confusion, CVE-2016-10555 class).
	verifyParser := jwt.NewParser(jwt.WithValidMethods([]string{alg}), jwt.WithLeeway(ClientAssertionClockSkew), jwt.WithIssuedAt())
	verified, err := verifyParser.Parse(req.ClientAssertion, func(t *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: assertion signature/claims invalid: %v", errInvalidClient, err)
	}
	if !verified.Valid {
		return nil, fmt.Errorf("%w: assertion not valid (signature, exp, or nbf)", errInvalidClient)
	}
	verifiedClaims, ok := verified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: verified claims unparseable", errInvalidClient)
	}

	if len(req.AllowedAssertionAlgs) > 0 && !slices.Contains(req.AllowedAssertionAlgs, verified.Method.Alg()) {
		return nil, fmt.Errorf("%w: assertion algorithm %s is not allowed here", errInvalidClient, verified.Method.Alg())
	}
	if _, isString := verifiedClaims["aud"].(string); req.RequireStringAudience && !isString {
		return nil, fmt.Errorf("%w: assertion aud must be a single string", errInvalidClient)
	}
	matched := false
	for _, aud := range req.Audiences {
		if matchesAudience(verifiedClaims, aud) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, fmt.Errorf("%w: assertion aud does not match expected audience", errInvalidClient)
	}

	expDate, err := verifiedClaims.GetExpirationTime()
	if err != nil || expDate == nil {
		return nil, fmt.Errorf("%w: assertion missing or invalid exp", errInvalidClient)
	}
	iatDate, err := verifiedClaims.GetIssuedAt()
	if err != nil {
		return nil, fmt.Errorf("%w: assertion has invalid iat", errInvalidClient)
	}
	exp := expDate.Time
	var iat time.Time
	if iatDate != nil {
		iat = iatDate.Time
	} else {
		// Treat absent iat as the earliest moment that still keeps the
		// assertion within the max lifetime — equivalent to assuming
		// the client minted it `MaxClientAssertionLifetime` ago.
		iat = exp.Add(-MaxClientAssertionLifetime)
	}
	now := time.Now()
	lifetime := exp.Sub(iat)
	if lifetime <= 0 {
		return nil, fmt.Errorf("%w: assertion exp must be after iat", errInvalidClient)
	}
	if lifetime > MaxClientAssertionLifetime {
		return nil, fmt.Errorf("%w: assertion lifetime %s exceeds max %s", errInvalidClient, lifetime, MaxClientAssertionLifetime)
	}

	jti, _ := verifiedClaims["jti"].(string)
	if jti == "" {
		return nil, fmt.Errorf("%w: assertion missing jti", errInvalidClient)
	}
	// Replay-protection window must outlive the assertion itself; we
	// track until `exp` plus a small skew buffer.
	replayWindow := exp.Add(30 * time.Second).Sub(now)
	if replayWindow < lifetime {
		replayWindow = lifetime
	}
	if a.jtiStore != nil && a.jtiStore.SeenWithin(jti, replayWindow) {
		return nil, fmt.Errorf("%w: assertion jti has been replayed", errInvalidClient)
	}

	method := "private_key_jwt"
	if strings.HasPrefix(alg, "HS") {
		method = "client_secret_jwt"
	}
	return &AuthenticateClientResponse{ClientID: clientID, Method: method}, nil
}

// assertionKey returns the key that verifies clientID's assertion and the
// one algorithm it may use. A client registered with jwks_uri gets its key
// from jwksAssertionKey. Any other client has one stored key, whose
// registered algorithm is the only one allowed. Both HS* (client_secret_jwt)
// and RS*/ES*/PS* (private_key_jwt) stored keys go through
// utils.DecodeVerifyKey, which returns the raw HMAC bytes for symmetric
// algs and the parsed public key for asymmetric ones.
func (a *clientAuthenticator) assertionKey(ctx context.Context, clientID string, header map[string]any) (any, string, error) {
	if a.appStore != nil {
		if app, err := a.appStore.GetApp(ctx, &core.GetAppRequest{ClientID: clientID}); err == nil && app != nil && app.App != nil && (app.App.JWKSURI != "" || len(app.App.JWKS) > 0) {
			return a.jwksAssertionKey(ctx, app.App, header)
		} else if errors.Is(err, ErrClientMetadataUnavailable) {
			return nil, "", err
		}
	}
	keyResp, err := a.keyLookup.GetKey(ctx, &keys.GetKeyRequest{ClientID: clientID})
	if err != nil || keyResp == nil || keyResp.Record == nil {
		return nil, "", errInvalidClient
	}
	rec := keyResp.Record
	verifyKey, err := utils.DecodeVerifyKey(rec.Key, rec.Algorithm)
	if err != nil {
		return nil, "", fmt.Errorf("%w: cannot decode client key: %v", errInvalidClient, err)
	}
	return verifyKey, rec.Algorithm, nil
}

// jwksAssertionKey picks app's key from its jwks_uri by the assertion's
// kid (issue 507), refetching once when the kid is unknown so a rotated key
// is found. A client ID metadata document client may carry its keys inline
// instead (app.JWKS, issue 532), and those are used as they are. The algorithm is the header's, but only if the key's type can
// verify it (algFitsKey) and it matches token_endpoint_auth_signing_alg
// when the client registered one. So the header chooses among the
// algorithms the client's key allows, never outside them.
func (a *clientAuthenticator) jwksAssertionKey(ctx context.Context, app *core.AppRegistration, header map[string]any) (any, string, error) {
	kid, _ := header["kid"].(string)
	alg, _ := header["alg"].(string)
	var set *utils.JWKSet
	var err error
	if len(app.JWKS) > 0 {
		set = &utils.JWKSet{}
		err = json.Unmarshal(app.JWKS, set)
	} else {
		set, err = a.jwks.Keys(ctx, app.JWKSURI, false)
	}
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", errInvalidClient, err)
	}
	jwk, err := selectClientJWK(set, kid)
	if errors.Is(err, errNoClientKey) && app.JWKSURI != "" {
		if set, err = a.jwks.Keys(ctx, app.JWKSURI, true); err == nil {
			jwk, err = selectClientJWK(set, kid)
		}
	}
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", errInvalidClient, err)
	}
	if !algFitsKey(alg, jwk) {
		return nil, "", fmt.Errorf("%w: assertion alg %q can't be verified with the client's %s key", errInvalidClient, alg, jwk.Kty)
	}
	if app.TokenEndpointAuthSigningAlg != "" && alg != app.TokenEndpointAuthSigningAlg {
		return nil, "", fmt.Errorf("%w: assertion alg %q is not the registered token_endpoint_auth_signing_alg", errInvalidClient, alg)
	}
	pub, _, err := utils.JWKToPublicKey(jwk)
	if err != nil {
		return nil, "", fmt.Errorf("%w: client key: %v", errInvalidClient, err)
	}
	return pub, alg, nil
}
