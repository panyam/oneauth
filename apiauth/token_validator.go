package apiauth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/tracing"
	"github.com/panyam/oneauth/utils"
)

// jwtValidator implements TokenValidator using local JWT validation.
// Dependencies are explicit and minimal: KeyLookup (read-only), Blacklist,
// issuer/audience config, and security hooks. SigningKey is an optional
// self-validation fallback (used when no KeyLookup is configured or the
// token's kid / client_id doesn't resolve through it) — supports the
// "APIAuth holds its own key" mode that doesn't need a KeyStore.
type jwtValidator struct {
	keyLookup      keys.KeyLookup
	signingKey     any
	signingAlg     string
	blacklist      core.TokenBlacklist
	issuer         string
	audience       string
	audienceFunc   func() string
	hooks          SecurityHooks
	tracerProvider trace.TracerProvider
	ownKid         string // kid of signingKey; tokens it signed skip the tenant check
	keySource      SigningKeySource
	ownKeyClientID string
}

// resolveAudience returns the currently-expected audience: AudienceFunc's
// non-empty return value if set, otherwise the eager Audience.
func (v *jwtValidator) resolveAudience() string {
	if v.audienceFunc != nil {
		if got := v.audienceFunc(); got != "" {
			return got
		}
	}
	return v.audience
}

// JWTValidatorConfig configures a jwtValidator.
type JWTValidatorConfig struct {
	KeyLookup keys.KeyLookup
	// SigningKey is an optional fallback used when KeyLookup is nil or the
	// token's kid / client_id does not resolve through it. For HS256, supply
	// []byte; for RS256/ES256, supply the verification key (*rsa.PublicKey,
	// *ecdsa.PublicKey) directly.
	SigningKey any
	SigningAlg string
	Blacklist  core.TokenBlacklist
	Issuer     string
	Audience   string
	// AudienceFunc, when non-nil, is consulted on every ValidateToken
	// call. A non-empty return takes precedence over Audience. See
	// OneAuthConfig.AudienceFunc for the canonical use case.
	AudienceFunc func() string
	Hooks        SecurityHooks

	// SigningKeySource, when set, replaces SigningKey: the validator's own
	// key is the public half of the source's current key, read per token,
	// so it follows a rotation. Tokens signed with a retired key verify
	// through KeyLookup (the KidStore) instead, for as long as it keeps
	// them.
	SigningKeySource SigningKeySource

	// OwnKeyClientID is the KeyStore client_id the AS's own public keys are
	// registered under. A key record with that client_id verifies the AS's
	// own tokens, which carry any client's client_id, so it skips the
	// tenant check. That covers a retired own key in the KidStore, whose
	// kid is no longer the current one. Empty exempts only the current
	// key.
	OwnKeyClientID string

	// TracerProvider opts the signature-verify hot path into SEP-414
	// tracing. When set, ValidateToken emits an `oneauth.signature_verify`
	// span (attributes: `jwt.alg`, `jwt.kid`). Nil keeps the path on the
	// no-op fast path. Typically populated from APIAuth.TracerProvider
	// so spans nest under `oneauth.token.issue` (issuer) or under the
	// caller's span (resource server).
	TracerProvider trace.TracerProvider
}

// NewJWTValidator creates a TokenValidator that validates JWTs locally.
func NewJWTValidator(cfg JWTValidatorConfig) TokenValidator {
	return &jwtValidator{
		keyLookup:      cfg.KeyLookup,
		signingKey:     cfg.SigningKey,
		signingAlg:     cfg.SigningAlg,
		blacklist:      cfg.Blacklist,
		issuer:         cfg.Issuer,
		audience:       cfg.Audience,
		audienceFunc:   cfg.AudienceFunc,
		hooks:          cfg.Hooks,
		tracerProvider: cfg.TracerProvider,
		ownKid:         kidOf(cfg.SigningKey, cfg.SigningAlg),
		keySource:      cfg.SigningKeySource,
		ownKeyClientID: cfg.OwnKeyClientID,
	}
}

// ownKey is the validator's own verify key and its kid: from the source's
// current key when there is one, else the configured SigningKey.
func (v *jwtValidator) ownKey() (any, string) {
	if v.keySource != nil {
		key, alg := v.keySource.CurrentSigningKey()
		return verifyKeyAndKid(key, alg)
	}
	return v.signingKey, v.ownKid
}

// ValidateToken parses and validates a JWT, returning the extracted claims
// wrapped in a ValidateTokenResponse per the (ctx, *Req) → (*Resp, error)
// convention adopted in 175.
func (v *jwtValidator) ValidateToken(ctx context.Context, req *ValidateTokenRequest) (*ValidateTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("ValidateTokenRequest is required")
	}
	_, span := tracing.Tracer(v.tracerProvider, tracing.InstrumentationName).
		Start(ctx, "oneauth.signature_verify")
	defer span.End()

	tokenString := req.Token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if alg, ok := token.Header["alg"].(string); ok {
			span.SetAttributes(attribute.String("jwt.alg", alg))
		}
		if kid, ok := token.Header["kid"].(string); ok && kid != "" {
			span.SetAttributes(attribute.String("jwt.kid", kid))
		}
		return v.resolveKey(token)
	}, accessTokenParserOptions()...)
	if err != nil {
		span.SetStatus(codes.Error, "parse error")
		span.RecordError(err)
		v.hooks.fireOnTokenRejected(fmt.Sprintf("parse error: %v", err))
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if !token.Valid {
		span.SetStatus(codes.Error, "token validation failed")
		v.hooks.fireOnTokenRejected("token validation failed")
		return nil, fmt.Errorf("token validation failed")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	// Only access tokens: not logout tokens, ID-JAGs or sessions signed
	// with the same key.
	if err := checkAccessTokenKind(token, claims); err != nil {
		v.hooks.fireOnTokenRejected("invalid token type")
		return nil, err
	}

	// Verify issuer
	if v.issuer != "" {
		if iss, ok := claims["iss"].(string); !ok || iss != v.issuer {
			v.hooks.fireOnTokenRejected("invalid issuer")
			return nil, fmt.Errorf("invalid issuer")
		}
	}

	// Verify audience — AudienceFunc takes precedence when non-empty.
	if expectedAud := v.resolveAudience(); expectedAud != "" {
		if !matchesAudience(claims, expectedAud) {
			v.hooks.fireOnTokenRejected("invalid audience")
			return nil, fmt.Errorf("invalid audience")
		}
	}

	// Extract subject
	userID, ok := claims["sub"].(string)
	if !ok || userID == "" {
		return nil, fmt.Errorf("missing subject")
	}

	// Extract scopes
	var scopes []string
	if scopesRaw, ok := claims["scopes"].([]any); ok {
		scopes = make([]string, 0, len(scopesRaw))
		for _, s := range scopesRaw {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
	}

	// Extract authorization_details (RFC 9396)
	var authzDetails []core.AuthorizationDetail
	if adRaw, ok := claims["authorization_details"].([]any); ok {
		authzDetails = parseAuthorizationDetailsFromClaims(adRaw)
	}

	// Extract custom claims
	customClaims := make(map[string]any)
	for k, v := range claims {
		if !standardClaims[k] {
			customClaims[k] = v
		}
	}

	// Check blacklist
	if v.blacklist != nil {
		if jti, ok := claims["jti"].(string); ok && jti != "" {
			if v.blacklist.IsRevoked(jti) {
				v.hooks.fireOnBlacklistHit(jti)
				v.hooks.fireOnTokenRejected("token has been revoked")
				return nil, fmt.Errorf("token has been revoked")
			}
		}
	}

	clientID := tokenClientID(claims)
	tokenID, _ := claims["jti"].(string)
	var expiresAt time.Time
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		expiresAt = exp.Time
	}
	var issuedAt time.Time
	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
		issuedAt = iat.Time
	}
	return &ValidateTokenResponse{Info: &TokenInfo{
		Subject:              userID,
		Scopes:               scopes,
		AuthorizationDetails: authzDetails,
		CustomClaims:         customClaims,
		AuthType:             "jwt",
		Confirmation:         confirmationFromClaims(claims),
		ClientID:             clientID,
		TokenID:              tokenID,
		ExpiresAt:            expiresAt,
		IssuedAt:             issuedAt,
	}}, nil
}

// tokenClientID is the client a verified access token was issued to. It is
// the `client_id` claim (RFC 9068 §2.2) when present, else `azp`. Keycloak
// names a user token's client only in `azp`, and revocation ownership treats
// a token with no client as anyone's, so dropping `azp` would let any
// client revoke such a token.
func tokenClientID(claims jwt.MapClaims) string {
	if v, _ := claims["client_id"].(string); v != "" {
		return v
	}
	v, _ := claims["azp"].(string)
	return v
}

// confirmationFromClaims reads the RFC 7800 `cnf` claim. A token with no
// `cnf`, or one whose `cnf` names no key this build understands, returns nil
// and is treated as a plain bearer token — the alternative, inventing an
// empty Confirmation, would assert a binding no key can satisfy and lock the
// legitimate client out.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-6
func confirmationFromClaims(claims jwt.MapClaims) *core.Confirmation {
	raw, ok := claims["cnf"].(map[string]any)
	if !ok {
		return nil
	}
	jkt, _ := raw["jkt"].(string)
	if jkt == "" {
		return nil
	}
	return &core.Confirmation{JKT: jkt}
}

// CheckScopes validates a token and verifies it contains all required scopes.
func (v *jwtValidator) CheckScopes(ctx context.Context, req *CheckScopesRequest) (*CheckScopesResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("CheckScopesRequest is required")
	}
	resp, err := v.ValidateToken(ctx, &ValidateTokenRequest{Token: req.Token})
	if err != nil {
		return nil, err
	}
	if !core.ContainsAllScopes(resp.Info.Scopes, req.RequiredScopes) {
		return nil, fmt.Errorf("insufficient scope: requires %v, has %v", req.RequiredScopes, resp.Info.Scopes)
	}
	return &CheckScopesResponse{}, nil
}

// CheckAuthorizationDetails validates a token and verifies it contains
// authorization_details entries for all required types.
func (v *jwtValidator) CheckAuthorizationDetails(ctx context.Context, req *CheckAuthorizationDetailsRequest) (*CheckAuthorizationDetailsResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("CheckAuthorizationDetailsRequest is required")
	}
	resp, err := v.ValidateToken(ctx, &ValidateTokenRequest{Token: req.Token})
	if err != nil {
		return nil, err
	}
	info := resp.Info
	grantedTypes := make(map[string]bool)
	for _, ad := range info.AuthorizationDetails {
		grantedTypes[ad.Type] = true
	}
	for _, reqType := range req.RequiredTypes {
		if !grantedTypes[reqType] {
			return nil, fmt.Errorf("missing required authorization_details type: %s", reqType)
		}
	}
	return &CheckAuthorizationDetailsResponse{}, nil
}

// resolveKey finds the appropriate signing key for a JWT token.
func (v *jwtValidator) resolveKey(token *jwt.Token) (any, error) {
	// A token naming our own kid was signed by us. Resolving it through
	// KeyLookup instead would fall back to the client_id claim and verify
	// an AS-issued token against that client's key.
	ownKey, ownKid := v.ownKey()
	if kid, _ := token.Header["kid"].(string); ownKid != "" && kid == ownKid {
		return v.signingKeyFor(token, ownKey)
	}

	// Try kid-based lookup first (only when a KeyLookup is configured)
	if v.keyLookup != nil {
		if kid, ok := token.Header["kid"].(string); ok && kid != "" {
			kidResp, err := v.keyLookup.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: kid})
			if err == nil && kidResp != nil && kidResp.Record != nil {
				rec := kidResp.Record
				if token.Header["alg"] != rec.Algorithm {
					v.hooks.fireOnAlgorithmMismatch(rec.Algorithm, fmt.Sprintf("%v", token.Header["alg"]))
					return nil, fmt.Errorf("algorithm mismatch: expected %s, got %v", rec.Algorithm, token.Header["alg"])
				}
				if v.ownKeyClientID == "" || rec.ClientID != v.ownKeyClientID {
					if err := checkTenantKey(rec, ownKid, token); err != nil {
						return nil, err
					}
				}
				return utils.DecodeVerifyKey(rec.Key, rec.Algorithm)
			}
		}

		// Fall back to client_id claim
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if clientID, ok := claims["client_id"].(string); ok && clientID != "" {
				getResp, err := v.keyLookup.GetKey(context.Background(), &keys.GetKeyRequest{ClientID: clientID})
				if err == nil && getResp != nil && getResp.Record != nil {
					rec := getResp.Record
					if token.Header["alg"] != rec.Algorithm {
						v.hooks.fireOnAlgorithmMismatch(rec.Algorithm, fmt.Sprintf("%v", token.Header["alg"]))
						return nil, fmt.Errorf("algorithm mismatch: expected %s, got %v", rec.Algorithm, token.Header["alg"])
					}
					return utils.DecodeVerifyKey(rec.Key, rec.Algorithm)
				}
			}
		}
	}

	// Self-validation fallback: the validator was configured with its own
	// SigningKey (typical APIAuth shape — one key, no KeyStore).
	if ownKey != nil {
		return v.signingKeyFor(token, ownKey)
	}

	if v.keyLookup == nil {
		return nil, fmt.Errorf("no key store configured")
	}
	return nil, fmt.Errorf("no key found for token")
}

// signingKeyFor returns the validator's own key for a token, after checking
// the token's alg is one that key can verify.
func (v *jwtValidator) signingKeyFor(token *jwt.Token, key any) (any, error) {
	switch k := key.(type) {
	case []byte:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// An empty HMAC key verifies any token signed with the empty
		// key (RFC 7518 §3.2 wants at least the hash size).
		if len(k) == 0 {
			return nil, fmt.Errorf("no HMAC key configured")
		}
		return k, nil
	default:
		// Asymmetric key — type-check against the token's alg before returning.
		if v.signingAlg != "" && token.Header["alg"] != v.signingAlg {
			v.hooks.fireOnAlgorithmMismatch(v.signingAlg, fmt.Sprintf("%v", token.Header["alg"]))
			return nil, fmt.Errorf("algorithm mismatch: expected %s, got %v", v.signingAlg, token.Header["alg"])
		}
		return key, nil
	}
}

// jwtIssuer implements TokenIssuer using JWT signing.
type jwtIssuer struct {
	signingKey          any              // []byte for HS256, *rsa.PrivateKey for RS256, *ecdsa.PrivateKey for ES256
	keySource           SigningKeySource // when set, supplies the key in place of signingKey
	signingAlg          string           // "HS256", "RS256", "ES256"
	issuer              string
	audience            string
	audienceFunc        func() string
	accessExpiry        time.Duration
	clientKeyLookup     keys.KeyLookup
	refreshStore        core.RefreshTokenStore
	validateCredentials CredentialsValidator
	getSubjectScopes    core.GetSubjectScopesFunc
	customClaims        CustomClaimsFunc
	hooks               TokenHooks
	disableRotation     bool
	blacklist           core.TokenBlacklist
	idTokens            IDTokenIssuer
	allowedResources    []string
}

// resolveAudience returns the currently-configured aud claim value:
// AudienceFunc's non-empty return takes precedence over the eager
// Audience.
func (i *jwtIssuer) resolveAudience() string {
	if i.audienceFunc != nil {
		if got := i.audienceFunc(); got != "" {
			return got
		}
	}
	return i.audience
}

// CustomClaimsFunc is called during access-token issuance to inject additional
// non-standard claims. Returning a claim key that collides with a standard JWT
// claim (sub, iss, aud, exp, iat, type, scopes, jti, authorization_details)
// is ignored with a log warning — standard claims are owned by the issuer.
type CustomClaimsFunc func(subject string, scopes []string) (map[string]any, error)

// JWTIssuerConfig configures a jwtIssuer.
type JWTIssuerConfig struct {
	SigningKey any
	SigningAlg string
	// SigningKeySource, when set, supplies the key on every mint in place
	// of SigningKey, so it can rotate (RotatingSigningKey). SigningAlg must
	// match its algorithm.
	SigningKeySource SigningKeySource
	Issuer           string
	Audience         string
	// AudienceFunc, when non-nil, is consulted on each access-token
	// mint. A non-empty return takes precedence over Audience. See
	// OneAuthConfig.AudienceFunc for the canonical use case.
	AudienceFunc        func() string
	AccessExpiry        time.Duration
	ClientKeyLookup     keys.KeyLookup            // for client_credentials authentication
	RefreshStore        core.RefreshTokenStore    // for refresh_token grant
	ValidateCredentials CredentialsValidator      // for password grant
	GetSubjectScopes    core.GetSubjectScopesFunc // for password grant (optional)
	CustomClaims        CustomClaimsFunc          // optional per-token custom-claim injection
	Hooks               TokenHooks

	// DisableRefreshTokenRotation mirrors
	// OneAuthConfig.DisableRefreshTokenRotation.
	DisableRefreshTokenRotation bool

	// Blacklist receives the access tokens of a refresh family revoked on
	// reuse detection (RFC 9700 §4.14.2). Without one the family's
	// refresh tokens are revoked and its access tokens live until they
	// expire.
	Blacklist core.TokenBlacklist

	// IDTokens mints the ID token a refresh of an OpenID Connect grant
	// returns (OIDC Core §12.2). It runs only for refresh tokens that
	// carry an OIDCGrant, which the authorization-code grant stores when
	// it issues an ID token. Nil issues no ID token on refresh.
	IDTokens IDTokenIssuer

	// AllowedResources mirrors OneAuthConfig.AllowedResources. RefreshGrant
	// checks a refresh request's resources against it when the grant was
	// authorized without any.
	AllowedResources []string
}

// NewJWTIssuer creates a TokenIssuer that signs JWTs.
func NewJWTIssuer(cfg JWTIssuerConfig) TokenIssuer {
	expiry := cfg.AccessExpiry
	if expiry == 0 {
		expiry = core.TokenExpiryAccessToken
	}
	return &jwtIssuer{
		keySource:           cfg.SigningKeySource,
		signingKey:          cfg.SigningKey,
		signingAlg:          cfg.SigningAlg,
		issuer:              cfg.Issuer,
		audience:            cfg.Audience,
		audienceFunc:        cfg.AudienceFunc,
		accessExpiry:        expiry,
		clientKeyLookup:     cfg.ClientKeyLookup,
		refreshStore:        cfg.RefreshStore,
		validateCredentials: cfg.ValidateCredentials,
		getSubjectScopes:    cfg.GetSubjectScopes,
		customClaims:        cfg.CustomClaims,
		hooks:               cfg.Hooks,
		disableRotation:     cfg.DisableRefreshTokenRotation,
		blacklist:           cfg.Blacklist,
		idTokens:            cfg.IDTokens,
		allowedResources:    cfg.AllowedResources,
	}
}

// CreateAccessToken mints a signed JWT. Convention shape per 175.
func (i *jwtIssuer) CreateAccessToken(ctx context.Context, req *CreateAccessTokenRequest) (*CreateAccessTokenResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("CreateAccessTokenRequest is required")
	}
	signingKey := i.key()
	// An empty HMAC key would mint tokens anyone can forge (RFC 7518 §3.2).
	if b, ok := signingKey.([]byte); ok && len(b) == 0 {
		return nil, fmt.Errorf("no signing key configured")
	}
	subject := req.Subject
	scopes := req.Scopes
	details := req.AuthorizationDetails
	now := time.Now()
	expiresAt := now.Add(i.accessExpiry)

	jti, err := core.GenerateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate jti: %w", err)
	}

	claims := jwt.MapClaims{
		"sub":    subject,
		"type":   "access",
		"scopes": scopes,
		"jti":    jti,
		"iat":    now.Unix(),
		"exp":    expiresAt.Unix(),
	}
	if len(details) > 0 {
		claims["authorization_details"] = details
	}
	if req.ClientID != "" {
		claims["client_id"] = req.ClientID
	}
	if len(req.UserinfoClaims) > 0 {
		claims[UserinfoClaimsClaim] = req.UserinfoClaims
	}
	if !req.Confirmation.IsEmpty() {
		claims["cnf"] = req.Confirmation
	}
	if i.issuer != "" {
		claims["iss"] = i.issuer
	}
	switch {
	case len(req.Audience) == 1:
		claims["aud"] = req.Audience[0]
	case len(req.Audience) > 1:
		claims["aud"] = req.Audience
	default:
		if aud := i.resolveAudience(); aud != "" {
			claims["aud"] = aud
		}
	}

	if i.customClaims != nil {
		custom, err := i.customClaims(subject, scopes)
		if err != nil {
			return nil, fmt.Errorf("custom claims func failed: %w", err)
		}
		for k, v := range custom {
			_, asSetClientID := claims["client_id"]
			if standardClaims[k] || issuanceReservedClaims[k] || (k == "client_id" && asSetClientID) {
				log.Printf("Warning: CustomClaimsFunc attempted to override standard claim %q (ignored)", k)
				continue
			}
			claims[k] = v
		}
	}

	signingMethod, err := utils.SigningMethodForAlg(i.signingAlg)
	if err != nil {
		// Fall back to HS256 for []byte keys
		if _, ok := signingKey.([]byte); ok {
			signingMethod = jwt.SigningMethodHS256
		} else {
			return nil, fmt.Errorf("invalid signing algorithm: %w", err)
		}
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	if kid, kidErr := utils.ComputeKid(signingKey, signingMethod.Alg()); kidErr == nil {
		token.Header["kid"] = kid
	}

	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	i.hooks.fireOnIssued(subject, "direct")
	return &CreateAccessTokenResponse{
		Token:     tokenString,
		ExpiresIn: int64(i.accessExpiry.Seconds()),
		TokenType: tokenTypeFor(req.Confirmation),
		TokenID:   jti,
		ExpiresAt: expiresAt,
	}, nil
}

// ClientCredentials performs the client_credentials grant.
func (i *jwtIssuer) ClientCredentials(ctx context.Context, req *ClientCredentialsRequest) (*ClientCredentialsResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("ClientCredentialsRequest is required")
	}
	if i.clientKeyLookup == nil {
		return nil, fmt.Errorf("client_credentials not configured")
	}

	// Authenticate client
	resp, err := i.clientKeyLookup.GetKey(ctx, &keys.GetKeyRequest{ClientID: req.ClientID})
	if err != nil || resp == nil || resp.Record == nil {
		return nil, fmt.Errorf("invalid_client: unknown client")
	}
	rec := resp.Record
	storedKey, ok := rec.Key.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid_client: client does not support secret authentication")
	}
	if !constantTimeEqual(string(storedKey), req.ClientSecret) {
		return nil, fmt.Errorf("invalid_client: invalid credentials")
	}

	// Validate authorization_details
	if err := core.ValidateAll(req.AuthorizationDetails); err != nil {
		return nil, err
	}

	// Create token
	tok, err := i.CreateAccessToken(ctx, &CreateAccessTokenRequest{
		Subject:              req.ClientID,
		Scopes:               req.Scopes,
		AuthorizationDetails: req.AuthorizationDetails,
	})
	if err != nil {
		return nil, err
	}

	i.hooks.fireOnIssued(req.ClientID, "client_credentials")

	return &ClientCredentialsResponse{Tokens: &core.TokenPair{
		AccessToken:          tok.Token,
		TokenType:            tok.TokenType,
		ExpiresIn:            tok.ExpiresIn,
		Scope:                strings.Join(req.Scopes, " "),
		AuthorizationDetails: req.AuthorizationDetails,
	}}, nil
}

// RefreshGrant rotates a refresh token and returns new access + refresh tokens.
// Handles theft detection: if the old token was already revoked, revokes the
// entire token family (all sessions from that initial login).
func (i *jwtIssuer) RefreshGrant(ctx context.Context, req *RefreshGrantRequest) (*RefreshGrantResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("RefreshGrantRequest is required")
	}
	if i.refreshStore == nil {
		return nil, fmt.Errorf("refresh_token grant not configured")
	}

	// Get and validate the refresh token
	getResp, err := i.refreshStore.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: req.RefreshToken})
	if err != nil {
		if err == core.ErrTokenNotFound {
			return nil, fmt.Errorf("invalid_grant: invalid refresh token")
		}
		return nil, fmt.Errorf("server_error: %w", err)
	}
	rt := getResp.Token

	// Check if revoked — token reuse detection (theft)
	if rt.Revoked {
		revokeRefreshFamily(ctx, i.refreshStore, i.blacklist, rt.Family)
		return nil, fmt.Errorf("invalid_grant: token reuse detected, all sessions revoked")
	}
	if rt.IsExpired() {
		return nil, fmt.Errorf("invalid_grant: token has expired")
	}

	// RFC 6749 §6: the token must have been issued to the client
	// presenting it. A token stored with no client has nothing to match.
	// Checked after the revocation check so a replayed token still trips
	// family revocation, and before rotation so a refused attempt does
	// not burn the owner's token.
	if rt.ClientID != "" && rt.ClientID != req.ClientID {
		return nil, fmt.Errorf("invalid_grant: refresh token was not issued to this client")
	}

	// A bound refresh token is only redeemable by the key it was issued
	// to (RFC 9449 §5), which is what leaves a stolen one useless. The
	// check runs before rotation so a failed attempt does not burn the
	// legitimate client's token.
	if !rt.Confirmation.IsEmpty() && !rt.Confirmation.Equal(req.Confirmation) {
		return nil, fmt.Errorf("invalid_grant: refresh token is bound to a different DPoP key")
	}
	// An unbound refresh token may still bind the access token it mints
	// to a presented key; the refresh token's own binding is fixed at
	// issuance and rotation carries it forward unchanged.
	confirmation := rt.Confirmation
	if confirmation.IsEmpty() {
		confirmation = req.Confirmation
	}

	// RFC 8707 §2.2: a refresh may narrow the grant's resources but not
	// widen them. A grant without resources may name any allowed one. Both
	// are checked before rotation, so a refused request doesn't burn the
	// token.
	var audience []string
	var gErr *GrantError
	if len(rt.Resources) > 0 {
		audience, gErr = narrowResources(req.Resources, rt.Resources)
	} else {
		audience, gErr = checkResources(i.allowedResources, req.Resources)
	}
	if gErr != nil {
		return nil, gErr
	}

	// Rotate: invalidate old, create new in same family. With rotation
	// off (FAPI 2.0 §5.3.2.1) the presented token stays live and the
	// response carries no refresh_token, so the client keeps using it.
	var newRefreshToken string
	recordOn := req.RefreshToken
	if !i.disableRotation {
		rotResp, err := i.refreshStore.RotateRefreshToken(ctx, &core.RotateRefreshTokenRequest{OldToken: req.RefreshToken})
		if err != nil {
			if err == core.ErrTokenReused {
				revokeRefreshFamily(ctx, i.refreshStore, i.blacklist, rt.Family)
				return nil, fmt.Errorf("invalid_grant: token reuse detected, all sessions revoked")
			}
			return nil, fmt.Errorf("server_error: %w", err)
		}
		newRefreshToken = rotResp.Token.Token
		recordOn = newRefreshToken
	}

	// The new access token carries forward what the first one had:
	// scopes, authorization_details, the client (which picks a pairwise
	// sub at userinfo) and the userinfo part of the claims request.
	var userinfoClaims []string
	if rt.OIDC != nil {
		userinfoClaims = rt.OIDC.UserinfoClaims
	}
	tok, err := i.CreateAccessToken(ctx, &CreateAccessTokenRequest{
		Subject:              rt.Subject,
		ClientID:             rt.ClientID,
		Scopes:               rt.Scopes,
		AuthorizationDetails: rt.AuthorizationDetails,
		Confirmation:         confirmation,
		UserinfoClaims:       userinfoClaims,
		Audience:             audience,
	})
	if err != nil {
		return nil, fmt.Errorf("server_error: %w", err)
	}
	// Recorded on the refresh token now in the client's hands, so
	// revoking it (or its family) blacklists this access token too.
	if err := recordAccessToken(ctx, i.refreshStore, i.blacklist, recordOn, tok.TokenID, tok.ExpiresAt); err != nil {
		if errors.Is(err, errRefreshRevoked) {
			return nil, fmt.Errorf("invalid_grant: refresh token was revoked")
		}
		return nil, fmt.Errorf("server_error: %w", err)
	}

	// OIDC Core §12.2: the ID token repeats the original login's
	// auth_time, acr and amr, and carries no nonce, since the refresh
	// request has none.
	var idToken string
	if i.idTokens != nil && rt.OIDC != nil && rt.ClientID != "" {
		idResp, err := i.idTokens.CreateIDToken(ctx, &CreateIDTokenRequest{
			Subject:         rt.Subject,
			ClientID:        rt.ClientID,
			Scopes:          rt.Scopes,
			AuthTime:        rt.OIDC.AuthTime,
			ACR:             rt.OIDC.ACR,
			AMR:             rt.OIDC.AMR,
			RequestedClaims: rt.OIDC.IDTokenClaims,
			AccessToken:     tok.Token,
		})
		if err != nil {
			return nil, fmt.Errorf("server_error: create ID token: %w", err)
		}
		idToken = idResp.Token
	}

	i.hooks.fireOnIssued(rt.Subject, "refresh_token")

	return &RefreshGrantResponse{Tokens: &core.TokenPair{
		AccessToken:          tok.Token,
		TokenType:            tok.TokenType,
		ExpiresIn:            tok.ExpiresIn,
		RefreshToken:         newRefreshToken,
		Scope:                strings.Join(rt.Scopes, " "),
		AuthorizationDetails: rt.AuthorizationDetails,
		IDToken:              idToken,
	}}, nil
}

// Password-grant (ROPC) implementation lives in password_granter.go.
// Extracted from this file per OAuth 2.1 §7.6 retirement: ROPC is now
// a peer interface (PasswordGranter) the deployment opts into rather
// than a TokenIssuer method that's always available. See #294.

// key is the issuer's current signing key: its source's when it has one.
func (i *jwtIssuer) key() any {
	if i.keySource != nil {
		k, _ := i.keySource.CurrentSigningKey()
		return k
	}
	return i.signingKey
}
