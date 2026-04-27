package apiauth

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// jwtValidator implements TokenValidator using local JWT validation.
// Dependencies are explicit and minimal: KeyLookup (read-only), Blacklist,
// issuer/audience config, and security hooks.
type jwtValidator struct {
	keyLookup keys.KeyLookup
	blacklist core.TokenBlacklist
	issuer    string
	audience  string
	hooks     SecurityHooks
}

// JWTValidatorConfig configures a jwtValidator.
type JWTValidatorConfig struct {
	KeyLookup keys.KeyLookup
	Blacklist core.TokenBlacklist
	Issuer    string
	Audience  string
	Hooks     SecurityHooks
}

// NewJWTValidator creates a TokenValidator that validates JWTs locally.
func NewJWTValidator(cfg JWTValidatorConfig) TokenValidator {
	return &jwtValidator{
		keyLookup: cfg.KeyLookup,
		blacklist: cfg.Blacklist,
		issuer:    cfg.Issuer,
		audience:  cfg.Audience,
		hooks:     cfg.Hooks,
	}
}

// ValidateToken parses and validates a JWT, returning the extracted claims.
func (v *jwtValidator) ValidateToken(tokenString string) (*TokenInfo, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return v.resolveKey(token)
	})
	if err != nil {
		v.hooks.fireOnTokenRejected(fmt.Sprintf("parse error: %v", err))
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if !token.Valid {
		v.hooks.fireOnTokenRejected("token validation failed")
		return nil, fmt.Errorf("token validation failed")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	// Verify token type
	if tokenType, ok := claims["type"].(string); ok && tokenType != "access" {
		v.hooks.fireOnTokenRejected("invalid token type")
		return nil, fmt.Errorf("invalid token type")
	}

	// Verify issuer
	if v.issuer != "" {
		if iss, ok := claims["iss"].(string); !ok || iss != v.issuer {
			v.hooks.fireOnTokenRejected("invalid issuer")
			return nil, fmt.Errorf("invalid issuer")
		}
	}

	// Verify audience
	if v.audience != "" {
		if !matchesAudience(claims, v.audience) {
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

	return &TokenInfo{
		UserID:               userID,
		Scopes:               scopes,
		AuthorizationDetails: authzDetails,
		CustomClaims:         customClaims,
		AuthType:             "jwt",
	}, nil
}

// CheckScopes validates a token and verifies it contains all required scopes.
func (v *jwtValidator) CheckScopes(token string, required []string) error {
	info, err := v.ValidateToken(token)
	if err != nil {
		return err
	}
	if !core.ContainsAllScopes(info.Scopes, required) {
		return fmt.Errorf("insufficient scope: requires %v, has %v", required, info.Scopes)
	}
	return nil
}

// CheckAuthorizationDetails validates a token and verifies it contains
// authorization_details entries for all required types.
func (v *jwtValidator) CheckAuthorizationDetails(token string, requiredTypes []string) error {
	info, err := v.ValidateToken(token)
	if err != nil {
		return err
	}
	grantedTypes := make(map[string]bool)
	for _, ad := range info.AuthorizationDetails {
		grantedTypes[ad.Type] = true
	}
	for _, reqType := range requiredTypes {
		if !grantedTypes[reqType] {
			return fmt.Errorf("missing required authorization_details type: %s", reqType)
		}
	}
	return nil
}

// resolveKey finds the appropriate signing key for a JWT token.
func (v *jwtValidator) resolveKey(token *jwt.Token) (any, error) {
	if v.keyLookup == nil {
		return nil, fmt.Errorf("no key store configured")
	}

	// Try kid-based lookup first
	if kid, ok := token.Header["kid"].(string); ok && kid != "" {
		rec, err := v.keyLookup.GetKeyByKid(kid)
		if err == nil && rec != nil {
			if token.Header["alg"] != rec.Algorithm {
				v.hooks.fireOnAlgorithmMismatch(rec.Algorithm, fmt.Sprintf("%v", token.Header["alg"]))
				return nil, fmt.Errorf("algorithm mismatch: expected %s, got %v", rec.Algorithm, token.Header["alg"])
			}
			// Cross-check kid owner vs client_id claim
			if rec.ClientID != "" {
				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					if claimClientID, _ := claims["client_id"].(string); claimClientID != "" && claimClientID != rec.ClientID {
						return nil, fmt.Errorf("kid owner %q does not match client_id claim %q", rec.ClientID, claimClientID)
					}
				}
			}
			return utils.DecodeVerifyKey(rec.Key, rec.Algorithm)
		}
	}

	// Fall back to client_id claim
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if clientID, ok := claims["client_id"].(string); ok && clientID != "" {
			rec, err := v.keyLookup.GetKey(clientID)
			if err == nil && rec != nil {
				if token.Header["alg"] != rec.Algorithm {
					v.hooks.fireOnAlgorithmMismatch(rec.Algorithm, fmt.Sprintf("%v", token.Header["alg"]))
					return nil, fmt.Errorf("algorithm mismatch: expected %s, got %v", rec.Algorithm, token.Header["alg"])
				}
				return utils.DecodeVerifyKey(rec.Key, rec.Algorithm)
			}
		}
	}

	return nil, fmt.Errorf("no key found for token")
}

// jwtIssuer implements TokenIssuer using JWT signing.
type jwtIssuer struct {
	signingKey      any    // []byte for HS256, *rsa.PrivateKey for RS256, *ecdsa.PrivateKey for ES256
	signingAlg      string // "HS256", "RS256", "ES256"
	issuer          string
	audience        string
	accessExpiry    time.Duration
	clientKeyLookup keys.KeyLookup
	refreshStore    core.RefreshTokenStore
	hooks           TokenHooks
}

// JWTIssuerConfig configures a jwtIssuer.
type JWTIssuerConfig struct {
	SigningKey      any
	SigningAlg      string
	Issuer         string
	Audience       string
	AccessExpiry   time.Duration
	ClientKeyLookup keys.KeyLookup         // for client_credentials authentication
	RefreshStore   core.RefreshTokenStore  // for refresh_token grant
	Hooks          TokenHooks
}

// NewJWTIssuer creates a TokenIssuer that signs JWTs.
func NewJWTIssuer(cfg JWTIssuerConfig) TokenIssuer {
	expiry := cfg.AccessExpiry
	if expiry == 0 {
		expiry = core.TokenExpiryAccessToken
	}
	return &jwtIssuer{
		signingKey:      cfg.SigningKey,
		signingAlg:      cfg.SigningAlg,
		issuer:          cfg.Issuer,
		audience:        cfg.Audience,
		accessExpiry:    expiry,
		clientKeyLookup: cfg.ClientKeyLookup,
		refreshStore:    cfg.RefreshStore,
		hooks:           cfg.Hooks,
	}
}

// CreateAccessToken mints a signed JWT.
func (i *jwtIssuer) CreateAccessToken(subject string, scopes []string, details []core.AuthorizationDetail) (string, int64, error) {
	now := time.Now()
	expiresAt := now.Add(i.accessExpiry)

	jti, err := core.GenerateSecureToken()
	if err != nil {
		return "", 0, fmt.Errorf("failed to generate jti: %w", err)
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
	if i.issuer != "" {
		claims["iss"] = i.issuer
	}
	if i.audience != "" {
		claims["aud"] = i.audience
	}

	signingMethod, err := utils.SigningMethodForAlg(i.signingAlg)
	if err != nil {
		// Fall back to HS256 for []byte keys
		if _, ok := i.signingKey.([]byte); ok {
			signingMethod = jwt.SigningMethodHS256
		} else {
			return "", 0, fmt.Errorf("invalid signing algorithm: %w", err)
		}
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	if kid, kidErr := utils.ComputeKid(i.signingKey, signingMethod.Alg()); kidErr == nil {
		token.Header["kid"] = kid
	}

	tokenString, err := token.SignedString(i.signingKey)
	if err != nil {
		return "", 0, fmt.Errorf("failed to sign token: %w", err)
	}

	i.hooks.fireOnIssued(subject, "direct")
	return tokenString, int64(i.accessExpiry.Seconds()), nil
}

// ClientCredentials performs the client_credentials grant.
func (i *jwtIssuer) ClientCredentials(clientID, clientSecret string, scopes []string, details []core.AuthorizationDetail) (*core.TokenPair, error) {
	if i.clientKeyLookup == nil {
		return nil, fmt.Errorf("client_credentials not configured")
	}

	// Authenticate client
	rec, err := i.clientKeyLookup.GetKey(clientID)
	if err != nil || rec == nil {
		return nil, fmt.Errorf("invalid_client: unknown client")
	}
	storedKey, ok := rec.Key.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid_client: client does not support secret authentication")
	}
	if !constantTimeEqual(string(storedKey), clientSecret) {
		return nil, fmt.Errorf("invalid_client: invalid credentials")
	}

	// Validate authorization_details
	if err := core.ValidateAll(details); err != nil {
		return nil, err
	}

	// Create token
	tokenStr, expiresIn, err := i.CreateAccessToken(clientID, scopes, details)
	if err != nil {
		return nil, err
	}

	i.hooks.fireOnIssued(clientID, "client_credentials")

	resp := &core.TokenPair{
		AccessToken:          tokenStr,
		TokenType:            "Bearer",
		ExpiresIn:            expiresIn,
		Scope:                strings.Join(scopes, " "),
		AuthorizationDetails: details,
	}
	return resp, nil
}

// RefreshGrant rotates a refresh token and returns new access + refresh tokens.
// Handles theft detection: if the old token was already revoked, revokes the
// entire token family (all sessions from that initial login).
func (i *jwtIssuer) RefreshGrant(refreshToken string) (*core.TokenPair, error) {
	if i.refreshStore == nil {
		return nil, fmt.Errorf("refresh_token grant not configured")
	}

	// Get and validate the refresh token
	rt, err := i.refreshStore.GetRefreshToken(refreshToken)
	if err != nil {
		if err == core.ErrTokenNotFound {
			return nil, fmt.Errorf("invalid_grant: invalid refresh token")
		}
		return nil, fmt.Errorf("server_error: %w", err)
	}

	// Check if revoked — token reuse detection (theft)
	if rt.Revoked {
		i.refreshStore.RevokeTokenFamily(rt.Family)
		return nil, fmt.Errorf("invalid_grant: token reuse detected, all sessions revoked")
	}
	if rt.IsExpired() {
		return nil, fmt.Errorf("invalid_grant: token has expired")
	}

	// Rotate: invalidate old, create new in same family
	newRT, err := i.refreshStore.RotateRefreshToken(refreshToken)
	if err != nil {
		if err == core.ErrTokenReused {
			i.refreshStore.RevokeTokenFamily(rt.Family)
			return nil, fmt.Errorf("invalid_grant: token reuse detected, all sessions revoked")
		}
		return nil, fmt.Errorf("server_error: %w", err)
	}

	// Create new access token (carry forward scopes + authorization_details)
	tokenStr, expiresIn, err := i.CreateAccessToken(rt.UserID, rt.Scopes, rt.AuthorizationDetails)
	if err != nil {
		return nil, fmt.Errorf("server_error: %w", err)
	}

	i.hooks.fireOnIssued(rt.UserID, "refresh_token")

	return &core.TokenPair{
		AccessToken:          tokenStr,
		TokenType:            "Bearer",
		ExpiresIn:            expiresIn,
		RefreshToken:         newRT.Token,
		Scope:                strings.Join(rt.Scopes, " "),
		AuthorizationDetails: rt.AuthorizationDetails,
	}, nil
}
