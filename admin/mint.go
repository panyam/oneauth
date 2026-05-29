package admin

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/utils"
)

// mintStandardClaims are the JWT claim keys MintResourceToken owns. Custom
// claims passed in via the customClaims map cannot overwrite these — collisions
// are logged and ignored.
var mintStandardClaims = map[string]bool{
	"sub": true, "iss": true, "aud": true, "exp": true,
	"iat": true, "type": true, "scopes": true, "jti": true,
	"client_id":             true,
	"authorization_details": true, // RFC 9396
}

// MintResourceToken creates a resource-scoped JWT for a user on behalf of a
// registered App, signed with the app's own signing key (federated token
// pattern — the resource server verifies with the same key, no AS callback
// needed). The signing algorithm is auto-detected from the key's Go type:
//
//   - []byte → HS256
//   - *rsa.PrivateKey → RS256
//   - *ecdsa.PrivateKey → ES256
//
// customClaims is merged into the JWT alongside the standard claims (sub,
// client_id, type, scopes, iat, exp). Keys colliding with standard claims
// are logged and dropped — standard claims are owned by the minter.
func MintResourceToken(userID, appClientID string, signingKey any, customClaims map[string]any, scopes []string, authzDetails []core.AuthorizationDetail) (string, error) {
	method, err := signingMethodFromKey(signingKey)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub":       userID,
		"client_id": appClientID,
		"type":      "access",
		"scopes":    scopes,
		"iat":       now.Unix(),
		"exp":       now.Add(15 * time.Minute).Unix(),
	}

	if len(authzDetails) > 0 {
		claims["authorization_details"] = authzDetails
	}

	for k, v := range customClaims {
		if mintStandardClaims[k] {
			log.Printf("MintResourceToken: customClaims attempted to override standard claim %q (ignored)", k)
			continue
		}
		claims[k] = v
	}

	token := jwt.NewWithClaims(method, claims)
	if kid, err := utils.ComputeKid(signingKey, method.Alg()); err == nil {
		token.Header["kid"] = kid
	}
	return token.SignedString(signingKey)
}

// signingMethodFromKey returns the appropriate jwt.SigningMethod for the given key type.
func signingMethodFromKey(key any) (jwt.SigningMethod, error) {
	switch key.(type) {
	case []byte:
		return jwt.SigningMethodHS256, nil
	case *rsa.PrivateKey:
		return jwt.SigningMethodRS256, nil
	case *ecdsa.PrivateKey:
		return jwt.SigningMethodES256, nil
	default:
		return nil, fmt.Errorf("unsupported signing key type: %T", key)
	}
}
