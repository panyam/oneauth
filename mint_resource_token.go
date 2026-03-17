package oneauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/utils"
)

// AppQuota contains per-app quota limits embedded as custom claims in resource-scoped JWTs.
type AppQuota struct {
	MaxRooms   int     `json:"max_rooms,omitempty"`
	MaxMsgRate float64 `json:"max_msg_rate,omitempty"`
}

// MintResourceToken creates a resource-scoped JWT for a user on behalf of a registered App,
// signed with the app's shared secret (HS256). This is the backwards-compatible API.
func MintResourceToken(userID, appClientID, appSecret string, quota AppQuota, scopes []string) (string, error) {
	return MintResourceTokenWithKey(userID, appClientID, []byte(appSecret), quota, scopes)
}

// MintResourceTokenWithKey creates a resource-scoped JWT signed with the provided key.
// The signing algorithm is auto-detected from the key type:
//   - []byte → HS256
//   - *rsa.PrivateKey → RS256
//   - *ecdsa.PrivateKey → ES256
func MintResourceTokenWithKey(userID, appClientID string, signingKey any, quota AppQuota, scopes []string) (string, error) {
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

	if quota.MaxRooms > 0 {
		claims["max_rooms"] = quota.MaxRooms
	}
	if quota.MaxMsgRate > 0 {
		claims["max_msg_rate"] = quota.MaxMsgRate
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
