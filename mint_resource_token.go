package oneauth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AppQuota contains per-app quota limits embedded as custom claims in resource-scoped JWTs.
type AppQuota struct {
	MaxRooms   int     `json:"max_rooms,omitempty"`
	MaxMsgRate float64 `json:"max_msg_rate,omitempty"`
}

// MintResourceToken creates a resource-scoped JWT for a user on behalf of a registered App.
// The token includes the app's client_id and quota as custom claims,
// and is signed with the app's shared secret.
//
// This is called by the App after authenticating a user locally.
// The resulting token can be presented to any Resource Server that shares
// the same KeyStore to authorize access.
func MintResourceToken(userID, appClientID, appSecret string, quota AppQuota, scopes []string) (string, error) {
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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(appSecret))
}
