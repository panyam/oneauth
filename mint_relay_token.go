package oneauth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// HostQuota contains per-host quota limits embedded as custom claims in relay-scoped JWTs.
type HostQuota struct {
	MaxRooms   int     `json:"max_rooms,omitempty"`
	MaxMsgRate float64 `json:"max_msg_rate,omitempty"`
}

// MintRelayToken creates a relay-scoped JWT for a user on behalf of a Host.
// The token includes the host's client_id and quota as custom claims,
// and is signed with the host's shared secret.
//
// This is called by the Host after authenticating a user locally.
func MintRelayToken(userID, hostClientID, hostSecret string, quota HostQuota, scopes []string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":       userID,
		"client_id": hostClientID,
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
	return token.SignedString([]byte(hostSecret))
}
