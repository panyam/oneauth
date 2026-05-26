package federatedauth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// newSecureUserId generates a cryptographically secure user ID for first-time
// federated login (when no existing user matched on email).
func newSecureUserId() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate user id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
