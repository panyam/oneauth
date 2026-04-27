package apiauth

import (
	"github.com/panyam/oneauth/keys"
)

// clientAuthenticator implements ClientAuthenticator using a KeyLookup
// with constant-time secret comparison.
type clientAuthenticator struct {
	keyLookup keys.KeyLookup
}

// NewClientAuthenticator creates a ClientAuthenticator backed by a KeyLookup.
func NewClientAuthenticator(kl keys.KeyLookup) ClientAuthenticator {
	return &clientAuthenticator{keyLookup: kl}
}

// AuthenticateClient verifies client_id + client_secret.
func (a *clientAuthenticator) AuthenticateClient(clientID, clientSecret string) error {
	if a.keyLookup == nil {
		return errInvalidClient
	}
	rec, err := a.keyLookup.GetKey(clientID)
	if err != nil || rec == nil {
		return errInvalidClient
	}
	storedKey, ok := rec.Key.([]byte)
	if !ok {
		return errInvalidClient
	}
	if !constantTimeEqual(string(storedKey), clientSecret) {
		return errInvalidClient
	}
	return nil
}
