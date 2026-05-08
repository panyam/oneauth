package apiauth

import (
	"context"
	"fmt"

	"github.com/panyam/oneauth/keys"
)

var errInvalidClient = &clientError{"invalid_client"}

type clientError struct{ msg string }

func (e *clientError) Error() string { return e.msg }

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
func (a *clientAuthenticator) AuthenticateClient(ctx context.Context, req *AuthenticateClientRequest) (*AuthenticateClientResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("AuthenticateClientRequest is required")
	}
	if a.keyLookup == nil {
		return nil, errInvalidClient
	}
	rec, err := a.keyLookup.GetKey(req.ClientID)
	if err != nil || rec == nil {
		return nil, errInvalidClient
	}
	storedKey, ok := rec.Key.([]byte)
	if !ok {
		return nil, errInvalidClient
	}
	if !constantTimeEqual(string(storedKey), req.ClientSecret) {
		return nil, errInvalidClient
	}
	return &AuthenticateClientResponse{}, nil
}
