package apiauth

import (
	"context"
	"fmt"
	"time"
)

// fapiClientAuthenticator holds client authentication to the FAPI 2.0
// Security Profile (§5.3.2.1): private_key_jwt only (oneauth doesn't do
// MTLS), with the assertion's aud a single string. The audiences it
// accepts come from OneAuth, which pins them to the issuer in FAPI mode.
//
// Its presence also marks the server as FAPI for the confidential-client
// gate, which then authenticates every client, public or unregistered
// included, since FAPI 2.0 allows confidential clients only.
type fapiClientAuthenticator struct {
	inner ClientAuthenticator
}

// AuthenticateClient refuses anything but a jwt-bearer client assertion,
// then has the inner authenticator verify it with RequireStringAudience.
func (a *fapiClientAuthenticator) AuthenticateClient(ctx context.Context, req *AuthenticateClientRequest) (*AuthenticateClientResponse, error) {
	if req == nil || req.ClientAssertionType != ClientAssertionTypeJWTBearer || req.ClientAssertion == "" {
		return nil, fmt.Errorf("%w: FAPI 2.0 requires private_key_jwt client authentication", errInvalidClient)
	}
	strict := *req
	strict.RequireStringAudience = true
	return a.inner.AuthenticateClient(ctx, &strict)
}

// isFAPI reports whether the authenticator is the FAPI 2.0 wrapper.
func isFAPI(a ClientAuthenticator) bool {
	_, ok := a.(*fapiClientAuthenticator)
	return ok
}

// FAPI 2.0 §5.3.2.2 lifetimes.
const (
	fapi2MaxCodeLifetime       = 60 * time.Second
	fapi2MaxRequestURILifetime = 599 * time.Second
)

// capLifetime returns configured, shortened to max. Zero stays zero so the
// handler's default applies; both defaults are already within FAPI's
// limits (DefaultAuthorizationCodeExpiry, DefaultPushedRequestExpiry).
func capLifetime(configured, max time.Duration) time.Duration {
	if configured > max {
		return max
	}
	return configured
}
