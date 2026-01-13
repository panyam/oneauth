package client

import (
	"net/http"
)

// AuthTransport wraps an http.RoundTripper to add Authorization headers
type AuthTransport struct {
	Base  http.RoundTripper
	Token string
}

// RoundTrip implements http.RoundTripper
func (t *AuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Token != "" {
		// Clone the request to avoid mutating the original
		req2 := req.Clone(req.Context())
		req2.Header.Set("Authorization", "Bearer "+t.Token)
		req = req2
	}

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	return base.RoundTrip(req)
}

// NewAuthTransport creates an AuthTransport with the given token
func NewAuthTransport(token string) *AuthTransport {
	return &AuthTransport{
		Base:  http.DefaultTransport,
		Token: token,
	}
}

// NewAuthTransportWithBase creates an AuthTransport with a custom base transport
func NewAuthTransportWithBase(base http.RoundTripper, token string) *AuthTransport {
	return &AuthTransport{
		Base:  base,
		Token: token,
	}
}
