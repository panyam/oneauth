package outbound

import (
	"golang.org/x/oauth2"
)

// Static is a TokenSource for a fixed bearer secret, such as a GitHub
// personal access token. The secret comes from Ref on every Token call, so
// rotating the file or variable needs no restart. The token has no expiry,
// and Static never caches it.
type Static struct {
	Ref SecretRef

	// TokenType is the Authorization scheme. Empty means "Bearer", which
	// GitHub, S3-compatible gateways and most APIs accept.
	TokenType string
}

// NewStatic parses ref and checks it resolves now, so a missing secret
// fails at startup rather than on the first API call.
func NewStatic(ref string) (*Static, error) {
	r, err := ParseSecretRef(ref)
	if err != nil {
		return nil, err
	}
	if _, err := r.Resolve(); err != nil {
		return nil, err
	}
	return &Static{Ref: r}, nil
}

// Token resolves Ref. A secret that has gone missing is ErrSecretMissing.
func (s *Static) Token() (*oauth2.Token, error) {
	v, err := s.Ref.Resolve()
	if err != nil {
		return nil, err
	}
	tt := s.TokenType
	if tt == "" {
		tt = "Bearer"
	}
	return &oauth2.Token{AccessToken: v, TokenType: tt}, nil
}

var _ oauth2.TokenSource = (*Static)(nil)
