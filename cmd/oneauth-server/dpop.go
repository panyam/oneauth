package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/panyam/oneauth/apiauth"
)

// DPoPServerConfig is the `dpop:` block: RFC 9449 sender-constrained tokens
// at the token endpoint (and PAR, when code_flow is on) and at this server's
// own API routes. Off by default, which leaves every client on bearer tokens.
//
//	dpop:
//	  enabled: true
//	  profile: fapi            # or algs: [ES256, EdDSA]; empty = library default
//	  require: true            # refuse token requests with no proof (FAPI 2.0)
//	  require_at_resource: true
//	  nonce:
//	    required: true
//	    secret: ${DPOP_NONCE_SECRET}
//
// Proofs are checked against server.public_url (the token endpoint at
// public_url + /api/token), so behind a TLS-terminating proxy set public_url
// or every proof fails the htu check.
type DPoPServerConfig struct {
	// Enabled turns DPoP on. Every other field needs it.
	Enabled bool `yaml:"enabled"`

	// Profile picks a named algorithm list. "fapi" is apiauth.FAPIDPoPAlgs
	// (ES256, EdDSA, PS256). Empty uses Algs, or the library default.
	Profile string `yaml:"profile"`

	// Algs lists the proof algorithms to accept. Asymmetric only. Can't be
	// combined with Profile.
	Algs []string `yaml:"algs"`

	// Require refuses token requests that carry no proof, with 400
	// invalid_dpop_proof (OneAuthConfig.RequireDPoP). Clients registered
	// with dpop_bound_access_tokens are held to it either way.
	Require bool `yaml:"require"`

	// RequireAtResource refuses bearer tokens at this server's API routes
	// (APIMiddleware.RequireDPoP).
	RequireAtResource bool `yaml:"require_at_resource"`

	// MaxAge bounds a proof's iat in both directions. Zero keeps the
	// library default.
	MaxAge time.Duration `yaml:"max_age"`

	// Nonce configures RFC 9449 §8 / §9 server nonces.
	Nonce DPoPNonceConfig `yaml:"nonce"`
}

// DPoPNonceConfig configures server-issued DPoP nonces.
type DPoPNonceConfig struct {
	// Required demands a server nonce in every proof. A client without one
	// gets a use_dpop_nonce challenge and retries.
	Required bool `yaml:"required"`

	// Secret keys the nonce MAC. Every instance behind one URL needs the
	// same secret, or a nonce issued by one is refused by the next. Empty
	// generates one per process, which suits a single instance only.
	Secret string `yaml:"secret"`

	// Lifetime is how long a nonce stays acceptable. Zero keeps the
	// library default.
	Lifetime time.Duration `yaml:"lifetime"`
}

// dpopWiring is what the server mounts: one validator pinned to the token
// endpoint URL, and one for its resource routes. Both nil when DPoP is off.
type dpopWiring struct {
	tokenEndpoint *apiauth.DPoPProofValidator
	resource      *apiauth.DPoPProofValidator
}

// buildDPoP turns the config into validators. It refuses a config that
// can't do what it says, such as require without enabled, so a typo fails
// at startup instead of serving bearer tokens.
func buildDPoP(cfg DPoPServerConfig, baseURL string) (*dpopWiring, error) {
	if !cfg.Enabled {
		if cfg.Require || cfg.RequireAtResource || cfg.Nonce.Required {
			return nil, fmt.Errorf("dpop: require, require_at_resource and nonce need dpop.enabled")
		}
		return &dpopWiring{}, nil
	}

	algs, err := dpopAlgs(cfg)
	if err != nil {
		return nil, err
	}

	var nonces apiauth.NonceSource
	var policy func(*http.Request) bool
	if cfg.Nonce.Required {
		var secret []byte
		if cfg.Nonce.Secret != "" {
			secret = []byte(cfg.Nonce.Secret)
		} else {
			log.Printf("dpop: nonce.secret is empty, so nonces are keyed per process; set it when more than one instance serves this URL")
		}
		nonces = apiauth.NewNonceSource(apiauth.NonceConfig{Secret: secret, Lifetime: cfg.Nonce.Lifetime})
		policy = func(*http.Request) bool { return true }
	}

	base := strings.TrimRight(baseURL, "/")
	build := func(c apiauth.DPoPConfig) *apiauth.DPoPProofValidator {
		c.AllowedAlgs = algs
		c.MaxAge = cfg.MaxAge
		c.NonceSource = nonces
		c.NoncePolicy = policy
		return apiauth.NewDPoPProofValidator(c)
	}
	return &dpopWiring{
		tokenEndpoint: build(apiauth.DPoPConfig{EndpointURL: base + "/api/token"}),
		resource:      build(apiauth.DPoPConfig{BaseURL: base}),
	}, nil
}

// dpopAlgs resolves profile / algs to the validator's allowed list. Nil
// keeps the library default.
func dpopAlgs(cfg DPoPServerConfig) ([]string, error) {
	switch {
	case cfg.Profile != "" && len(cfg.Algs) > 0:
		return nil, fmt.Errorf("dpop: set profile or algs, not both")
	case cfg.Profile == "fapi":
		return apiauth.FAPIDPoPAlgs(), nil
	case cfg.Profile != "":
		return nil, fmt.Errorf("dpop: unknown profile %q (known: fapi)", cfg.Profile)
	}
	for _, alg := range cfg.Algs {
		if strings.HasPrefix(alg, "HS") || alg == "none" {
			return nil, fmt.Errorf("dpop: %s can't sign a proof of possession; use an asymmetric algorithm", alg)
		}
	}
	if len(cfg.Algs) == 0 {
		return nil, nil
	}
	return cfg.Algs, nil
}
