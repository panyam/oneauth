package main

import (
	"context"
	"crypto"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

// TrustedAssertionIssuerConfig is one upstream IdP whose JWTs the token
// endpoint accepts as RFC 7523 §2.1 jwt-bearer assertions and as RFC 8693
// token-exchange subject tokens (issue 521). The MCP enterprise-managed
// authorization flow uses both.
type TrustedAssertionIssuerConfig struct {
	// Issuer is the `iss` the IdP's JWTs carry, matched exactly.
	Issuer string `yaml:"issuer"`

	// PublicKeyPath is a PEM public key that verifies the IdP's JWTs.
	// Set this or JWKSURI, not both.
	PublicKeyPath string `yaml:"public_key_path"`

	// JWKSURI is the IdP's JWKS, cached and looked up by each JWT's kid,
	// so the IdP can rotate keys. Set this or PublicKeyPath, not both.
	JWKSURI string `yaml:"jwks_uri"`

	// Audiences are the `aud` values an assertion may carry. Empty
	// accepts this server's issuer and token endpoint, which is what RFC
	// 7523 §3 asks an assertion to name.
	Audiences []string `yaml:"audiences"`

	// AcceptedAlgorithms limits the JWS algorithms the IdP may sign with.
	// Only asymmetric ones are allowed. Empty accepts RS256, PS256, ES256
	// and EdDSA.
	AcceptedAlgorithms []string `yaml:"accepted_algorithms"`
}

// defaultAssertionAlgs are the algorithms an issuer with no
// accepted_algorithms may sign with.
var defaultAssertionAlgs = []string{"RS256", "PS256", "ES256", "EdDSA"}

// asymmetricAssertionAlgs are the algorithms accepted_algorithms may list.
// A symmetric one would need a secret shared with the IdP, which a public
// key setting can't hold.
var asymmetricAssertionAlgs = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"EdDSA": true,
}

// trustedAssertionIssuers builds the apiauth issuers from config. An entry
// with no issuer, no key, both kinds of key, an unreadable key or a
// symmetric algorithm is an error, so the server doesn't start trusting
// less than the config says. The returned func stops the JWKS caches.
func trustedAssertionIssuers(cfg *Config) ([]apiauth.TrustedAssertionIssuer, func(), error) {
	var out []apiauth.TrustedAssertionIssuer
	var stops []func()
	stopAll := func() {
		for _, s := range stops {
			s()
		}
	}
	defaultAuds := []string{cfg.JWT.Issuer, cfg.JWT.Issuer + "/api/token"}
	if base := publicBaseURL(cfg); base != cfg.JWT.Issuer {
		defaultAuds = append(defaultAuds, base+"/api/token")
	}
	for i, e := range cfg.TrustedAssertionIssuers {
		where := fmt.Sprintf("trusted_assertion_issuers[%d]", i)
		if e.Issuer == "" {
			stopAll()
			return nil, nil, fmt.Errorf("%s: issuer is required", where)
		}
		if (e.PublicKeyPath == "") == (e.JWKSURI == "") {
			stopAll()
			return nil, nil, fmt.Errorf("%s (%s): set exactly one of public_key_path and jwks_uri", where, e.Issuer)
		}
		algs := e.AcceptedAlgorithms
		if len(algs) == 0 {
			algs = defaultAssertionAlgs
		}
		for _, a := range algs {
			if !asymmetricAssertionAlgs[a] {
				stopAll()
				return nil, nil, fmt.Errorf("%s (%s): accepted_algorithms may only list asymmetric algorithms, not %q", where, e.Issuer, a)
			}
		}
		ti := apiauth.TrustedAssertionIssuer{Issuer: e.Issuer, Audiences: e.Audiences, AcceptedAlgorithms: algs}
		if len(ti.Audiences) == 0 {
			ti.Audiences = defaultAuds
		}
		if e.PublicKeyPath != "" {
			raw, err := os.ReadFile(e.PublicKeyPath)
			if err != nil {
				stopAll()
				return nil, nil, fmt.Errorf("%s (%s): %w", where, e.Issuer, err)
			}
			if ti.PublicKey, err = utils.ParsePublicKeyPEM(raw); err != nil {
				stopAll()
				return nil, nil, fmt.Errorf("%s (%s): %w", where, e.Issuer, err)
			}
		} else {
			ks := keys.NewJWKSKeyStore(e.JWKSURI)
			if err := ks.Start(); err != nil {
				stopAll()
				return nil, nil, fmt.Errorf("%s (%s): JWKS: %w", where, e.Issuer, err)
			}
			stops = append(stops, ks.Stop)
			ti.KeyFunc = jwksKeyFunc(ks)
		}
		out = append(out, ti)
	}
	return out, stopAll, nil
}

// jwksKeyFunc resolves an assertion's verification key from ks by its kid.
func jwksKeyFunc(ks *keys.JWKSKeyStore) func(*jwt.Token) (crypto.PublicKey, error) {
	return func(t *jwt.Token) (crypto.PublicKey, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("assertion has no kid")
		}
		rec, err := ks.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: kid})
		if err != nil {
			return nil, err
		}
		key, err := utils.DecodeVerifyKey(rec.Record.Key, t.Method.Alg())
		if err != nil {
			return nil, err
		}
		return key, nil
	}
}
