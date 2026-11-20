package apiauth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/panyam/oneauth/utils"
)

// Defaults for ClientJWKSFetcher's zero fields.
const (
	defaultClientJWKSTTL         = 5 * time.Minute
	defaultClientJWKSMinRefresh  = 30 * time.Second
	defaultClientJWKSMaxBytes    = 64 << 10
	defaultClientJWKSHTTPTimeout = 5 * time.Second
)

// ClientJWKSFetcher fetches and caches the key sets that private_key_jwt
// clients publish at their registered jwks_uri (RFC 7591 §2, issue 507).
// The zero value is ready to use and safe against SSRF: it dials no
// loopback or private address, follows no redirect, reads at most MaxBytes,
// and fetches only https URLs. Safe for concurrent use.
//
// A cached set is served until TTL passes. A caller that can't find the
// key it needs asks for a refresh, which refetches unless the set was
// fetched less than MinRefreshInterval ago. That lets a client rotate keys
// (OIDC Core §10.1.1) while a stream of unknown kids can't make the AS
// hammer the URL.
type ClientJWKSFetcher struct {
	// AllowPrivateHosts lets the fetcher dial loopback and private
	// addresses. For test harnesses and closed networks only; it pairs with
	// admin.AppRegistrar.AllowPrivateJWKSHosts.
	AllowPrivateHosts bool
	// HTTPClient replaces the guarded client. A custom client brings its
	// own dial policy (tests use it to trust a test server's certificate),
	// but the fetcher still follows no redirect with it.
	HTTPClient *http.Client
	// TTL is how long a fetched set is used. Zero means 5 minutes.
	TTL time.Duration
	// MinRefreshInterval is the least time between two fetches of one URL.
	// Zero means 30 seconds.
	MinRefreshInterval time.Duration
	// MaxBytes caps the response body. Zero means 64 KiB.
	MaxBytes int64
	// RootCAs, when set, are the CAs the guarded client trusts instead of
	// the system roots. The dial guard and the no-redirect rule still
	// apply, unlike with a custom HTTPClient.
	RootCAs *x509.CertPool

	mu     sync.Mutex
	cache  map[string]cachedClientJWKS
	client *http.Client
}

type cachedClientJWKS struct {
	set       *utils.JWKSet
	fetchedAt time.Time
}

// Keys returns the key set at uri. It serves the cached set while it is
// fresh, unless refresh is set and MinRefreshInterval has passed since the
// last fetch. A failed fetch returns the error and leaves any cached set in
// place, so a client keeps authenticating through a brief outage of its
// jwks_uri until TTL runs out.
func (f *ClientJWKSFetcher) Keys(ctx context.Context, uri string, refresh bool) (*utils.JWKSet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cache == nil {
		f.cache = map[string]cachedClientJWKS{}
	}
	now := time.Now()
	if c, ok := f.cache[uri]; ok {
		age := now.Sub(c.fetchedAt)
		if !refresh && age < orDuration(f.TTL, defaultClientJWKSTTL) {
			return c.set, nil
		}
		if refresh && age < orDuration(f.MinRefreshInterval, defaultClientJWKSMinRefresh) {
			return c.set, nil
		}
	}
	set, err := f.fetch(ctx, uri)
	if err != nil {
		if c, ok := f.cache[uri]; ok && now.Sub(c.fetchedAt) < orDuration(f.TTL, defaultClientJWKSTTL) {
			return c.set, nil
		}
		return nil, err
	}
	f.cache[uri] = cachedClientJWKS{set: set, fetchedAt: now}
	return set, nil
}

func (f *ClientJWKSFetcher) fetch(ctx context.Context, uri string) (*utils.JWKSet, error) {
	var set utils.JWKSet
	if err := f.getJSON(ctx, uri, "jwks_uri", &set); err != nil {
		return nil, err
	}
	return &set, nil
}

// SectorRedirectURIs fetches a sector_identifier_uri, which must hold a
// JSON array of redirect URIs (OIDC Registration §5), with the same guards
// as a jwks_uri. Nothing is cached: registration fetches it once. It fits
// admin.AppRegistrar.FetchSectorIdentifier.
func (f *ClientJWKSFetcher) SectorRedirectURIs(ctx context.Context, uri string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var uris []string
	if err := f.getJSON(ctx, uri, "sector_identifier_uri", &uris); err != nil {
		return nil, err
	}
	return uris, nil
}

// getJSON GETs uri, which must be https, through the guarded client and
// decodes at most MaxBytes of a 200 response into v. label names the
// field in errors. The caller holds f.mu.
func (f *ClientJWKSFetcher) getJSON(ctx context.Context, uri, label string, v any) error {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%s %q is not an https URL", label, uri)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json, application/jwk-set+json")
	resp, err := f.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", label, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: status %d", label, resp.StatusCode)
	}
	limit := f.MaxBytes
	if limit <= 0 {
		limit = defaultClientJWKSMaxBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("read %s: %w", label, err)
	}
	if int64(len(body)) > limit {
		return fmt.Errorf("%s response is over %d bytes", label, limit)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("parse %s: %w", label, err)
	}
	return nil
}

func (f *ClientJWKSFetcher) httpClient() *http.Client {
	if f.HTTPClient != nil {
		// A redirect is never followed, whichever client fetches.
		c := *f.HTTPClient
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return &c
	}
	if f.client == nil {
		f.client = guardedHTTPClient(f.AllowPrivateHosts, f.RootCAs, defaultClientJWKSHTTPTimeout, "jwks_uri")
	}
	return f.client
}

func orDuration(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// errNoClientKey is a jwks_uri client's set with no key for the assertion.
var errNoClientKey = errors.New("no key in the client's jwks_uri matches the assertion")

// selectClientJWK picks the key an assertion names: by kid, or the one
// signing key when the assertion has no kid and the set has exactly one.
// Encryption keys (use "enc") never verify an assertion.
func selectClientJWK(set *utils.JWKSet, kid string) (utils.JWK, error) {
	var signing []utils.JWK
	for _, k := range set.Keys {
		if k.Use == "enc" {
			continue
		}
		if kid != "" && k.Kid == kid {
			return k, nil
		}
		signing = append(signing, k)
	}
	if kid == "" && len(signing) == 1 {
		return signing[0], nil
	}
	return utils.JWK{}, errNoClientKey
}

// algFitsKey reports whether alg is an asymmetric JWS algorithm the key's
// type can verify: RS* and PS* for RSA, ES* for EC with its curve, EdDSA
// for OKP. The assertion's header can't pick an algorithm outside the key's
// family (CVE-2016-10555).
func algFitsKey(alg string, k utils.JWK) bool {
	if k.Alg != "" && k.Alg != alg {
		return false
	}
	switch k.Kty {
	case "RSA":
		switch alg {
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
			return true
		}
	case "EC":
		return map[string]string{"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}[k.Crv] == alg
	case "OKP":
		return alg == "EdDSA" && k.Crv == "Ed25519"
	}
	return false
}
