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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/panyam/oneauth/core"
)

// Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document-03,
// issue 532). A client uses an https URL it controls as its client_id, and the
// AS fetches the client's metadata from that URL instead of needing it
// registered. The MCP authorization spec (2025-11-25) says an AS SHOULD
// support this.
const (
	// cimdMaxBytes is the document size limit. Draft §10.11 says an AS
	// SHOULD read at most 5 kilobytes.
	cimdMaxBytes = 5 << 10
	// cimdDefaultTTL applies when the response carries no max-age.
	cimdDefaultTTL = 5 * time.Minute
	// cimdMinTTL and cimdMaxTTL bound the effective cache lifetime. Draft
	// §6.2 says an AS SHOULD enforce both, and names no numbers.
	cimdMinTTL = time.Minute
	cimdMaxTTL = 24 * time.Hour
	// cimdStaleLimit is how long after a fetch a cached document still
	// answers while its URL fails transiently. Draft §6.1 says a transient
	// failure SHOULD NOT invalidate trust cached earlier.
	cimdStaleLimit  = 24 * time.Hour
	cimdHTTPTimeout = 5 * time.Second
)

var (
	// ErrInvalidClientMetadata is a terminal failure for a client_id that
	// names a metadata document: the URL breaks draft §3, the server
	// answered something other than 200, or the document breaks §4 or §5.
	// The token endpoint answers it with invalid_client, and /authorize
	// shows its error page instead of redirecting (§6.1).
	ErrInvalidClientMetadata = errors.New("invalid client ID metadata document")
	// ErrClientMetadataUnavailable is a transient failure to fetch a
	// client's metadata document, such as a network error or a 5xx, with
	// no usable cached copy. The token endpoint answers it with 503
	// temporarily_unavailable (§6.1).
	ErrClientMetadataUnavailable = errors.New("client ID metadata document temporarily unavailable")
)

// IsClientIDMetadataDocumentURL reports whether clientID is shaped like a
// metadata-document client_id: it starts with "https://". Such a client_id
// is never looked up in the wrapped registry, valid or not. Draft §9.1 asks
// an AS to keep its own client_ids from starting with "https://", and
// oneauth's start with "app_".
func IsClientIDMetadataDocumentURL(clientID string) bool {
	return strings.HasPrefix(clientID, "https://")
}

// ValidateClientIDMetadataDocumentURL checks clientID against draft §3: the
// https scheme, no userinfo, a path other than "/", no "." or ".."
// segments, and no fragment. A query is allowed, since §3 only says SHOULD
// NOT. The client_id is used exactly as given and never normalized (§3).
func ValidateClientIDMetadataDocumentURL(clientID string) error {
	u, err := url.Parse(clientID)
	if err != nil {
		return fmt.Errorf("%w: client_id is not a URL: %v", ErrInvalidClientMetadata, err)
	}
	switch {
	case u.Scheme != "https":
		return fmt.Errorf("%w: client_id must use https", ErrInvalidClientMetadata)
	case u.Host == "":
		return fmt.Errorf("%w: client_id has no host", ErrInvalidClientMetadata)
	case u.User != nil:
		return fmt.Errorf("%w: client_id must not contain userinfo", ErrInvalidClientMetadata)
	case u.Fragment != "" || strings.Contains(clientID, "#"):
		return fmt.Errorf("%w: client_id must not contain a fragment", ErrInvalidClientMetadata)
	case u.EscapedPath() == "" || u.EscapedPath() == "/":
		return fmt.Errorf("%w: client_id must have a path other than /", ErrInvalidClientMetadata)
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("%w: client_id path must not contain . or .. segments", ErrInvalidClientMetadata)
		}
	}
	return nil
}

// CIMDAppStore is a core.AppRegistrationStore that resolves metadata-document
// client_ids (issue 532) and passes every other client_id to the store it
// wraps. GetApp is the only method it changes. So every place oneauth looks a
// client up (the redirect check at /authorize, client authentication at the
// token endpoint, userinfo, pairwise subjects, the consent page) accepts a
// CIMD client with no change at the call site.
//
// GetApp for a client_id that IsClientIDMetadataDocumentURL accepts:
//   - checks the URL with ValidateClientIDMetadataDocumentURL, and refuses
//     the AS's own Issuer (§10.1);
//   - fetches it through a guarded client: https only, no redirect
//     followed, no private address unless AllowPrivateHosts, at most 5 KB,
//     200 only, no cookies;
//   - validates the document (validateClientMetadataDocument);
//   - caches the result for the response's max-age, clamped to between 1
//     minute and 24 hours, 5 minutes when it gives none. Failures are never
//     cached. A transient failure serves the cached copy for up to 24 hours
//     after it was fetched.
//
// The returned AppRegistration exists only in memory. It is never saved, so
// SaveApp, ListApps and DeleteApp see only the wrapped store's clients. It
// carries no LogoURI, since draft §10.9 requires an AS to prefetch a logo
// and serve it from its own host.
//
// Safe for concurrent use.
type CIMDAppStore struct {
	// AppRegistrationStore holds the registered clients. Nil means there
	// are none, and GetApp answers core.ErrAppNotFound for them.
	core.AppRegistrationStore

	// Issuer is the AS's issuer URL. A client_id equal to it is refused.
	Issuer string
	// GrantTypes and ResponseTypes are what the AS supports. A document's
	// grant_types and response_types are cut down to them (§6), and an
	// empty result is invalid. Nil means authorization_code and
	// refresh_token, and code.
	GrantTypes    []string
	ResponseTypes []string

	// UserinfoSigningAlgs and AuthorizationSigningAlgs are the algorithms
	// the AS signs userinfo and JARM responses with. A document asking for
	// another userinfo_signed_response_alg or
	// authorization_signed_response_alg is invalid, as DCR refuses it, so
	// `none` is too. Empty refuses any, which is right when OIDC or JARM
	// is off. NewOneAuth sets both.
	UserinfoSigningAlgs      []string
	AuthorizationSigningAlgs []string

	// AllowPrivateHosts lets the fetcher dial loopback and private
	// addresses. For test harnesses and closed networks only. Draft §10.7
	// says a production AS MUST NOT fetch them.
	AllowPrivateHosts bool
	// RootCAs, when set, are the CAs the guarded client trusts instead of
	// the system roots.
	RootCAs *x509.CertPool
	// HTTPClient replaces the guarded client, for tests. It brings its own
	// dial policy, but no redirect is followed with it either.
	HTTPClient *http.Client
	// Now replaces time.Now, for tests.
	Now func() time.Time

	mu     sync.Mutex
	cache  map[string]cimdEntry
	client *http.Client
}

type cimdEntry struct {
	app       *core.AppRegistration
	fetchedAt time.Time
	expires   time.Time
}

// GetApp returns the registration for req.ClientID. A metadata-document
// client_id is resolved as the type's doc describes, with errors that wrap
// ErrInvalidClientMetadata or ErrClientMetadataUnavailable. Any other
// client_id goes to the wrapped store.
func (s *CIMDAppStore) GetApp(ctx context.Context, req *core.GetAppRequest) (*core.GetAppResponse, error) {
	if req == nil || !IsClientIDMetadataDocumentURL(req.ClientID) {
		if s.AppRegistrationStore == nil {
			return nil, core.ErrAppNotFound
		}
		return s.AppRegistrationStore.GetApp(ctx, req)
	}
	app, err := s.resolve(ctx, req.ClientID)
	if err != nil {
		return nil, err
	}
	copied := *app
	return &core.GetAppResponse{App: &copied}, nil
}

func (s *CIMDAppStore) resolve(ctx context.Context, clientID string) (*core.AppRegistration, error) {
	if err := ValidateClientIDMetadataDocumentURL(clientID); err != nil {
		return nil, err
	}
	if s.Issuer != "" && clientID == s.Issuer {
		return nil, fmt.Errorf("%w: client_id must not be the authorization server's issuer", ErrInvalidClientMetadata)
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[string]cimdEntry{}
	}
	cached, ok := s.cache[clientID]
	if ok && now.Before(cached.expires) {
		return cached.app, nil
	}
	app, ttl, err := s.fetch(ctx, clientID)
	if err != nil {
		if errors.Is(err, ErrClientMetadataUnavailable) && ok && now.Sub(cached.fetchedAt) < cimdStaleLimit {
			return cached.app, nil
		}
		delete(s.cache, clientID)
		return nil, err
	}
	s.cache[clientID] = cimdEntry{app: app, fetchedAt: now, expires: now.Add(ttl)}
	return app, nil
}

// fetch GETs the document and validates it. The caller holds s.mu.
func (s *CIMDAppStore) fetch(ctx context.Context, clientID string) (*core.AppRegistration, time.Duration, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrInvalidClientMetadata, err)
	}
	httpReq.Header.Set("Accept", "application/json")
	resp, err := s.httpClient().Do(httpReq)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: fetch %s: %v", ErrClientMetadataUnavailable, clientID, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		return nil, 0, fmt.Errorf("%w: fetch %s: status %d", ErrClientMetadataUnavailable, clientID, resp.StatusCode)
	default:
		// §6.1: any other status, including a redirect, which is never
		// followed, is an error.
		return nil, 0, fmt.Errorf("%w: fetch %s: status %d", ErrInvalidClientMetadata, clientID, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: read %s: %v", ErrClientMetadataUnavailable, clientID, err)
	}
	if len(body) > cimdMaxBytes {
		return nil, 0, fmt.Errorf("%w: document is over %d bytes", ErrInvalidClientMetadata, cimdMaxBytes)
	}
	app, err := validateClientMetadataDocument(clientID, body, cimdSupport{
		grants:       orStrings(s.GrantTypes, cimdDefaultGrantTypes),
		responses:    orStrings(s.ResponseTypes, cimdDefaultResponseTypes),
		userinfoAlgs: s.UserinfoSigningAlgs,
		jarmAlgs:     s.AuthorizationSigningAlgs,
	})
	if err != nil {
		return nil, 0, err
	}
	return app, cimdTTL(resp.Header), nil
}

var (
	cimdDefaultGrantTypes    = []string{AuthorizationCodeGrantType, "refresh_token"}
	cimdDefaultResponseTypes = []string{"code"}
	// cimdSharedSecretMethods are the token_endpoint_auth_method values
	// draft §4.1 forbids, since the client has no secret the AS issued.
	cimdSharedSecretMethods = []string{"client_secret_basic", "client_secret_post", "client_secret_jwt"}
	// jwkPrivateMembers are the JWK members that carry private or
	// symmetric key material (RFC 7518 §6.2.2, §6.3.2, §6.4.1).
	jwkPrivateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
)

// clientMetadataDocument is the part of an RFC 7591 client metadata
// document a CIMD client's registration uses.
type clientMetadataDocument struct {
	ClientID                           string          `json:"client_id"`
	ClientName                         string          `json:"client_name"`
	ClientURI                          string          `json:"client_uri"`
	RedirectURIs                       []string        `json:"redirect_uris"`
	GrantTypes                         []string        `json:"grant_types"`
	ResponseTypes                      []string        `json:"response_types"`
	Scope                              string          `json:"scope"`
	TokenEndpointAuthMethod            string          `json:"token_endpoint_auth_method"`
	TokenEndpointAuthSigningAlg        string          `json:"token_endpoint_auth_signing_alg"`
	AuthorizationSignedResponseAlg     string          `json:"authorization_signed_response_alg"`
	UserinfoSignedResponseAlg          string          `json:"userinfo_signed_response_alg"`
	DPoPBoundAccessTokens              bool            `json:"dpop_bound_access_tokens"`
	RequirePushedAuthorizationRequests bool            `json:"require_pushed_authorization_requests"`
	JWKSURI                            string          `json:"jwks_uri"`
	JWKS                               json.RawMessage `json:"jwks"`
	PolicyURI                          string          `json:"policy_uri"`
	TOSURI                             string          `json:"tos_uri"`
	ClientSecret                       *string         `json:"client_secret"`
	ClientSecretExpiresAt              json.RawMessage `json:"client_secret_expires_at"`
}

// validateClientMetadataDocument checks body as the metadata document for
// clientID (draft §4, §4.1, §5, §6) and returns the registration it
// describes:
//   - a JSON object whose client_id equals clientID exactly;
//   - redirect_uris and client_name present, which MCP requires;
//   - no client_secret or client_secret_expires_at;
//   - token_endpoint_auth_method none or private_key_jwt, none when absent
//     (never RFC 7591's client_secret_basic default);
//   - private_key_jwt with exactly one of jwks and jwks_uri, and jwks
//     holding public keys only;
//   - grant_types and response_types cut down to what the AS supports, not
//     empty.
//
// cimdSupport is what the AS supports, which a document is checked against.
type cimdSupport struct {
	grants, responses      []string
	userinfoAlgs, jarmAlgs []string
}

func validateClientMetadataDocument(clientID string, body []byte, support cimdSupport) (*core.AppRegistration, error) {
	var doc clientMetadataDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: document is not a JSON object: %v", ErrInvalidClientMetadata, err)
	}
	if doc.ClientID != clientID {
		return nil, fmt.Errorf("%w: document client_id %q does not match the URL", ErrInvalidClientMetadata, doc.ClientID)
	}
	if len(doc.RedirectURIs) == 0 {
		return nil, fmt.Errorf("%w: document has no redirect_uris", ErrInvalidClientMetadata)
	}
	if doc.ClientName == "" {
		return nil, fmt.Errorf("%w: document has no client_name", ErrInvalidClientMetadata)
	}
	if doc.ClientSecret != nil || len(doc.ClientSecretExpiresAt) > 0 {
		return nil, fmt.Errorf("%w: document must not carry client_secret or client_secret_expires_at", ErrInvalidClientMetadata)
	}
	method := doc.TokenEndpointAuthMethod
	if method == "" {
		method = "none"
	}
	switch {
	case slices.Contains(cimdSharedSecretMethods, method):
		return nil, fmt.Errorf("%w: token_endpoint_auth_method %s needs a shared secret, which a metadata document can't have", ErrInvalidClientMetadata, method)
	case method != "none" && method != "private_key_jwt":
		return nil, fmt.Errorf("%w: token_endpoint_auth_method %q is not supported", ErrInvalidClientMetadata, method)
	}
	hasJWKS := len(doc.JWKS) > 0 && string(doc.JWKS) != "null"
	if hasJWKS && doc.JWKSURI != "" {
		return nil, fmt.Errorf("%w: document must not carry both jwks and jwks_uri", ErrInvalidClientMetadata)
	}
	if method == "private_key_jwt" && !hasJWKS && doc.JWKSURI == "" {
		return nil, fmt.Errorf("%w: private_key_jwt needs jwks or jwks_uri", ErrInvalidClientMetadata)
	}
	if hasJWKS {
		if err := checkPublicJWKS(doc.JWKS); err != nil {
			return nil, err
		}
	}
	for field, alg := range map[string]struct {
		got       string
		supported []string
	}{
		"userinfo_signed_response_alg":      {doc.UserinfoSignedResponseAlg, support.userinfoAlgs},
		"authorization_signed_response_alg": {doc.AuthorizationSignedResponseAlg, support.jarmAlgs},
	} {
		if alg.got != "" && !slices.Contains(alg.supported, alg.got) {
			return nil, fmt.Errorf("%w: %s %q is not one this server signs with", ErrInvalidClientMetadata, field, alg.got)
		}
	}
	grants := intersect(orStrings(doc.GrantTypes, []string{AuthorizationCodeGrantType}), support.grants)
	if len(grants) == 0 {
		return nil, fmt.Errorf("%w: none of the document's grant_types is supported", ErrInvalidClientMetadata)
	}
	responses := intersect(orStrings(doc.ResponseTypes, []string{"code"}), support.responses)
	if len(responses) == 0 {
		return nil, fmt.Errorf("%w: none of the document's response_types is supported", ErrInvalidClientMetadata)
	}
	app := &core.AppRegistration{
		ClientID:                           clientID,
		ClientName:                         doc.ClientName,
		ClientURI:                          doc.ClientURI,
		RedirectURIs:                       doc.RedirectURIs,
		GrantTypes:                         grants,
		ResponseTypes:                      responses,
		Scope:                              doc.Scope,
		TokenEndpointAuthMethod:            method,
		TokenEndpointAuthSigningAlg:        doc.TokenEndpointAuthSigningAlg,
		AuthorizationSignedResponseAlg:     doc.AuthorizationSignedResponseAlg,
		UserinfoSignedResponseAlg:          doc.UserinfoSignedResponseAlg,
		DPoPBoundAccessTokens:              doc.DPoPBoundAccessTokens,
		RequirePushedAuthorizationRequests: doc.RequirePushedAuthorizationRequests,
		JWKSURI:                            doc.JWKSURI,
		PolicyURI:                          doc.PolicyURI,
		TOSURI:                             doc.TOSURI,
	}
	if hasJWKS {
		app.JWKS = doc.JWKS
	}
	return app, nil
}

// checkPublicJWKS refuses a jwks that isn't {"keys": [...]} or whose keys
// carry private or symmetric material (§4.1).
func checkPublicJWKS(raw json.RawMessage) error {
	var set struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil || len(set.Keys) == 0 {
		return fmt.Errorf("%w: jwks must be a JSON Web Key Set with at least one key", ErrInvalidClientMetadata)
	}
	for _, k := range set.Keys {
		for _, m := range jwkPrivateMembers {
			if _, ok := k[m]; ok {
				return fmt.Errorf("%w: jwks must hold public keys only (found %q)", ErrInvalidClientMetadata, m)
			}
		}
	}
	return nil
}

// cimdTTL reads the cache lifetime from Cache-Control (RFC 9111 §5.2.2.1),
// clamped to between cimdMinTTL and cimdMaxTTL. no-store and no-cache get
// the minimum. Expires is ignored, which §6.2 allows.
func cimdTTL(h http.Header) time.Duration {
	ttl := cimdDefaultTTL
	for _, part := range strings.Split(h.Get("Cache-Control"), ",") {
		d := strings.ToLower(strings.TrimSpace(part))
		switch {
		case d == "no-store" || d == "no-cache":
			return cimdMinTTL
		case strings.HasPrefix(d, "max-age="):
			if n, err := strconv.Atoi(strings.TrimPrefix(d, "max-age=")); err == nil && n >= 0 {
				ttl = time.Duration(n) * time.Second
			}
		}
	}
	return min(max(ttl, cimdMinTTL), cimdMaxTTL)
}

func (s *CIMDAppStore) httpClient() *http.Client {
	if s.HTTPClient != nil {
		c := *s.HTTPClient
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		c.Jar = nil
		return &c
	}
	if s.client == nil {
		s.client = guardedHTTPClient(s.AllowPrivateHosts, s.RootCAs, cimdHTTPTimeout, "client_id metadata document")
	}
	return s.client
}

func (s *CIMDAppStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func orStrings(v, def []string) []string {
	if len(v) == 0 {
		return def
	}
	return v
}

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) && !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}
