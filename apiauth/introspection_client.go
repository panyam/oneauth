package apiauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// IntrospectionValidator validates tokens by calling a remote introspection
// endpoint (RFC 7662), as an alternative to local JWT validation via JWKS.
//
// Use this when:
//   - The resource server can't access the KeyStore or JWKS endpoint
//   - Centralized blacklist checking is needed
//   - Opaque (non-JWT) tokens need validation
//
// The validator authenticates to the introspection endpoint using client
// credentials (client_secret_basic).
//
// Optional response caching reduces load on the auth server. Cache entries
// expire after CacheTTL (default: no cache).
//
// See: https://www.rfc-editor.org/rfc/rfc7662
type IntrospectionValidator struct {
	// IntrospectionURL is the auth server's introspection endpoint.
	// Required.
	IntrospectionURL string

	// ClientID and ClientSecret authenticate this resource server to the
	// introspection endpoint via HTTP Basic auth (client_secret_basic).
	// Required.
	ClientID     string
	ClientSecret string

	// HTTPClient is used for introspection requests. If nil, uses
	// http.DefaultClient.
	HTTPClient *http.Client

	// CacheTTL enables response caching. If > 0, introspection responses
	// are cached for this duration. A revoked token may remain "active"
	// in the cache for up to CacheTTL after revocation.
	// Default: 0 (no caching).
	CacheTTL time.Duration

	// cache stores introspection results keyed by token hash.
	mu    sync.RWMutex
	cache map[string]*cacheEntry
}

type cacheEntry struct {
	result *IntrospectionResult
	expiry time.Time
}

// IntrospectionResult holds the parsed introspection response.
type IntrospectionResult struct {
	Active    bool   `json:"active"`
	Sub       string `json:"sub,omitempty"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
	Aud       any    `json:"aud,omitempty"`
}

// Validate calls the introspection endpoint to check if a token is active.
// Returns the introspection result with parsed claims, or an error if the
// introspection request itself failed (network error, auth failure, etc.).
//
// An inactive token is NOT an error — it returns IntrospectionResult{Active: false}.
// Only transport/auth failures return errors.
func (v *IntrospectionValidator) Validate(token string) (*IntrospectionResult, error) {
	// Check cache first
	if v.CacheTTL > 0 {
		if cached := v.getCached(token); cached != nil {
			return cached, nil
		}
	}

	client := v.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	// POST to introspection endpoint with Basic auth
	data := url.Values{"token": {token}}
	req, err := http.NewRequest(http.MethodPost, v.IntrospectionURL,
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("introspection request build failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(v.ClientID, v.ClientSecret)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("introspection auth failed: invalid client credentials")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection returned status %d", resp.StatusCode)
	}

	var result IntrospectionResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("introspection response decode failed: %w", err)
	}

	// Cache the result
	if v.CacheTTL > 0 {
		v.putCached(token, &result)
	}

	return &result, nil
}

// ValidateForMiddleware validates a token and returns the fields that
// APIMiddleware.validateRequest needs: userID, scopes, authType, customClaims.
// Returns an error if the token is inactive or introspection fails.
func (v *IntrospectionValidator) ValidateForMiddleware(token string) (userID string, scopes []string, authType string, customClaims map[string]any, err error) {
	result, err := v.Validate(token)
	if err != nil {
		return "", nil, "", nil, err
	}
	if !result.Active {
		return "", nil, "", nil, fmt.Errorf("token is not active")
	}

	// Parse scopes
	if result.Scope != "" {
		scopes = strings.Split(result.Scope, " ")
	}

	// Build custom claims map
	customClaims = make(map[string]any)
	if result.ClientID != "" {
		customClaims["client_id"] = result.ClientID
	}
	if result.Iss != "" {
		customClaims["iss"] = result.Iss
	}
	if result.Jti != "" {
		customClaims["jti"] = result.Jti
	}
	if result.Aud != nil {
		customClaims["aud"] = result.Aud
	}

	return result.Sub, scopes, "introspection", customClaims, nil
}

// getCached returns a cached result if it exists and hasn't expired.
func (v *IntrospectionValidator) getCached(token string) *IntrospectionResult {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.cache == nil {
		return nil
	}
	entry, ok := v.cache[token]
	if !ok || time.Now().After(entry.expiry) {
		return nil
	}
	return entry.result
}

// putCached stores an introspection result in the cache.
func (v *IntrospectionValidator) putCached(token string, result *IntrospectionResult) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.cache == nil {
		v.cache = make(map[string]*cacheEntry)
	}
	v.cache[token] = &cacheEntry{
		result: result,
		expiry: time.Now().Add(v.CacheTTL),
	}
}
