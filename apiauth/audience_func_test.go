package apiauth_test

// Tests for OneAuthConfig.AudienceFunc — the deferred-audience-resolution
// path that lets an in-process AS mint tokens whose `aud` claim equals a
// resource server URL that's only known after the RS is built.
//
// See: docs/MIGRATION.md "AudienceFunc" section.

import (
	"context"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/apiauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// audienceVar wraps a string + mutex pair. The fixture below uses it
// to model the canonical use case: build OneAuth once, swap the
// audience value in later as resource servers come online.
type audienceVar struct {
	mu  sync.Mutex
	val string
}

func (a *audienceVar) get() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.val
}

func (a *audienceVar) set(v string) {
	a.mu.Lock()
	a.val = v
	a.mu.Unlock()
}

func newAudienceFuncFixture(t *testing.T, a *audienceVar) *apiauth.OneAuth {
	t.Helper()
	return apiauth.NewOneAuth(apiauth.OneAuthConfig{
		SigningKey:   []byte("audience-func-test-secret-32ch!"),
		SigningAlg:   "HS256",
		Issuer:       "audience-func-test",
		AudienceFunc: a.get,
	})
}

// audClaim extracts the `aud` claim from a JWT without verifying the
// signature; tests only inspect the issued shape.
func audClaim(t *testing.T, token string) any {
	t.Helper()
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	require.NoError(t, err)
	claims, _ := parsed.Claims.(jwt.MapClaims)
	return claims["aud"]
}

// TestAudienceFunc_LateBinding pins the canonical use case: the
// audience is unknown when NewOneAuth runs, becomes known later, and
// every subsequent CreateAccessToken stamps the *current* value. No
// rebuild of OneAuth is required.
func TestAudienceFunc_LateBinding(t *testing.T) {
	audVar := &audienceVar{}
	oa := newAudienceFuncFixture(t, audVar)

	// Audience not yet bound — issued token must have no `aud` claim.
	resp, err := oa.Issuer.CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "u1"})
	require.NoError(t, err)
	assert.Nil(t, audClaim(t, resp.Token), "aud MUST be omitted when AudienceFunc returns empty")

	// Audience comes online (e.g., RS URL is now known).
	audVar.set("https://rs.example/mcp")
	resp, err = oa.Issuer.CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "u2"})
	require.NoError(t, err)
	assert.Equal(t, "https://rs.example/mcp", audClaim(t, resp.Token),
		"aud MUST reflect the AudienceFunc value at mint time")

	// Audience changes again — next mint sees the new value.
	audVar.set("https://rs2.example/mcp")
	resp, err = oa.Issuer.CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "u3"})
	require.NoError(t, err)
	assert.Equal(t, "https://rs2.example/mcp", audClaim(t, resp.Token),
		"AudienceFunc MUST be consulted on every mint, not cached")
}

// TestAudienceFunc_TakesPrecedenceOverEagerAudience pins resolution
// order: when both Audience and AudienceFunc are set, the closure
// wins as long as it returns non-empty. An empty return falls back
// to the eager value so callers can opt out of the lazy path
// per-mint.
func TestAudienceFunc_TakesPrecedenceOverEagerAudience(t *testing.T) {
	audVar := &audienceVar{val: "https://lazy.example"}
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		SigningKey:   []byte("audience-func-test-secret-32ch!"),
		SigningAlg:   "HS256",
		Issuer:       "audience-func-test",
		Audience:     "https://eager.example",
		AudienceFunc: audVar.get,
	})

	resp, err := oa.Issuer.CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "u1"})
	require.NoError(t, err)
	assert.Equal(t, "https://lazy.example", audClaim(t, resp.Token),
		"AudienceFunc MUST take precedence when it returns non-empty")

	// Empty return → fall back to eager Audience.
	audVar.set("")
	resp, err = oa.Issuer.CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "u2"})
	require.NoError(t, err)
	assert.Equal(t, "https://eager.example", audClaim(t, resp.Token),
		"AudienceFunc returning empty MUST fall back to the eager Audience")
}

// TestAudienceFunc_ValidatorPath pins that the validator side honors
// the same closure. Critical for AS-internal introspection: when the
// AS's audience moves, its own validator must accept the new aud.
func TestAudienceFunc_ValidatorPath(t *testing.T) {
	audVar := &audienceVar{val: "https://rs.example"}
	oa := newAudienceFuncFixture(t, audVar)

	resp, err := oa.Issuer.CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{Subject: "u1"})
	require.NoError(t, err)

	// Token carries aud=rs.example; validator (same closure) accepts.
	if _, err := oa.Validator.ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: resp.Token}); err != nil {
		t.Fatalf("validator MUST accept token whose aud matches AudienceFunc: %v", err)
	}

	// Closure moves; the previously-issued token (aud=rs.example) no
	// longer matches and validation MUST fail. The validator does not
	// cache the expected audience.
	audVar.set("https://different.example")
	if _, err := oa.Validator.ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: resp.Token}); err == nil {
		t.Fatal("validator MUST reject token whose aud no longer matches AudienceFunc")
	}
}
