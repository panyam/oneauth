package client_test

// E2E coverage for the MCP Enterprise-Managed Authorization (SEP-990)
// two-stage chain against real in-process oneauth ASes on BOTH legs, driven
// through the client SDK — the same wire conversation mcpkit
// ext/auth/enterprise_managed.go performs:
//
//	IdP AS /token  (RFC 8693 token-exchange)  id_token → id-jag   (leg 1)
//	RS  AS /token  (RFC 7523 jwt-bearer)       id-jag   → access   (leg 2)
//
// This is the reference-impl / wire-format check: it exercises the exact
// token-type URNs, typ header, and token_type=N_A the mcpkit client is fixed
// on. See:
//   - draft-ietf-oauth-identity-assertion-authz-grant-04
//   - MCP EMA: https://github.com/modelcontextprotocol/ext-auth
//   - oneauth issue 350

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/client"
	"github.com/panyam/oneauth/testutil"
)

func TestEnterpriseManaged_E2E_TwoLegChain(t *testing.T) {
	loginKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	idjagKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const (
		loginIssuer = "https://login-idp.example.com"
		idpASIssuer = "https://idp-as.example.com"
		rsASIssuer  = "https://rs-as.example.com"
		idpASAud    = "https://idp-as.example.com/api/token"
		mcpClientID = "mcp-client-1"
		mcpServer   = "https://mcp.example.com"
	)

	// IdP AS (leg 1): validates the login id_token, issues an ID-JAG signed
	// with idjagKey.
	idpSrv := testutil.NewTestAuthServer(t,
		testutil.WithIssuer(idpASIssuer),
		testutil.WithAudience(idpASAud),
		testutil.WithTrustedAssertionIssuers([]apiauth.TrustedAssertionIssuer{{
			Issuer:             loginIssuer,
			PublicKey:          &loginKey.PublicKey,
			Audiences:          []string{idpASAud},
			AcceptedAlgorithms: []string{"RS256"},
		}}),
		testutil.WithIDJAGIssuer(apiauth.NewJWTIDJAGIssuer(apiauth.IDJAGIssuerConfig{
			SigningKey: idjagKey,
			SigningAlg: "RS256",
			Issuer:     idpASIssuer,
			TTL:        time.Minute,
		})),
	)
	defer idpSrv.Close()

	// RS AS (leg 2): trusts the IdP AS as an assertion issuer and redeems
	// the ID-JAG.
	rsSrv := testutil.NewTestAuthServer(t,
		testutil.WithIssuer(rsASIssuer),
		testutil.WithAudience(rsASIssuer),
		testutil.WithTrustedAssertionIssuers([]apiauth.TrustedAssertionIssuer{{
			Issuer:             idpASIssuer,
			PublicKey:          &idjagKey.PublicKey,
			Audiences:          []string{rsASIssuer},
			AcceptedAlgorithms: []string{"RS256"},
		}}),
	)
	defer rsSrv.Close()

	// The login IdP's id_token about the user.
	now := time.Now()
	idToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": loginIssuer,
		"sub": "alice@corp.example.com",
		"aud": idpASAud,
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"nbf": now.Add(-1 * time.Second).Unix(),
	}).SignedString(loginKey)
	require.NoError(t, err)

	// Leg 1 — exchange the id_token for an ID-JAG.
	idp := client.NewAuthClient(idpSrv.URL(), nil, client.WithTokenEndpoint("/api/token"))
	exch, err := idp.TokenExchange(context.Background(), &client.TokenExchangeRequest{
		ClientID:           mcpClientID,
		SubjectToken:       idToken,
		SubjectTokenType:   apiauth.TokenTypeIDToken,
		RequestedTokenType: apiauth.TokenTypeIDJAG,
		Audience:           []string{rsASIssuer},
		Resource:           []string{mcpServer},
		Scope:              []string{"read"},
	})
	require.NoError(t, err, "leg 1 (id-jag issuance) MUST succeed")
	assert.Equal(t, apiauth.TokenTypeIDJAG, exch.IssuedTokenType,
		"issued_token_type MUST be the id-jag URN")
	assert.Equal(t, apiauth.TokenTypeNA, exch.TokenType,
		"non-access-token output MUST report token_type=N_A")
	require.NotEmpty(t, exch.AccessToken, "the id-jag rides in the access_token field")

	// The ID-JAG carries the draft typ header and target-AS aud.
	idjagHeader, idjagClaims := parseUnverifiedEMA(t, exch.AccessToken)
	assert.Equal(t, apiauth.IDJAGTypeHeader, idjagHeader["typ"])
	assert.Equal(t, rsASIssuer, idjagClaims["aud"])
	assert.Equal(t, mcpClientID, idjagClaims["client_id"])

	// Leg 2 — redeem the ID-JAG for an MCP access token at the RS AS.
	as := client.NewAuthClient(rsSrv.URL(), nil, client.WithTokenEndpoint("/api/token"))
	cred, err := as.JwtBearerGrant(context.Background(), &client.JwtBearerGrantRequest{
		ClientID:  mcpClientID,
		Assertion: exch.AccessToken,
	})
	require.NoError(t, err, "leg 2 (id-jag redemption) MUST succeed")
	require.NotEmpty(t, cred.AccessToken)

	_, accessClaims := parseUnverifiedEMA(t, cred.AccessToken)
	assert.Equal(t, "alice@corp.example.com", accessClaims["sub"],
		"the MCP access token MUST carry the id-jag subject")
	assert.Equal(t, mcpClientID, accessClaims["client_id"],
		"the MCP access token MUST bind the id-jag client_id")

	// Single-use: replaying the same ID-JAG MUST fail.
	_, err = as.JwtBearerGrant(context.Background(), &client.JwtBearerGrantRequest{
		ClientID:  mcpClientID,
		Assertion: exch.AccessToken,
	})
	assert.Error(t, err, "a replayed id-jag MUST be rejected (single-use)")
}

func parseUnverifiedEMA(t *testing.T, raw string) (map[string]any, jwt.MapClaims) {
	t.Helper()
	tok, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(raw, jwt.MapClaims{})
	require.NoError(t, err)
	return tok.Header, tok.Claims.(jwt.MapClaims)
}
