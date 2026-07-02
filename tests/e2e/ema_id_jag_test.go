package e2e

// E2E for the MCP Enterprise-Managed Authorization (SEP-990) chain where the
// redeeming AS discovers the ID-JAG signing key over JWKS by `kid` — the
// production path, not a pre-shared static key. Complements the
// static-PublicKey coverage in apiauth/id_jag_test.go and the SDK-driven
// two-leg check in client/enterprise_managed_e2e_test.go.
//
// Leg 1 (IdP AS): signs the ID-JAG with its own RS256 key (published in its
// JWKS). Leg 2 (RS AS): trusts the IdP by issuer URL only, resolving the
// signing key via keys.JWKSKeyStore.GetKeyByKid over real HTTP.
//
// See:
//   - draft-ietf-oauth-identity-assertion-authz-grant-04
//   - oneauth issue 350

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/testutil"
)

// postTokenForm POSTs a form to a token endpoint URL and decodes the JSON
// body. Distinct from the SDK-driven client e2e — this drives the raw wire.
func postTokenForm(t *testing.T, endpoint string, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(endpoint, form)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func TestEMA_IDJAG_JWKSDiscoveryRedemption(t *testing.T) {
	loginKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const (
		loginIssuer = "https://login-idp.example.com"
		idpASIssuer = "https://idp-as.example.com"
		rsASIssuer  = "https://rs-as.example.com"
		idpASAud    = "https://idp-as.example.com/api/token"
		mcpClientID = "mcp-client-1"
	)

	// Leg 1 — IdP AS. Validates the login id_token, mints an ID-JAG signed
	// with its own JWKS-published RS256 key.
	idpSrv := testutil.NewTestAuthServer(t,
		testutil.WithIssuer(idpASIssuer),
		testutil.WithAudience(idpASAud),
		testutil.WithTrustedAssertionIssuers([]apiauth.TrustedAssertionIssuer{{
			Issuer:             loginIssuer,
			PublicKey:          &loginKey.PublicKey,
			Audiences:          []string{idpASAud},
			AcceptedAlgorithms: []string{"RS256"},
		}}),
		testutil.WithIDJAGIssuanceSelfSigned(time.Minute),
	)

	// The RS AS resolves the IdP's signing key from its JWKS by kid — it is
	// given the issuer URL and JWKS endpoint, never a static key.
	jwksStore := keys.NewJWKSKeyStore(idpSrv.JWKSURL())
	require.NoError(t, jwksStore.Start())
	t.Cleanup(jwksStore.Stop)
	jwksKeyFunc := func(token *jwt.Token) (crypto.PublicKey, error) {
		kid, _ := token.Header["kid"].(string)
		resp, err := jwksStore.GetKeyByKid(context.Background(), &keys.GetKeyByKidRequest{Kid: kid})
		if err != nil {
			return nil, err
		}
		return resp.Record.Key, nil
	}

	// Leg 2 — RS AS. Trusts the IdP by issuer + JWKS-resolved key only.
	rsSrv := testutil.NewTestAuthServer(t,
		testutil.WithIssuer(rsASIssuer),
		testutil.WithAudience(rsASIssuer),
		testutil.WithTrustedAssertionIssuers([]apiauth.TrustedAssertionIssuer{{
			Issuer:             idpASIssuer,
			KeyFunc:            jwksKeyFunc,
			Audiences:          []string{rsASIssuer},
			AcceptedAlgorithms: []string{"RS256"},
		}}),
	)

	// Login IdP's id_token about the user.
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

	// Leg 1 — exchange id_token → ID-JAG at the IdP AS.
	exForm := url.Values{}
	exForm.Set("grant_type", apiauth.TokenExchangeGrantType)
	exForm.Set("subject_token", idToken)
	exForm.Set("subject_token_type", apiauth.TokenTypeIDToken)
	exForm.Set("requested_token_type", apiauth.TokenTypeIDJAG)
	exForm.Set("audience", rsASIssuer)
	exForm.Set("client_id", mcpClientID)
	exStatus, exBody := postTokenForm(t, idpSrv.TokenEndpoint(), exForm)
	require.Equal(t, 200, exStatus, "id-jag issuance MUST succeed: %v", exBody)
	idjag, _ := exBody["access_token"].(string)
	require.NotEmpty(t, idjag)

	// The ID-JAG header carries a kid the RS AS can resolve from JWKS.
	idjagTok, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(idjag, jwt.MapClaims{})
	require.NoError(t, err)
	assert.Equal(t, apiauth.IDJAGTypeHeader, idjagTok.Header["typ"])
	assert.NotEmpty(t, idjagTok.Header["kid"], "ID-JAG MUST carry a kid for JWKS discovery")

	// Leg 2 — redeem the ID-JAG at the RS AS, which fetches the IdP JWKS.
	rdForm := url.Values{}
	rdForm.Set("grant_type", apiauth.JwtBearerGrantType)
	rdForm.Set("assertion", idjag)
	rdStatus, rdBody := postTokenForm(t, rsSrv.TokenEndpoint(), rdForm)
	require.Equal(t, 200, rdStatus, "JWKS-discovery redemption MUST succeed: %v", rdBody)
	accessToken, _ := rdBody["access_token"].(string)
	require.NotEmpty(t, accessToken)

	accTok, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(accessToken, jwt.MapClaims{})
	require.NoError(t, err)
	claims := accTok.Claims.(jwt.MapClaims)
	assert.Equal(t, "alice@corp.example.com", claims["sub"])
	assert.Equal(t, mcpClientID, claims["client_id"], "access token MUST bind the id-jag client_id")
}
