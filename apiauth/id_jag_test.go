// Tests for ID-JAG (Identity Assertion Authorization Grant) issuance and
// redemption — the MCP Enterprise-Managed Authorization two-stage chain:
//
//	IdP /token   (RFC 8693 token-exchange)   id_token → id-jag
//	AS  /token   (RFC 7523 jwt-bearer)        id-jag   → MCP access token
//
// See:
//   - draft-ietf-oauth-identity-assertion-authz-grant-04
//   - RFC 8693:  https://www.rfc-editor.org/rfc/rfc8693
//   - RFC 7523:  https://www.rfc-editor.org/rfc/rfc7523
//   - MCP EMA:   https://github.com/modelcontextprotocol/ext-auth (enterprise-managed-authorization)
//   - oneauth issue 350
package apiauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/apiauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseUnverified decodes a compact JWT's header + claims without checking
// the signature — for asserting on token contents in tests.
func parseUnverified(t *testing.T, raw string) (header map[string]any, claims jwt.MapClaims) {
	t.Helper()
	tok, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(raw, jwt.MapClaims{})
	require.NoError(t, err)
	return tok.Header, tok.Claims.(jwt.MapClaims)
}

// TestIDJAG_CreateIDJAG_HeaderAndClaims verifies the minted ID-JAG carries
// the draft `typ` header and the required claim set with `aud` bound to the
// request audience (not pinned at construction).
func TestIDJAG_CreateIDJAG_HeaderAndClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	iss := apiauth.NewJWTIDJAGIssuer(apiauth.IDJAGIssuerConfig{
		SigningKey: key,
		SigningAlg: "RS256",
		Issuer:     "https://idp.example.com",
		TTL:        time.Minute,
	})

	res, err := iss.CreateIDJAG(context.Background(), &apiauth.CreateIDJAGRequest{
		Subject:  "alice@corp.example.com",
		Audience: "https://rs-as.example.com",
		ClientID: "mcp-client-1",
		Scopes:   []string{"read", "write"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.Token)

	header, claims := parseUnverified(t, res.Token)
	assert.Equal(t, apiauth.IDJAGTypeHeader, header["typ"],
		"ID-JAG MUST carry typ=oauth-id-jag+jwt so the redeemer can distinguish it")
	assert.Equal(t, "https://idp.example.com", claims["iss"])
	assert.Equal(t, "alice@corp.example.com", claims["sub"])
	assert.Equal(t, "https://rs-as.example.com", claims["aud"], "aud MUST bind to the request audience")
	assert.Equal(t, "mcp-client-1", claims["client_id"])
	assert.Equal(t, "read write", claims["scope"])
	assert.NotEmpty(t, claims["jti"], "ID-JAG MUST carry a jti for single-use enforcement")
	assert.NotEmpty(t, claims["exp"])
	assert.NotEmpty(t, claims["iat"])
}

// TestIDJAG_CreateIDJAG_RequiresSubjectAndAudience — an ID-JAG with no
// subject or no target AS is not redeemable; the issuer rejects both.
func TestIDJAG_CreateIDJAG_RequiresSubjectAndAudience(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	iss := apiauth.NewJWTIDJAGIssuer(apiauth.IDJAGIssuerConfig{SigningKey: key, SigningAlg: "RS256", Issuer: "https://idp.example.com"})

	_, err = iss.CreateIDJAG(context.Background(), &apiauth.CreateIDJAGRequest{Audience: "https://rs-as.example.com"})
	assert.Error(t, err, "missing subject MUST error")

	_, err = iss.CreateIDJAG(context.Background(), &apiauth.CreateIDJAGRequest{Subject: "alice"})
	assert.Error(t, err, "missing audience MUST error")
}

// ---------------------------------------------------------------------------
// Two-AS harness: an IdP AS that issues ID-JAGs and an RS AS that redeems.
// ---------------------------------------------------------------------------

type idjagEnv struct {
	idpAuth  *apiAuthFixture // IdP AS — issues id-jag via token-exchange
	rsAuth   *apiAuthFixture // RS AS — redeems id-jag via jwt-bearer
	loginKey *rsa.PrivateKey // signs the subject id_token
	idjagKey *rsa.PrivateKey // the IdP AS's id-jag signing key

	loginIssuer string
	idpASIssuer string // id-jag iss
	rsASIssuer  string // id-jag aud (the RS AS)
	idpASAud    string // audience the subject id_token must carry
	mcpClientID string
	mcpServer   string
}

func newIDJAGEnv(t *testing.T) *idjagEnv {
	t.Helper()
	loginKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	idjagKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	e := &idjagEnv{
		loginKey:    loginKey,
		idjagKey:    idjagKey,
		loginIssuer: "https://login-idp.example.com",
		idpASIssuer: "https://idp-as.example.com",
		rsASIssuer:  "https://rs-as.example.com",
		idpASAud:    "https://idp-as.example.com/api/token",
		mcpClientID: "mcp-client-1",
		mcpServer:   "https://mcp.example.com",
	}

	// IdP AS: trusts the login IdP for subject_tokens, and is opted into
	// ID-JAG issuance signed with its own id-jag key.
	e.idpAuth = newAPIAuthFixture(apiauth.OneAuthConfig{
		SigningKey: []byte("idp-as-secret-key-for-testing-only"),
		SigningAlg: "HS256",
		Issuer:     e.idpASIssuer,
		Audience:   e.idpASAud,
		TrustedAssertionIssuers: []apiauth.TrustedAssertionIssuer{{
			Issuer:             e.loginIssuer,
			PublicKey:          &loginKey.PublicKey,
			Audiences:          []string{e.idpASAud},
			AcceptedAlgorithms: []string{"RS256"},
		}},
		IDJAGIssuer: apiauth.NewJWTIDJAGIssuer(apiauth.IDJAGIssuerConfig{
			SigningKey: idjagKey,
			SigningAlg: "RS256",
			Issuer:     e.idpASIssuer,
			TTL:        time.Minute,
		}),
	}, nil)

	// RS AS: trusts the IdP AS (the id-jag iss + key) with aud pinned to
	// itself, per RFC 7523 §3.
	e.rsAuth = newAPIAuthFixture(apiauth.OneAuthConfig{
		SigningKey: []byte("rs-as-secret-key-for-testing-only"),
		SigningAlg: "HS256",
		Issuer:     e.rsASIssuer,
		Audience:   e.rsASIssuer,
		TrustedAssertionIssuers: []apiauth.TrustedAssertionIssuer{{
			Issuer:             e.idpASIssuer,
			PublicKey:          &idjagKey.PublicKey,
			Audiences:          []string{e.rsASIssuer},
			AcceptedAlgorithms: []string{"RS256"},
		}},
	}, nil)

	return e
}

// mintIDToken signs a subject id_token with the login IdP key.
func (e *idjagEnv) mintIDToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": e.loginIssuer,
		"sub": "alice@corp.example.com",
		"aud": e.idpASAud,
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"nbf": now.Add(-1 * time.Second).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(e.loginKey)
	require.NoError(t, err)
	return signed
}

// issueIDJAG runs stage 1: exchange the id_token for an ID-JAG at the IdP AS.
// audienceOverride, when non-empty, replaces the default rsASIssuer audience
// (used to force an aud mismatch at redemption).
func (e *idjagEnv) issueIDJAG(t *testing.T, audienceOverride string) (int, map[string]any) {
	t.Helper()
	audience := e.rsASIssuer
	if audienceOverride != "" {
		audience = audienceOverride
	}
	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token", e.mintIDToken(t))
	form.Set("subject_token_type", apiauth.TokenTypeIDToken)
	form.Set("requested_token_type", apiauth.TokenTypeIDJAG)
	form.Set("audience", audience)
	form.Set("resource", e.mcpServer)
	form.Set("client_id", e.mcpClientID)
	form.Set("scope", "read")
	return postForm(t, e.idpAuth, form)
}

// redeemIDJAG runs stage 2: present the ID-JAG to the RS AS jwt-bearer grant.
func (e *idjagEnv) redeemIDJAG(t *testing.T, idjag string) (int, map[string]any) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", apiauth.JwtBearerGrantType)
	form.Set("assertion", idjag)
	form.Set("scope", "read")
	return postForm(t, e.rsAuth, form)
}

// TestTokenExchange_IDJAG_HappyPath — stage 1 with subject_token_type=id_token
// returns an oauth-id-jag+jwt with token_type=N_A, issued_token_type=id-jag,
// and aud/client_id bound from the request.
func TestTokenExchange_IDJAG_HappyPath(t *testing.T) {
	e := newIDJAGEnv(t)

	status, body := e.issueIDJAG(t, "")
	require.Equal(t, http.StatusOK, status, "stage-1 id-jag exchange MUST succeed")

	assert.Equal(t, apiauth.TokenTypeIDJAG, body["issued_token_type"])
	assert.Equal(t, apiauth.TokenTypeNA, body["token_type"],
		"non-access-token output MUST report token_type=N_A (RFC 8693 §2.2.1)")
	idjag, _ := body["access_token"].(string)
	require.NotEmpty(t, idjag)

	header, claims := parseUnverified(t, idjag)
	assert.Equal(t, apiauth.IDJAGTypeHeader, header["typ"])
	assert.Equal(t, e.idpASIssuer, claims["iss"])
	assert.Equal(t, "alice@corp.example.com", claims["sub"])
	assert.Equal(t, e.rsASIssuer, claims["aud"], "aud MUST bind to the request audience")
	assert.Equal(t, e.mcpClientID, claims["client_id"])
	assert.Equal(t, e.mcpServer, claims["resource"])
}

// TestTokenExchange_IDJAG_NotEnabled — without an IDJAGIssuer wired, an
// id-jag request is rejected with invalid_request even though token-exchange
// is otherwise configured.
func TestTokenExchange_IDJAG_NotEnabled(t *testing.T) {
	env := newJwtBearerTestEnv(t) // token-exchange configured, no IDJAGIssuer
	subjectToken := env.mintAssertion(t, nil)

	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", apiauth.TokenTypeJWT)
	form.Set("requested_token_type", apiauth.TokenTypeIDJAG)
	form.Set("audience", "https://rs-as.example.com")

	status, body := postForm(t, env.apiAuth, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_request", body["error"])
	assert.Contains(t, body["error_description"], "not enabled")
}

// TestTokenExchange_IDJAG_RequiresAudience — audience is mandatory for id-jag
// output (it becomes the target-AS aud); omitting it is invalid_request.
func TestTokenExchange_IDJAG_RequiresAudience(t *testing.T) {
	e := newIDJAGEnv(t)
	form := url.Values{}
	form.Set("grant_type", apiauth.TokenExchangeGrantType)
	form.Set("subject_token", e.mintIDToken(t))
	form.Set("subject_token_type", apiauth.TokenTypeIDToken)
	form.Set("requested_token_type", apiauth.TokenTypeIDJAG)
	// audience intentionally omitted.

	status, body := postForm(t, e.idpAuth, form)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_request", body["error"])
	assert.Contains(t, body["error_description"], "audience")
}

// TestJwtBearer_IDJAG_Redemption_BindsClientID — stage 2 redeems the ID-JAG
// and binds the issued access token to the ID-JAG subject and client_id.
func TestJwtBearer_IDJAG_Redemption_BindsClientID(t *testing.T) {
	e := newIDJAGEnv(t)
	_, issued := e.issueIDJAG(t, "")
	idjag, _ := issued["access_token"].(string)
	require.NotEmpty(t, idjag)

	status, body := e.redeemIDJAG(t, idjag)
	require.Equal(t, http.StatusOK, status, "stage-2 id-jag redemption MUST succeed")
	accessToken, _ := body["access_token"].(string)
	require.NotEmpty(t, accessToken)

	_, claims := parseUnverified(t, accessToken)
	assert.Equal(t, "alice@corp.example.com", claims["sub"], "access token MUST carry the id-jag subject")
	assert.Equal(t, e.mcpClientID, claims["client_id"],
		"access token MUST bind the id-jag client_id (draft §5)")
}

// TestJwtBearer_IDJAG_Redemption_ReplayRejected — an ID-JAG is single-use;
// redeeming the same one twice fails the second time.
func TestJwtBearer_IDJAG_Redemption_ReplayRejected(t *testing.T) {
	e := newIDJAGEnv(t)
	_, issued := e.issueIDJAG(t, "")
	idjag, _ := issued["access_token"].(string)
	require.NotEmpty(t, idjag)

	status1, _ := e.redeemIDJAG(t, idjag)
	require.Equal(t, http.StatusOK, status1, "first redemption MUST succeed")

	status2, body2 := e.redeemIDJAG(t, idjag)
	assert.Equal(t, http.StatusBadRequest, status2, "replayed id-jag MUST be rejected")
	assert.Equal(t, "invalid_grant", body2["error"])
	assert.Contains(t, body2["error_description"], "replay")
}

// TestJwtBearer_IDJAG_Redemption_AudienceMismatch — an ID-JAG whose aud names
// a different AS is rejected (RFC 7523 §3 audience check).
func TestJwtBearer_IDJAG_Redemption_AudienceMismatch(t *testing.T) {
	e := newIDJAGEnv(t)
	_, issued := e.issueIDJAG(t, "https://wrong-as.example.com")
	idjag, _ := issued["access_token"].(string)
	require.NotEmpty(t, idjag)

	status, body := e.redeemIDJAG(t, idjag)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])
}
