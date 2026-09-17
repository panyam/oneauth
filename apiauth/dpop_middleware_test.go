package apiauth_test

// Resource-server tests for DPoP (RFC 9449 §7): which presentations of a
// sender-constrained token a protected resource accepts, and which it must
// refuse. Every rejection here is the difference between a binding that
// constrains a thief and one that only looks like it does.
//
// References:
//   - RFC 9449 §7.1 (https://www.rfc-editor.org/rfc/rfc9449#section-7.1) — the DPoP scheme
//   - RFC 9449 §7.2 (https://www.rfc-editor.org/rfc/rfc9449#section-7.2) — Bearer compatibility
//   - RFC 6750 §3.1 (https://www.rfc-editor.org/rfc/rfc6750#section-3.1) — challenge parameters
//   - See: https://github.com/panyam/oneauth/issues/336

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/stores/fs"
	"github.com/panyam/oneauth/utils"
)

const (
	rsBaseURL     = "https://rs.example.com"
	rsResource    = "/protected"
	rsResourceURL = rsBaseURL + rsResource
	rsSecret      = "resource-server-jwt-secret-32ch!"
	rsIssuer      = "dpop-rs-test-issuer"
)

// rsFixture is one protected resource plus the AS that issues its tokens.
type rsFixture struct {
	issuer  apiauth.TokenIssuer
	handler http.Handler
}

func newRSFixture(t *testing.T, opts ...func(*apiauth.APIMiddleware)) *rsFixture {
	t.Helper()
	issuer := apiauth.NewJWTIssuer(apiauth.JWTIssuerConfig{
		SigningKey: []byte(rsSecret),
		SigningAlg: "HS256",
		Issuer:     rsIssuer,
	})
	mw := &apiauth.APIMiddleware{
		JWTSecretKey: rsSecret,
		JWTIssuer:    rsIssuer,
		DPoP: apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{
			BaseURL: rsBaseURL,
		}),
	}
	for _, opt := range opts {
		opt(mw)
	}
	protected := mw.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"subject": apiauth.GetSubjectFromAPIContext(r.Context()),
		})
	}))
	return &rsFixture{issuer: issuer, handler: protected}
}

// mintToken issues an access token, bound to jkt when non-empty.
func (f *rsFixture) mintToken(t *testing.T, jkt string) string {
	t.Helper()
	req := &apiauth.CreateAccessTokenRequest{Subject: "alice", Scopes: []string{"read"}}
	if jkt != "" {
		req.Confirmation = &core.Confirmation{JKT: jkt}
	}
	resp, err := f.issuer.CreateAccessToken(context.Background(), req)
	require.NoError(t, err)
	return resp.Token
}

// call sends one request to the protected resource. scheme and proof are
// applied verbatim so a test can present a token the wrong way on purpose.
func (f *rsFixture) call(scheme, token, proof string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, rsResourceURL+rsResource, nil)
	req.URL.Path = rsResource
	if token != "" {
		req.Header.Set("Authorization", scheme+" "+token)
	}
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	rr := httptest.NewRecorder()
	f.handler.ServeHTTP(rr, req)
	return rr
}

// resourceProof mints a proof for a GET of the protected resource, carrying
// the `ath` for token unless the caller overrides it.
func resourceProof(t *testing.T, sign func(proofOpts) string, token string, override ...proofOpts) string {
	t.Helper()
	o := proofOpts{method: http.MethodGet, url: rsResourceURL, ath: athFor(token)}
	if len(override) == 1 {
		if override[0].method != "" {
			o.method = override[0].method
		}
		if override[0].url != "" {
			o.url = override[0].url
		}
		if override[0].ath != "" {
			o.ath = override[0].ath
		}
		o.jti = override[0].jti
		o.iat = override[0].iat
	}
	return sign(o)
}

func TestDPoPResource_AcceptsBoundTokenWithMatchingProof(t *testing.T) {
	fx := newRSFixture(t)
	key, sign := newProofSigner(t)
	expected, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)
	token := fx.mintToken(t, expected)

	rr := fx.call("DPoP", token, resourceProof(t, sign, token))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "alice")
}

// The downgrade RFC 9449 §7.2 exists to close: a thief who holds a bound
// token drops the DPoP header, says Bearer, and the binding buys nothing
// unless the resource server refuses this.
func TestDPoPResource_RejectsBoundTokenPresentedAsBearer(t *testing.T) {
	fx := newRSFixture(t)
	key, _ := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)
	token := fx.mintToken(t, jkt)

	rr := fx.call("Bearer", token, "")

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
}

// A proof from a key the token was not issued to is the stolen-token case:
// the attacker can mint syntactically perfect proofs with their own key.
func TestDPoPResource_RejectsProofFromAnotherKey(t *testing.T) {
	fx := newRSFixture(t)
	key, _ := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)
	token := fx.mintToken(t, jkt)
	_, attacker := newProofSigner(t)

	rr := fx.call("DPoP", token, resourceProof(t, attacker, token))

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), "Invalid DPoP key binding")
}

func TestDPoPResource_RejectsMissingProof(t *testing.T) {
	fx := newRSFixture(t)
	key, _ := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)

	rr := fx.call("DPoP", fx.mintToken(t, jkt), "")

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`)
}

// Without `ath`, a proof captured from one request could be replayed with a
// different token the same client holds.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.2
func TestDPoPResource_RejectsMismatchedAccessTokenHash(t *testing.T) {
	fx := newRSFixture(t)
	key, sign := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)
	token := fx.mintToken(t, jkt)
	other := fx.mintToken(t, jkt)

	rr := fx.call("DPoP", token, resourceProof(t, sign, token, proofOpts{ath: athFor(other)}))

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`)
}

// A proof names one request. Reusing it for a second request is the replay
// the `jti` check exists to stop.
func TestDPoPResource_RejectsReplayedProof(t *testing.T) {
	fx := newRSFixture(t)
	key, sign := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)
	token := fx.mintToken(t, jkt)
	proof := resourceProof(t, sign, token)

	require.Equal(t, http.StatusOK, fx.call("DPoP", token, proof).Code)
	rr := fx.call("DPoP", token, proof)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`)
}

// A proof whose htu names a different resource must not work here, or a
// proof captured by a low-value endpoint would open a high-value one.
func TestDPoPResource_RejectsProofForAnotherResource(t *testing.T) {
	fx := newRSFixture(t)
	key, sign := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)
	token := fx.mintToken(t, jkt)

	rr := fx.call("DPoP", token, resourceProof(t, sign, token, proofOpts{url: rsBaseURL + "/other"}))

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`)
}

// RFC 9449 does not say what to do with an unbound token presented under the
// DPoP scheme. OneAuth refuses it: the client asked to be judged on a key
// binding the token does not carry, so accepting would leave it believing in
// protection that does not exist.
func TestDPoPResource_RejectsUnboundTokenUnderDPoPScheme(t *testing.T) {
	fx := newRSFixture(t)
	_, sign := newProofSigner(t)
	token := fx.mintToken(t, "")

	rr := fx.call("DPoP", token, resourceProof(t, sign, token))

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
}

// Bearer clients keep working on a DPoP-enabled resource server, which is
// what allows a fleet to migrate one client at a time.
func TestDPoPResource_UnboundTokenStillWorksAsBearer(t *testing.T) {
	fx := newRSFixture(t)

	rr := fx.call("Bearer", fx.mintToken(t, ""), "")

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

func TestDPoPResource_RequireDPoPRefusesBearer(t *testing.T) {
	fx := newRSFixture(t, func(m *apiauth.APIMiddleware) { m.RequireDPoP = true })

	rr := fx.call("Bearer", fx.mintToken(t, ""), "")

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), "requires a DPoP-bound access token")
}

// An API key has no `cnf` for a proof to be checked against, so presenting
// one under the DPoP scheme is a client error rather than a stronger
// credential.
func TestDPoPResource_RejectsAPIKeyUnderDPoPScheme(t *testing.T) {
	fx := newRSFixture(t, func(m *apiauth.APIMiddleware) {
		m.APIKeyStore = fs.NewFSAPIKeyStore(t.TempDir())
	})
	_, sign := newProofSigner(t)

	rr := fx.call("DPoP", "oa_whatever", resourceProof(t, sign, "oa_whatever"))

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "API keys cannot be presented under the DPoP scheme")
}

// Challenge shapes per RFC 9449 §7.2: a request that attempted nothing gets
// both schemes and no error code, while a request whose scheme was
// unambiguous gets the error on that scheme.
func TestDPoPResource_ChallengeAdvertisesBothSchemes(t *testing.T) {
	fx := newRSFixture(t)

	rr := fx.call("", "", "")

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	challenge := rr.Header().Get("WWW-Authenticate")
	assert.Contains(t, challenge, "Bearer")
	assert.Contains(t, challenge, `DPoP algs="`)
	assert.NotContains(t, challenge, "error=", "a request that presented no credentials must not be told what went wrong")
}

// A bearer-only deployment keeps its exact challenge, so wiring DPoP stays
// the thing that changes behavior.
func TestDPoPResource_BearerOnlyChallengeUnchanged(t *testing.T) {
	fx := newRSFixture(t, func(m *apiauth.APIMiddleware) { m.DPoP = nil })

	rr := fx.call("", "", "")

	assert.Equal(t, `Bearer realm="api"`, rr.Header().Get("WWW-Authenticate"))
}

// A DPoP-unaware resource server accepts a bound token as a bearer token,
// which RFC 9449 §7.2 both predicts and permits. Asserted so the security
// consequence is visible: issuing bound tokens is not protection until every
// resource server enforces them.
func TestDPoPResource_ValidatorNotWiredAcceptsBoundTokenAsBearer(t *testing.T) {
	fx := newRSFixture(t, func(m *apiauth.APIMiddleware) { m.DPoP = nil })

	rr := fx.call("Bearer", fx.mintToken(t, "some-thumbprint"), "")

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

// The access token and its `ath` published in RFC 9449 Figures 13 and 14.
// Checking our hash against the RFC's own pair catches a change to the
// computation that our round-trip tests would happily agree with.
func TestDPoPResource_RFC9449AccessTokenHashVector(t *testing.T) {
	const (
		rfcAccessToken = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"
		rfcATH         = "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
	)

	assert.Equal(t, rfcATH, athFor(rfcAccessToken))
}

// The §7.1 example proof carries that same `ath`, so validating it against
// the published access token checks the resource-side path end to end
// against the RFC's own bytes.
func TestDPoPResource_RFC9449ResourceProofVector(t *testing.T) {
	const rfcProof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA"

	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{
		Now: func() time.Time { return time.Unix(1562262618, 0) },
	})
	resp, err := v.Validate(context.Background(), &apiauth.DPoPProofRequest{
		Proof:       rfcProof,
		Method:      http.MethodGet,
		URL:         "https://resource.example.org/protectedresource",
		AccessToken: "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
	})

	require.NoError(t, err)
	assert.Equal(t, rfc9449ExampleJKT, resp.JKT)
}

// Introspection carries `cnf` (RFC 9449 §6) so a resource server that does
// not validate the JWT itself can still enforce the binding.
func TestDPoPResource_IntrospectionReportsConfirmation(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	issuer := apiauth.NewJWTIssuer(apiauth.JWTIssuerConfig{
		SigningKey: []byte(rsSecret), SigningAlg: "HS256", Issuer: rsIssuer,
	})
	validator := apiauth.NewJWTValidator(apiauth.JWTValidatorConfig{
		KeyLookup: ks, SigningKey: []byte(rsSecret), SigningAlg: "HS256", Issuer: rsIssuer,
	})
	introspector := apiauth.NewTokenIntrospector(validator)

	tok, err := issuer.CreateAccessToken(context.Background(), &apiauth.CreateAccessTokenRequest{
		Subject:      "alice",
		Confirmation: &core.Confirmation{JKT: rfc9449ExampleJKT},
	})
	require.NoError(t, err)

	resp, err := introspector.Introspect(context.Background(), &apiauth.IntrospectRequest{Token: tok.Token})

	require.NoError(t, err)
	require.True(t, resp.Result.Active)
	require.NotNil(t, resp.Result.Cnf)
	assert.Equal(t, rfc9449ExampleJKT, resp.Result.Cnf.JKT)
}

// RFC 9110 §11.6.1 separates auth-params with commas, and RFC 9449 Figure 16
// shows the shape a DPoP challenge takes. A space-separated list parses as
// one malformed parameter, which a conforming client discards along with the
// error it was supposed to act on.
func TestDPoPResource_ChallengeParamsAreCommaSeparated(t *testing.T) {
	fx := newRSFixture(t)
	key, _ := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)

	rr := fx.call("Bearer", fx.mintToken(t, jkt), "")

	challenge := rr.Header().Get("WWW-Authenticate")
	assert.Contains(t, challenge, `error="invalid_token", error_description=`)
	assert.Regexp(t, `error_description="[^"]*", algs="`, challenge)
}
