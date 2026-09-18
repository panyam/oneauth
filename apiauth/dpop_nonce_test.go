package apiauth_test

// Tests for the DPoP nonce protocol (RFC 9449 §8 at the authorization
// server, §9 at the resource server): when a server demands a nonce, what it
// hands back, and what it then accepts.
//
// The threat this closes is narrower than the rest of DPoP and worth stating
// plainly. An `iat` window bounds how old a proof may be. It does nothing
// about a client, or whoever has compromised one, minting a stack of proofs
// dated into the future and banking them (§11.2). A proof cannot be built
// before the server issues the nonce it must contain.
//
// References:
//   - RFC 9449 §8 (https://www.rfc-editor.org/rfc/rfc9449#section-8)
//   - RFC 9449 §9 (https://www.rfc-editor.org/rfc/rfc9449#section-9)
//   - RFC 9449 §11.2 (https://www.rfc-editor.org/rfc/rfc9449#section-11.2)
//   - See: https://github.com/panyam/oneauth/issues/375

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/utils"
)

const nonceEndpointURL = "https://as.example.com/api/token"

func alwaysNonce(*http.Request) bool { return true }

// newNonceValidator builds a validator that demands a nonce on every
// request, which is the easiest policy to test even though it is a poor
// production default.
func newNonceValidator(t *testing.T, opts ...func(*apiauth.DPoPConfig)) (*apiauth.DPoPProofValidator, apiauth.NonceSource) {
	t.Helper()
	source := apiauth.NewNonceSource(apiauth.NonceConfig{})
	cfg := apiauth.DPoPConfig{
		EndpointURL: nonceEndpointURL,
		NonceSource: source,
		NoncePolicy: alwaysNonce,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return apiauth.NewDPoPProofValidator(cfg), source
}

func validateWithNonce(t *testing.T, v *apiauth.DPoPProofValidator, proof string) error {
	t.Helper()
	_, err := v.Validate(context.Background(), &apiauth.DPoPProofRequest{
		Proof: proof, Method: testProofMethod, URL: nonceEndpointURL, RequireNonce: true,
	})
	return err
}

// A nonce issued by this server must be accepted by it; that is the whole
// contract, and the HMAC form has to survive its own round trip.
func TestNonceSource_IssuesValuesItAccepts(t *testing.T) {
	source := apiauth.NewNonceSource(apiauth.NonceConfig{})

	nonce, err := source.Issue()

	require.NoError(t, err)
	assert.NotEmpty(t, nonce)
	assert.True(t, source.Valid(nonce))
}

// Two nonces must differ even when issued in the same second, which is the
// normal case under any load worth mentioning. A salt inside the MAC'd
// payload is what buys that; a bare timestamp would hand every client in a
// given second the same string.
func TestNonceSource_IssuesDistinctValues(t *testing.T) {
	source := apiauth.NewNonceSource(apiauth.NonceConfig{})
	seen := map[string]bool{}

	for range 100 {
		n, err := source.Issue()
		require.NoError(t, err)
		require.False(t, seen[n], "nonce %q was issued twice", n)
		seen[n] = true
		assert.True(t, source.Valid(n))
	}
}

// A nonce another server issued, or one a client invented, must be refused.
// Accepting either would make the challenge decorative.
func TestNonceSource_RejectsForeignAndMalformedValues(t *testing.T) {
	ours := apiauth.NewNonceSource(apiauth.NonceConfig{})
	theirs := apiauth.NewNonceSource(apiauth.NonceConfig{})

	foreign, err := theirs.Issue()
	require.NoError(t, err)

	assert.False(t, ours.Valid(foreign), "a nonce from a different server MUST NOT be accepted")
	assert.False(t, ours.Valid(""))
	assert.False(t, ours.Valid("not-base64url!!"))
	assert.False(t, ours.Valid("c2hvcnQ"))
}

func TestNonceSource_RejectsExpiredValues(t *testing.T) {
	now := time.Now()
	source := apiauth.NewNonceSource(apiauth.NonceConfig{
		Lifetime: time.Minute,
		Now:      func() time.Time { return now },
	})
	nonce, err := source.Issue()
	require.NoError(t, err)
	require.True(t, source.Valid(nonce))

	now = now.Add(2 * time.Minute)

	assert.False(t, source.Valid(nonce), "a nonce past its lifetime MUST be refused")
}

// A nonce is not single-use. RFC 9449 expects a client to hold one and reuse
// it across requests until challenged again; replay defense is the jti
// check's job, and consuming nonces would challenge every second request.
func TestNonceSource_NonceIsReusableWithinItsLifetime(t *testing.T) {
	source := apiauth.NewNonceSource(apiauth.NonceConfig{})
	nonce, err := source.Issue()
	require.NoError(t, err)

	for range 3 {
		assert.True(t, source.Valid(nonce))
	}
}

// A proof with no nonce, when one is demanded, is answered with a nonce to
// retry with rather than a flat rejection. The distinction matters: the
// client has done nothing wrong yet.
func TestNonce_MissingNonceReturnsAChallenge(t *testing.T) {
	v, source := newNonceValidator(t)
	_, sign := newProofSigner(t)

	err := validateWithNonce(t, v, sign(proofOpts{url: nonceEndpointURL}))

	var nonceErr *apiauth.NonceRequiredError
	require.ErrorAs(t, err, &nonceErr)
	assert.NotEmpty(t, nonceErr.Nonce, "the challenge MUST carry a nonce the client can retry with")
	assert.True(t, source.Valid(nonceErr.Nonce))
}

func TestNonce_ValidNonceIsAccepted(t *testing.T) {
	v, source := newNonceValidator(t)
	_, sign := newProofSigner(t)
	nonce, err := source.Issue()
	require.NoError(t, err)

	err = validateWithNonce(t, v, sign(proofOpts{url: nonceEndpointURL, nonce: nonce}))

	require.NoError(t, err)
}

// A stale or forged nonce is challenged again with a fresh one, which is
// what makes the mismatch self-correcting (§8).
func TestNonce_UnknownNonceIsChallengedAgain(t *testing.T) {
	v, source := newNonceValidator(t)
	_, sign := newProofSigner(t)

	err := validateWithNonce(t, v, sign(proofOpts{url: nonceEndpointURL, nonce: "someone-elses-nonce"}))

	var nonceErr *apiauth.NonceRequiredError
	require.ErrorAs(t, err, &nonceErr)
	assert.Contains(t, nonceErr.Error(), "unknown or has expired")
	assert.True(t, source.Valid(nonceErr.Nonce), "the replacement nonce MUST be usable")
}

// Wiring a source without a policy must change nothing, which is what keeps
// this additive for every client that has never seen a nonce.
func TestNonce_SourceWithoutPolicyDemandsNothing(t *testing.T) {
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{
		EndpointURL: nonceEndpointURL,
		NonceSource: apiauth.NewNonceSource(apiauth.NonceConfig{}),
	})
	_, sign := newProofSigner(t)

	req := httptest.NewRequest(http.MethodPost, "/api/token", nil)
	req.Header.Set("DPoP", sign(proofOpts{url: nonceEndpointURL}))
	cnf, err := v.Confirm(context.Background(), req)

	require.NoError(t, err)
	assert.NotNil(t, cnf)
}

// The policy decides per request, so a deployment can demand a nonce on a
// high-value endpoint without paying a round trip everywhere.
func TestNonce_PolicyDecidesPerRequest(t *testing.T) {
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{
		BaseURL:     "https://as.example.com",
		NonceSource: apiauth.NewNonceSource(apiauth.NonceConfig{}),
		NoncePolicy: func(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, "/high-value") },
	})
	_, sign := newProofSigner(t)

	ordinary := httptest.NewRequest(http.MethodGet, "/ordinary", nil)
	ordinary.Header.Set("DPoP", sign(proofOpts{method: http.MethodGet, url: "https://as.example.com/ordinary"}))
	_, err := v.Confirm(context.Background(), ordinary)
	require.NoError(t, err)

	guarded := httptest.NewRequest(http.MethodGet, "/high-value/transfer", nil)
	guarded.Header.Set("DPoP", sign(proofOpts{method: http.MethodGet, url: "https://as.example.com/high-value/transfer"}))
	_, err = v.Confirm(context.Background(), guarded)

	var nonceErr *apiauth.NonceRequiredError
	require.ErrorAs(t, err, &nonceErr)
}

// A challenge must not consume the proof's jti, or the client could not
// retry with the same request and would be stuck in a loop.
func TestNonce_ChallengeDoesNotBurnTheJTI(t *testing.T) {
	v, source := newNonceValidator(t)
	_, sign := newProofSigner(t)

	err := validateWithNonce(t, v, sign(proofOpts{url: nonceEndpointURL, jti: "retry-me"}))
	var nonceErr *apiauth.NonceRequiredError
	require.ErrorAs(t, err, &nonceErr)

	nonce, issueErr := source.Issue()
	require.NoError(t, issueErr)
	err = validateWithNonce(t, v, sign(proofOpts{url: nonceEndpointURL, jti: "retry-me", nonce: nonce}))

	require.NoError(t, err, "the retry MUST be able to reuse the jti the challenged proof carried")
}

// --- endpoint behaviour ---

// §8: the token endpoint answers with 400, use_dpop_nonce, and the header.
func TestNonce_TokenEndpointChallenge(t *testing.T) {
	ks := keys.NewInMemoryKeyStore()
	_, err := ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
		ClientID: "nonce-client", Key: []byte("nonce-secret"), Algorithm: "HS256",
	}})
	require.NoError(t, err)
	oa := apiauth.NewOneAuth(apiauth.OneAuthConfig{
		KeyStore:   ks,
		SigningKey: []byte("nonce-test-jwt-secret-32-chars!!!"),
		SigningAlg: "HS256",
		Issuer:     "nonce-test",
		DPoP: apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{
			EndpointURL: nonceEndpointURL,
			NonceSource: apiauth.NewNonceSource(apiauth.NonceConfig{}),
			NoncePolicy: alwaysNonce,
		}),
	})
	handler := apiauth.NewTokenEndpointHandler(oa)
	_, sign := newProofSigner(t)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"nonce-client"},
		"client_secret": {"nonce-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, nonceEndpointURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", sign(proofOpts{url: nonceEndpointURL}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "use_dpop_nonce", errorCode(t, rr))
	assert.NotEmpty(t, rr.Header().Get("DPoP-Nonce"), "§8 requires the nonce to travel in the DPoP-Nonce header")
}

// §9: the resource server answers with 401, the DPoP scheme, and the header.
func TestNonce_ResourceServerChallenge(t *testing.T) {
	source := apiauth.NewNonceSource(apiauth.NonceConfig{})
	fx := newRSFixture(t, func(m *apiauth.APIMiddleware) {
		m.DPoP = apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{
			BaseURL:     rsBaseURL,
			NonceSource: source,
			NoncePolicy: alwaysNonce,
		})
	})
	key, sign := newProofSigner(t)
	jkt, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)
	token := fx.mintToken(t, jkt)

	rr := fx.call("DPoP", token, resourceProof(t, sign, token))

	require.Equal(t, http.StatusUnauthorized, rr.Code)
	challenge := rr.Header().Get("WWW-Authenticate")
	assert.Contains(t, challenge, `error="use_dpop_nonce"`)
	assert.NotEmpty(t, rr.Header().Get("DPoP-Nonce"))

	// And the retry carrying that nonce succeeds.
	nonce := rr.Header().Get("DPoP-Nonce")
	rr = fx.call("DPoP", token, resourceProof(t, sign, token, proofOpts{nonce: nonce}))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

// The payload RFC 9449 Figure 21 publishes for a nonce-carrying proof. Our
// reader has to accept the claim exactly as the RFC writes it.
func TestNonce_RFC9449Figure21ClaimShape(t *testing.T) {
	const rfcNonce = "eyJ7S_zG.eyJH0-Z.HX4w-7v"
	source := &fixedNonceSource{nonce: rfcNonce}
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{
		EndpointURL: "https://server.example.com/token",
		NonceSource: source,
		NoncePolicy: alwaysNonce,
	})
	_, sign := newProofSigner(t)

	_, err := v.Validate(context.Background(), &apiauth.DPoPProofRequest{
		Proof: sign(proofOpts{
			method: http.MethodPost,
			url:    "https://server.example.com/token",
			jti:    "-BwC3ESc6acc2lTc",
			nonce:  rfcNonce,
		}),
		Method:       http.MethodPost,
		URL:          "https://server.example.com/token",
		RequireNonce: true,
	})

	require.NoError(t, err)
}

// fixedNonceSource accepts one value, so a test can assert against the
// RFC's published nonce rather than one we generated.
type fixedNonceSource struct{ nonce string }

func (s *fixedNonceSource) Issue() (string, error)  { return s.nonce, nil }
func (s *fixedNonceSource) Valid(nonce string) bool { return nonce == s.nonce }
