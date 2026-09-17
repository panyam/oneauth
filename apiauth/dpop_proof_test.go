package apiauth_test

// Proof-validation tests for DPoP (RFC 9449 §4.3). Each rejection case is a
// security test: a proof that fails one of these checks and is accepted
// anyway lets an attacker bind a token to a key they do not hold, or replay
// a proof they captured in transit.
//
// References:
//   - RFC 9449 §4.2 (https://www.rfc-editor.org/rfc/rfc9449#section-4.2) — proof syntax
//   - RFC 9449 §4.3 (https://www.rfc-editor.org/rfc/rfc9449#section-4.3) — the checks
//   - RFC 9449 §11.1 (https://www.rfc-editor.org/rfc/rfc9449#section-11.1) — replay
//   - See: https://github.com/panyam/oneauth/issues/336

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/utils"
)

const (
	testProofMethod = "POST"
	testProofURL    = "https://as.example.com/api/token"
)

// rfc9449ExampleProof is the proof JWT from RFC 9449 Figure 2, line
// continuations removed. Its key is the one whose thumbprint the RFC
// publishes in Figure 9, which makes the pair a wire-format test vector: a
// change to our parsing or thumbprint computation that still round-trips
// through our own signer would break here.
const rfc9449ExampleProof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"

// rfc9449ExampleJKT is the thumbprint RFC 9449 Figure 9 publishes for the
// Figure 2 proof's key.
const rfc9449ExampleJKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

// proofOpts overrides pieces of a generated proof so a test can make exactly
// one thing wrong. The zero value produces a proof that validates.
type proofOpts struct {
	typ        string
	method     string
	url        string
	jti        string
	iat        time.Time
	ath        string
	omitJTI    bool
	omitJWK    bool
	privateJWK bool
	signMethod jwt.SigningMethod
}

// newProofSigner returns an ES256 key plus a proof factory bound to it, so
// every proof in a test shares one client key the way a real client would.
func newProofSigner(t *testing.T) (*ecdsa.PrivateKey, func(proofOpts) string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key, func(o proofOpts) string {
		return newProof(t, key, o)
	}
}

func newProof(t *testing.T, key any, o proofOpts) string {
	t.Helper()

	method := o.signMethod
	if method == nil {
		method = jwt.SigningMethodES256
		if _, ok := key.(*rsa.PrivateKey); ok {
			method = jwt.SigningMethodRS256
		}
	}

	claims := jwt.MapClaims{
		"htm": firstNonEmpty(o.method, testProofMethod),
		"htu": firstNonEmpty(o.url, testProofURL),
	}
	if !o.omitJTI {
		claims["jti"] = firstNonEmpty(o.jti, "jti-"+time.Now().Format(time.RFC3339Nano))
	}
	iat := o.iat
	if iat.IsZero() {
		iat = time.Now()
	}
	claims["iat"] = iat.Unix()
	if o.ath != "" {
		claims["ath"] = o.ath
	}

	token := jwt.NewWithClaims(method, claims)
	token.Header["typ"] = firstNonEmpty(o.typ, "dpop+jwt")
	if !o.omitJWK {
		token.Header["jwk"] = publicJWKMap(t, key, o.privateJWK)
	}

	var signingKey any = key
	if method == jwt.SigningMethodNone {
		signingKey = jwt.UnsafeAllowNoneSignatureType
	}
	signed, err := token.SignedString(signingKey)
	require.NoError(t, err)
	return signed
}

// publicJWKMap renders the signing key's public half as the `jwk` header
// object. withPrivate adds a `d` member, modelling a client that leaks its
// private key (or an attacker trying to have the server verify with material
// it supplied).
func publicJWKMap(t *testing.T, key any, withPrivate bool) map[string]any {
	t.Helper()
	var jwk utils.JWK
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		jwk = utils.ECDSAPublicKeyToJWK("", "ES256", &k.PublicKey)
	case *rsa.PrivateKey:
		jwk = utils.RSAPublicKeyToJWK("", "RS256", &k.PublicKey)
	default:
		t.Fatalf("unsupported test key type %T", key)
	}
	encoded, err := json.Marshal(jwk)
	require.NoError(t, err)
	var members map[string]any
	require.NoError(t, json.Unmarshal(encoded, &members))
	if withPrivate {
		members["d"] = "cHJldGVuZC1wcml2YXRlLWtleQ"
	}
	return members
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func validateProof(t *testing.T, v *apiauth.DPoPProofValidator, proof string) (*apiauth.DPoPProofResponse, error) {
	t.Helper()
	return v.Validate(context.Background(), &apiauth.DPoPProofRequest{
		Proof:  proof,
		Method: testProofMethod,
		URL:    testProofURL,
	})
}

// assertInvalidProof checks that err is the RFC 9449 §5 error a client is
// owed. A 400 with a different code (or a 500) tells a client to give up
// rather than retry with a corrected proof.
func assertInvalidProof(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var ge *apiauth.GrantError
	require.ErrorAs(t, err, &ge)
	assert.Equal(t, "invalid_dpop_proof", ge.Code)
	assert.Equal(t, http.StatusBadRequest, ge.Status)
}

func TestDPoPProof_RFC9449ExampleVector(t *testing.T) {
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{
		Now: func() time.Time { return time.Unix(1562262616, 0) },
	})

	resp, err := v.Validate(context.Background(), &apiauth.DPoPProofRequest{
		Proof:  rfc9449ExampleProof,
		Method: "POST",
		URL:    "https://server.example.com/token",
	})

	require.NoError(t, err)
	assert.Equal(t, rfc9449ExampleJKT, resp.JKT)
}

func TestDPoPProof_AcceptsES256AndRS256(t *testing.T) {
	ecKey, ecProof := newProofSigner(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})

	ecResp, err := validateProof(t, v, ecProof(proofOpts{}))
	require.NoError(t, err)
	rsaResp, err := validateProof(t, v, newProof(t, rsaKey, proofOpts{}))
	require.NoError(t, err)

	expectedEC, err := utils.ComputeKid(&ecKey.PublicKey, "ES256")
	require.NoError(t, err)
	expectedRSA, err := utils.ComputeKid(&rsaKey.PublicKey, "RS256")
	require.NoError(t, err)
	assert.Equal(t, expectedEC, ecResp.JKT)
	assert.Equal(t, expectedRSA, rsaResp.JKT)
	assert.NotEqual(t, ecResp.JKT, rsaResp.JKT)
}

// A proof the AS accepts under any `typ` lets any JWT the client already
// holds — an access token, a client assertion — be replayed as a proof.
func TestDPoPProof_RejectsWrongTyp(t *testing.T) {
	_, proof := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})

	_, err := validateProof(t, v, proof(proofOpts{typ: "JWT"}))

	assertInvalidProof(t, err)
}

// An HMAC proof proves nothing: its key is shared, so anyone who can verify
// it can also mint it.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.2
func TestDPoPProof_RejectsSymmetricAlg(t *testing.T) {
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})
	secret := []byte("shared-secret-not-a-possession-proof")

	claims := jwt.MapClaims{"jti": "hs256", "htm": testProofMethod, "htu": testProofURL, "iat": time.Now().Unix()}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["typ"] = "dpop+jwt"
	signed, err := token.SignedString(secret)
	require.NoError(t, err)

	_, err = validateProof(t, v, signed)

	assertInvalidProof(t, err)
}

// See: https://www.rfc-editor.org/rfc/rfc8725#section-3.1 (alg=none)
func TestDPoPProof_RejectsAlgNone(t *testing.T) {
	_, proof := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})

	_, err := validateProof(t, v, proof(proofOpts{signMethod: jwt.SigningMethodNone}))

	assertInvalidProof(t, err)
}

func TestDPoPProof_RejectsMissingJWKHeader(t *testing.T) {
	_, proof := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})

	_, err := validateProof(t, v, proof(proofOpts{omitJWK: true}))

	assertInvalidProof(t, err)
}

// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.3 (item 5)
func TestDPoPProof_RejectsPrivateKeyInJWKHeader(t *testing.T) {
	_, proof := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})

	_, err := validateProof(t, v, proof(proofOpts{privateJWK: true}))

	assertInvalidProof(t, err)
}

// The signature is the whole proof: a body swapped under a valid-looking
// header is exactly the attack DPoP exists to stop.
func TestDPoPProof_RejectsTamperedSignature(t *testing.T) {
	_, proof := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})

	valid := proof(proofOpts{})
	parts := strings.Split(valid, ".")
	require.Len(t, parts, 3)

	_, err := validateProof(t, v, parts[0]+"."+parts[1]+"."+flipSignatureByte(t, parts[2]))

	assertInvalidProof(t, err)
}

// Two proofs signed by different keys must not validate against one another;
// this is the check that stops an attacker from replaying a captured proof
// body under their own key.
func TestDPoPProof_RejectsMismatchedKeyAndSignature(t *testing.T) {
	_, proofA := newProofSigner(t)
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})

	signedByA := proofA(proofOpts{})
	parts := strings.Split(signedByA, ".")
	require.Len(t, parts, 3)
	// Re-header the proof with B's public key while keeping A's signature.
	spoofed := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"jti": "spoofed", "htm": testProofMethod, "htu": testProofURL, "iat": time.Now().Unix(),
	})
	spoofed.Header["typ"] = "dpop+jwt"
	spoofed.Header["jwk"] = publicJWKMap(t, keyB, false)
	header, err := spoofed.SigningString()
	require.NoError(t, err)

	_, err = validateProof(t, v, header+"."+parts[2])

	assertInvalidProof(t, err)
}

func TestDPoPProof_RejectsMissingJTI(t *testing.T) {
	_, proof := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})

	_, err := validateProof(t, v, proof(proofOpts{omitJTI: true}))

	assertInvalidProof(t, err)
}

// Replay is the reason `jti` exists: a proof captured by anything that sees
// the request must not be usable a second time.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-11.1
func TestDPoPProof_RejectsReplayedJTI(t *testing.T) {
	_, proof := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})
	replayed := proof(proofOpts{jti: "one-shot"})

	_, err := validateProof(t, v, replayed)
	require.NoError(t, err)
	_, err = validateProof(t, v, replayed)

	assertInvalidProof(t, err)
}

// A rejected proof must not consume its jti, or an attacker who can guess or
// observe the jtis an honest client will use could lock that client out by
// pre-sending garbage proofs carrying them.
func TestDPoPProof_FailedProofDoesNotConsumeJTI(t *testing.T) {
	_, proof := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})

	_, err := validateProof(t, v, proof(proofOpts{jti: "not-burned", method: "GET"}))
	assertInvalidProof(t, err)

	_, err = validateProof(t, v, proof(proofOpts{jti: "not-burned"}))

	require.NoError(t, err)
}

// A proof is scoped to one request. Accepting a mismatched htm/htu would let
// a proof captured from a low-value request be replayed against the token
// endpoint.
func TestDPoPProof_RejectsMethodAndURIMismatch(t *testing.T) {
	_, proof := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})

	_, err := validateProof(t, v, proof(proofOpts{method: "GET"}))
	assertInvalidProof(t, err)

	_, err = validateProof(t, v, proof(proofOpts{url: "https://as.example.com/api/introspect"}))
	assertInvalidProof(t, err)

	_, err = validateProof(t, v, proof(proofOpts{url: "https://attacker.example.net/api/token"}))
	assertInvalidProof(t, err)
}

// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.3 (item 9)
func TestDPoPProof_IgnoresQueryAndFragmentInHTU(t *testing.T) {
	_, proof := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})

	_, err := validateProof(t, v, proof(proofOpts{url: testProofURL + "?trace=1#section"}))

	require.NoError(t, err)
}

func TestDPoPProof_RejectsStaleAndFutureIAT(t *testing.T) {
	_, proof := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{MaxAge: 30 * time.Second})

	_, err := validateProof(t, v, proof(proofOpts{iat: time.Now().Add(-5 * time.Minute)}))
	assertInvalidProof(t, err)

	_, err = validateProof(t, v, proof(proofOpts{iat: time.Now().Add(5 * time.Minute)}))
	assertInvalidProof(t, err)

	_, err = validateProof(t, v, proof(proofOpts{iat: time.Now().Add(-10 * time.Second)}))
	require.NoError(t, err)
}

// `ath` ties a proof to the access token presented with it, so a proof
// captured alongside one token cannot be reused with another token held by
// the same client.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.2
func TestDPoPProof_ChecksAccessTokenHash(t *testing.T) {
	_, proof := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})
	const accessToken = "an-access-token-value"

	withToken := func(p string) error {
		_, err := v.Validate(context.Background(), &apiauth.DPoPProofRequest{
			Proof: p, Method: testProofMethod, URL: testProofURL, AccessToken: accessToken,
		})
		return err
	}

	require.NoError(t, withToken(proof(proofOpts{ath: athFor(accessToken)})))
	assertInvalidProof(t, withToken(proof(proofOpts{ath: athFor("a-different-token")})))
	assertInvalidProof(t, withToken(proof(proofOpts{})))
}

func TestDPoPProof_ConfirmReadsHTTPRequest(t *testing.T) {
	key, proof := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{EndpointURL: testProofURL})
	expected, err := utils.ComputeKid(&key.PublicKey, "ES256")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/token", nil)
	req.Header.Set("DPoP", proof(proofOpts{}))
	cnf, err := v.Confirm(context.Background(), req)

	require.NoError(t, err)
	require.NotNil(t, cnf)
	assert.Equal(t, expected, cnf.JKT)
}

// No proof is not an error: DPoP is opt-in per request, and a client that
// sends none gets an ordinary bearer token.
func TestDPoPProof_ConfirmWithoutHeaderIsUnbound(t *testing.T) {
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{EndpointURL: testProofURL})

	cnf, err := v.Confirm(context.Background(), httptest.NewRequest(http.MethodPost, "/api/token", nil))

	require.NoError(t, err)
	assert.Nil(t, cnf)
}

// Picking one of two DPoP headers would let an attacker who can add a header
// to an honest client's request choose which key the issued token binds to.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-4.3 (item 2)
func TestDPoPProof_ConfirmRejectsMultipleHeaders(t *testing.T) {
	_, proofA := newProofSigner(t)
	_, proofB := newProofSigner(t)
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{EndpointURL: testProofURL})

	req := httptest.NewRequest(http.MethodPost, "/api/token", nil)
	req.Header.Add("DPoP", proofA(proofOpts{}))
	req.Header.Add("DPoP", proofB(proofOpts{}))
	cnf, err := v.Confirm(context.Background(), req)

	assertInvalidProof(t, err)
	assert.Nil(t, cnf)
}

func TestDPoPProof_SigningAlgValuesSupportedDefaultsToAsymmetric(t *testing.T) {
	v := apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{})

	algs := v.SigningAlgValuesSupported()

	assert.ElementsMatch(t, []string{"ES256", "RS256", "PS256"}, algs)
	for _, alg := range algs {
		assert.NotContains(t, alg, "HS", "symmetric algorithms must never be advertised for DPoP proofs")
	}
}

// athFor computes the RFC 9449 §4.2 `ath` value independently of the
// implementation under test, so a change to the hashing would fail here
// rather than agree with itself.
func athFor(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// flipSignatureByte flips a bit in the first signature byte and re-encodes.
// Editing the base64 text directly is not enough: Go's decoder ignores
// trailing bits, so changing the last character often decodes to the same
// bytes and the signature still verifies.
func flipSignatureByte(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	raw[0] ^= 0xFF
	return base64.RawURLEncoding.EncodeToString(raw)
}
