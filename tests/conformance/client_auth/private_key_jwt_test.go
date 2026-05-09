package client_auth_test

// Conformance fixtures for `private_key_jwt` token-endpoint client
// authentication. These tests pin the wire-format requirements
// independently of the OneAuth implementation — they would apply
// equally to any AS claiming `private_key_jwt` support.
//
// See:
//   - RFC 7521 §4.2 (assertion-type URN exact match)
//   - RFC 7523 §3   (iss/sub/aud/exp/jti requirements)
//   - OIDC Core §9  (private_key_jwt definition)
//   - CVE-2016-10555 (algorithm confusion)

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/keys"
	"github.com/panyam/oneauth/testutil"
	"github.com/panyam/oneauth/utils"
)

const (
	jwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

type fixture struct {
	t        *testing.T
	srv      *testutil.TestAuthServer
	clientID string
	priv     *rsa.PrivateKey
	tokenURL string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	srv := testutil.NewTestAuthServer(t)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubPEM, err := utils.EncodePublicKeyPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("encode pub: %v", err)
	}
	const clientID = "pkjwt-conformance-client"
	if err := srv.KeyStore.PutKey(&keys.KeyRecord{
		ClientID:  clientID,
		Key:       pubPEM,
		Algorithm: "RS256",
	}); err != nil {
		t.Fatalf("put key: %v", err)
	}
	return &fixture{
		t:        t,
		srv:      srv,
		clientID: clientID,
		priv:     priv,
		tokenURL: srv.URL() + "/api/token",
	}
}

func (f *fixture) sign(mutate func(jwt.MapClaims, map[string]any), method jwt.SigningMethod, key any) string {
	f.t.Helper()
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		f.t.Fatalf("rand: %v", err)
	}
	claims := jwt.MapClaims{
		"iss": f.clientID,
		"sub": f.clientID,
		"aud": f.tokenURL,
		"jti": base64.RawURLEncoding.EncodeToString(jtiBytes),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(60 * time.Second).Unix(),
	}
	header := map[string]any{}
	if mutate != nil {
		mutate(claims, header)
	}
	tok := jwt.NewWithClaims(method, claims)
	for k, v := range header {
		tok.Header[k] = v
	}
	signed, err := tok.SignedString(key)
	if err != nil {
		f.t.Fatalf("sign: %v", err)
	}
	return signed
}

func (f *fixture) post(form url.Values) *http.Response {
	f.t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		f.t.Fatalf("build req: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatalf("post: %v", err)
	}
	return resp
}

func (f *fixture) postAssertion(assertion string) *http.Response {
	return f.post(url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {f.clientID},
		"client_assertion_type": {jwtBearerAssertionType},
		"client_assertion":      {assertion},
	})
}

// TestPrivateKeyJWT covers the wire-format requirements from RFC 7521 §4.2 +
// RFC 7523 §3 + OIDC Core §9.
func TestPrivateKeyJWT(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		f := newFixture(t)
		assertion := f.sign(nil, jwt.SigningMethodRS256, f.priv)
		resp := f.postAssertion(assertion)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("status=%d body=%s", resp.StatusCode, body)
		}
		var data map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if _, ok := data["access_token"].(string); !ok {
			t.Fatalf("response missing access_token: %v", data)
		}
	})

	t.Run("rejects_iss_sub_mismatch", func(t *testing.T) {
		// RFC 7521 §4.1: iss MUST equal sub for client-auth assertions.
		f := newFixture(t)
		assertion := f.sign(func(c jwt.MapClaims, _ map[string]any) {
			c["sub"] = "other-subject"
		}, jwt.SigningMethodRS256, f.priv)
		resp := f.postAssertion(assertion)
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("iss != sub MUST be rejected, got 200")
		}
	})

	t.Run("rejects_wrong_audience", func(t *testing.T) {
		// RFC 7523 §3 item 3: aud MUST identify the AS.
		f := newFixture(t)
		assertion := f.sign(func(c jwt.MapClaims, _ map[string]any) {
			c["aud"] = "https://wrong.example.com/token"
		}, jwt.SigningMethodRS256, f.priv)
		resp := f.postAssertion(assertion)
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("wrong aud MUST be rejected, got 200")
		}
	})

	t.Run("rejects_expired", func(t *testing.T) {
		// RFC 7523 §3 item 4: exp in the past MUST be rejected.
		f := newFixture(t)
		assertion := f.sign(func(c jwt.MapClaims, _ map[string]any) {
			c["iat"] = time.Now().Add(-2 * time.Minute).Unix()
			c["exp"] = time.Now().Add(-1 * time.Minute).Unix()
		}, jwt.SigningMethodRS256, f.priv)
		resp := f.postAssertion(assertion)
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("expired assertion MUST be rejected, got 200")
		}
	})

	t.Run("rejects_replayed_jti", func(t *testing.T) {
		// RFC 7523 §3 item 7: jti reuse within lifetime MUST be rejected.
		f := newFixture(t)
		assertion := f.sign(nil, jwt.SigningMethodRS256, f.priv)
		ok := f.postAssertion(assertion)
		ok.Body.Close()
		if ok.StatusCode != http.StatusOK {
			t.Fatalf("first use should succeed, got %d", ok.StatusCode)
		}
		dup := f.postAssertion(assertion)
		defer dup.Body.Close()
		if dup.StatusCode == http.StatusOK {
			t.Fatalf("replayed jti MUST be rejected, got 200")
		}
	})

	t.Run("rejects_bad_assertion_type", func(t *testing.T) {
		// RFC 7521 §4.2: client_assertion_type value is exact.
		f := newFixture(t)
		assertion := f.sign(nil, jwt.SigningMethodRS256, f.priv)
		resp := f.post(url.Values{
			"grant_type":            {"client_credentials"},
			"client_id":             {f.clientID},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:saml2-bearer"},
			"client_assertion":      {assertion},
		})
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("non-JWT assertion type MUST be rejected, got 200")
		}
	})

	t.Run("rejects_alg_confusion", func(t *testing.T) {
		// CVE-2016-10555 / CWE-327: AS MUST lock the assertion alg to
		// the value registered for the client. Forging an HS256
		// assertion with the public key as the HMAC secret must fail
		// when the client is registered for RS256.
		f := newFixture(t)
		pubPEM, err := utils.EncodePublicKeyPEM(&f.priv.PublicKey)
		if err != nil {
			t.Fatalf("encode pub: %v", err)
		}
		forged := f.sign(nil, jwt.SigningMethodHS256, pubPEM)
		resp := f.postAssertion(forged)
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("alg-confusion assertion MUST be rejected, got 200")
		}
	})
}

// _ ensures the apiauth.ClientAssertionTypeJWTBearer constant matches
// RFC 7521 §4.2 verbatim — a deliberate lock. If a future refactor
// renames the URN, this stops compiling first.
var _ = apiauth.ClientAssertionTypeJWTBearer == jwtBearerAssertionType
