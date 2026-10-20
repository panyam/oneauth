package apiauth_test

// OpenID Connect Core ID tokens from the authorization-code grant: when
// one is issued, what it says, how it is bound to the access token and to
// the authorization request, and that it is never mistaken for an access
// token.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
// See: https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
// See: https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
// See: https://github.com/panyam/oneauth/issues/339

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

const oidcIssuer = "https://as.example.com"

type oidcFixture struct {
	*apiAuthFixture
	codes core.AuthorizationCodeStore
	key   *ecdsa.PrivateKey
}

// newOIDCFixture builds an ES256 AS with OIDC on. userClaims may be nil.
func newOIDCFixture(t *testing.T, userClaims apiauth.UserClaimsFunc) *oidcFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	codes := core.NewInMemoryAuthorizationCodeStore()
	fx := newAPIAuthFixture(apiauth.OneAuthConfig{
		SigningKey:             key,
		SigningAlg:             "ES256",
		VerifyKey:              &key.PublicKey,
		Issuer:                 oidcIssuer,
		Blacklist:              core.NewInMemoryBlacklist(),
		RefreshStore:           newInMemoryRefreshStore(),
		AuthorizationCodeStore: codes,
		OIDC:                   &apiauth.OIDCConfig{UserClaims: userClaims},
	}, nil)
	return &oidcFixture{apiAuthFixture: fx, codes: codes, key: key}
}

// seedOIDCCode stores code-1 for the shared test client, with the given
// scopes, nonce and auth_time.
func seedOIDCCode(t *testing.T, codes core.AuthorizationCodeStore, scopes []string, nonce string, authTime time.Time) {
	t.Helper()
	_, err := codes.CreateAuthorizationCode(context.Background(), &core.CreateAuthorizationCodeRequest{
		Code: &core.AuthorizationCode{
			Code:                "code-1",
			ClientID:            authcodeTestClientID,
			RedirectURI:         authcodeTestRedirect,
			Scopes:              scopes,
			Subject:             authcodeTestSubject,
			CodeChallenge:       core.ComputeCodeChallenge(authcodeTestVerifier),
			CodeChallengeMethod: core.CodeChallengeMethodS256,
			Nonce:               nonce,
			AuthTime:            authTime,
			IssuedAt:            time.Now(),
			ExpiresAt:           time.Now().Add(time.Minute),
		},
	})
	require.NoError(t, err)
}

// redeemOIDC redeems code-1 and returns the decoded token response.
func redeemOIDC(t *testing.T, fx *oidcFixture) map[string]any {
	t.Helper()
	rr := httptest.NewRecorder()
	fx.ServeHTTP(rr, tokenRedeemForm(t, nil))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	return decodeJSON(t, rr)
}

// verifyIDToken checks the ID token's signature against the AS public key
// and returns its claims, as a relying party would (OIDC Core §3.1.3.7).
func verifyIDToken(t *testing.T, fx *oidcFixture, raw string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return &fx.key.PublicKey, nil },
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer(oidcIssuer), jwt.WithAudience(authcodeTestClientID), jwt.WithExpirationRequired())
	require.NoError(t, err)
	return claims
}

func TestOIDC_OpenIDScopeGetsAnIDToken(t *testing.T) {
	fx := newOIDCFixture(t, nil)
	authTime := time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	seedOIDCCode(t, fx.codes, []string{"openid", "read"}, "n-0S6_WzA2Mj", authTime)

	body := redeemOIDC(t, fx)
	raw, _ := body["id_token"].(string)
	require.NotEmpty(t, raw, "an openid grant returns id_token (OIDC Core §3.1.3.3)")

	claims := verifyIDToken(t, fx, raw)
	assert.Equal(t, authcodeTestSubject, claims["sub"])
	assert.Equal(t, "n-0S6_WzA2Mj", claims["nonce"], "nonce from the authorization request is echoed (§3.1.3.6)")
	assert.Equal(t, float64(authTime.Unix()), claims["auth_time"])
	assert.NotNil(t, claims["iat"])
}

// at_hash is the left half of SHA-256 over the access token, so a client
// can tell that the access token came in the same response as the ID token.
func TestOIDC_AtHashBindsTheAccessToken(t *testing.T) {
	fx := newOIDCFixture(t, nil)
	seedOIDCCode(t, fx.codes, []string{"openid"}, "", time.Time{})

	body := redeemOIDC(t, fx)
	claims := verifyIDToken(t, fx, body["id_token"].(string))

	sum := sha256.Sum256([]byte(body["access_token"].(string)))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:16]), claims["at_hash"])
	_, hasNonce := claims["nonce"]
	assert.False(t, hasNonce, "no nonce was sent, so none is echoed")
	_, hasAuthTime := claims["auth_time"]
	assert.False(t, hasAuthTime, "auth_time is left out when the AS does not know it")
}

func TestOIDC_NoOpenIDScopeNoIDToken(t *testing.T) {
	fx := newOIDCFixture(t, nil)
	seedOIDCCode(t, fx.codes, []string{"read"}, "n-1", time.Time{})

	body := redeemOIDC(t, fx)
	assert.Nil(t, body["id_token"], "a plain OAuth grant gets no ID token")
}

// An ID token is signed with the AS key, so without a marker it would pass
// as an access token at any resource server that trusts the AS.
//
// See: https://www.rfc-editor.org/rfc/rfc8725#section-3.11
func TestOIDC_IDTokenIsRefusedAsAnAccessToken(t *testing.T) {
	fx := newOIDCFixture(t, nil)
	seedOIDCCode(t, fx.codes, []string{"openid", "read"}, "", time.Time{})
	body := redeemOIDC(t, fx)
	idToken := body["id_token"].(string)

	_, err := fx.OneAuth.Validator.ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: idToken})
	assert.Error(t, err)

	protected := fx.OneAuth.HTTPMiddleware().ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+idToken)
	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// UserClaims supplies claims, but cannot rewrite the ones that identify
// the token: a claims function returning `sub` or `aud` from a user
// profile must not redirect the ID token to someone else.
func TestOIDC_UserClaimsCannotOverrideRegisteredClaims(t *testing.T) {
	fx := newOIDCFixture(t, func(_ context.Context, subject string, scopes []string) (map[string]any, error) {
		return map[string]any{"email": subject + "@example.com", "sub": "mallory", "aud": "other-client", "nonce": "forged", "azp": "other-client", "jti": "forged"}, nil
	})
	seedOIDCCode(t, fx.codes, []string{"openid", "email"}, "n-2", time.Time{})

	claims := verifyIDToken(t, fx, redeemOIDC(t, fx)["id_token"].(string))
	assert.Equal(t, authcodeTestSubject+"@example.com", claims["email"])
	assert.Equal(t, authcodeTestSubject, claims["sub"])
	assert.Equal(t, "n-2", claims["nonce"])
	// azp names the party the ID token was issued to (OIDC Core §2); a
	// forged one would point a relying party at another client.
	assert.Nil(t, claims["azp"])
	assert.Nil(t, claims["jti"])
}

// OIDC Core §10.1 signs an HMAC ID token with the client's own secret. A
// secret the AS shares with its resource servers would let any of them
// forge ID tokens, so OIDC refuses to start with one.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#Signing
func TestOIDC_RefusesAnHMACSigningKey(t *testing.T) {
	assert.PanicsWithValue(t,
		"apiauth: NewOneAuth: OIDC: oidc: ID tokens need an asymmetric signing key (OIDC Core §10.1 reserves HMAC for client secrets)",
		func() {
			apiauth.NewOneAuth(apiauth.OneAuthConfig{
				SigningKey: []byte("oidc-hmac-secret-32-characters!!"),
				SigningAlg: "HS256",
				Issuer:     oidcIssuer,
				OIDC:       &apiauth.OIDCConfig{},
			})
		})
}

// The nonce travels from /authorize through the stored code to the ID
// token, for a request in the URL and for one pushed through PAR.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
func TestOIDC_NonceTravelsFromAuthorize(t *testing.T) {
	for _, pushed := range []bool{false, true} {
		name := "redirect"
		if pushed {
			name = "par"
		}
		t.Run(name, func(t *testing.T) {
			fx := newOIDCFixture(t, nil)
			authTime := time.Now().Add(-time.Minute).Truncate(time.Second)
			mux := http.NewServeMux()
			pushedStore := core.NewInMemoryPushedAuthorizationRequestStore()
			apiauth.MountAuthorize(mux, apiauth.AuthorizeMountConfig{
				OneAuth:              fx.OneAuth,
				IssuerURL:            oidcIssuer,
				AllowAnyRedirectURI:  true,
				SubjectFromRequest:   func(*http.Request) string { return authcodeTestSubject },
				AuthTimeFromRequest:  func(*http.Request) time.Time { return authTime },
				CSRFTokenFromRequest: func(*http.Request) string { return "" },
				AutoApproveSubject:   authcodeTestSubject,
				PushedStore:          pushedStore,
			})

			params := url.Values{
				"client_id":             {authcodeTestClientID},
				"redirect_uri":          {authcodeTestRedirect},
				"response_type":         {"code"},
				"scope":                 {"openid"},
				"code_challenge":        {core.ComputeCodeChallenge(authcodeTestVerifier)},
				"code_challenge_method": {core.CodeChallengeMethodS256},
				"nonce":                 {"n-from-authorize"},
			}
			if pushed {
				par := httptest.NewRequest(http.MethodPost, "/par", strings.NewReader(params.Encode()))
				par.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				rr := httptest.NewRecorder()
				mux.ServeHTTP(rr, par)
				require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
				params = url.Values{"client_id": {authcodeTestClientID}, "request_uri": {decodeJSON(t, rr)["request_uri"].(string)}}
			}

			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil))
			require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
			loc, err := url.Parse(rr.Header().Get("Location"))
			require.NoError(t, err)
			code := loc.Query().Get("code")
			require.NotEmpty(t, code)

			tr := httptest.NewRecorder()
			fx.ServeHTTP(tr, tokenRedeemForm(t, url.Values{"code": {code}}))
			require.Equal(t, http.StatusOK, tr.Code, tr.Body.String())
			claims := verifyIDToken(t, fx, decodeJSON(t, tr)["id_token"].(string))
			assert.Equal(t, "n-from-authorize", claims["nonce"])
			assert.Equal(t, float64(authTime.Unix()), claims["auth_time"])
		})
	}
}

// The consent page posts the request back as hidden inputs, and Approve
// re-reads it from there. A nonce missing from the form would be dropped
// between the consent screen and the code.
func TestOIDC_ConsentFormCarriesTheNonce(t *testing.T) {
	fx := newOIDCFixture(t, nil)
	mux := http.NewServeMux()
	apiauth.MountAuthorize(mux, apiauth.AuthorizeMountConfig{
		OneAuth:              fx.OneAuth,
		IssuerURL:            oidcIssuer,
		AllowAnyRedirectURI:  true,
		SubjectFromRequest:   func(*http.Request) string { return authcodeTestSubject },
		CSRFTokenFromRequest: func(*http.Request) string { return "" },
	})
	params := url.Values{
		"client_id":             {authcodeTestClientID},
		"redirect_uri":          {authcodeTestRedirect},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {core.ComputeCodeChallenge(authcodeTestVerifier)},
		"code_challenge_method": {core.CodeChallengeMethodS256},
		"nonce":                 {"n-consent"},
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), `<input type="hidden" name="nonce" value="n-consent">`)
}
