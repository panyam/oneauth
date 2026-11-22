package keycloak_test

// Keycloak verifying a PS256 ID token that oneauth signed (issue 558). It's
// the reverse of TestKeycloak_JARMLogin, where oneauth verifies Keycloak's
// PS256 signing.
//
// The test registers an OIDC identity provider in Keycloak with
// JWT Authorization Grant (RFC 7523 §2.1) turned on, the PS256 public key
// pinned as a PEM, and the assertion algorithm pinned to PS256. oneauth's
// IDTokenIssuer mints an ID token for the test user, and the test trades it
// at Keycloak's token endpoint for a Keycloak access token. The pinned key
// means Keycloak never fetches a JWKS, so it doesn't need to reach the host
// from inside Docker.
//
// See: https://www.rfc-editor.org/rfc/rfc7523#section-2.1
// See: https://www.rfc-editor.org/rfc/rfc8017#section-8.1
// See: https://github.com/panyam/oneauth/issues/558

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
)

const (
	jwtGrantIssuer   = "https://oneauth-ps256.example.test"
	jwtGrantAudience = "keycloak-broker"
	jwtGrantSubject  = "oneauth-user-558"
)

func TestKeycloak_VerifiesOneauthPS256IDToken(t *testing.T) {
	skipIfKeycloakNotRunning(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	grant := setupJWTGrant(t, &key.PublicKey)

	issuer, err := apiauth.NewJWTIDTokenIssuer(apiauth.JWTIDTokenIssuerConfig{
		SigningKey: key,
		SigningAlg: "PS256",
		Issuer:     jwtGrantIssuer,
		Expiry:     2 * time.Minute,
	})
	require.NoError(t, err)
	mint := func() string {
		resp, err := issuer.CreateIDToken(context.Background(), &apiauth.CreateIDTokenRequest{
			Subject: jwtGrantSubject, ClientID: jwtGrantAudience,
		})
		require.NoError(t, err)
		return resp.Token
	}

	t.Run("accepted", func(t *testing.T) {
		idToken := mint()
		assert.Equal(t, "PS256", parseJWTHeader(t, idToken)["alg"])
		status, body := grant.exchange(t, idToken)
		require.Equal(t, http.StatusOK, status, body)
		var tok struct {
			AccessToken string `json:"access_token"`
		}
		require.NoError(t, json.Unmarshal([]byte(body), &tok))
		claims := parseJWTClaims(t, tok.AccessToken)
		assert.Equal(t, realmURL(), claims["iss"])
		assert.Equal(t, grant.userID, claims["sub"], "the token is for the user linked to the oneauth subject")
	})

	// The same claims under another key, or as RS256 under the right key,
	// show Keycloak checked the PS256 signature rather than the claims.
	t.Run("another key refused", func(t *testing.T) {
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		status, body := grant.exchange(t, resign(t, mint(), jwt.SigningMethodPS256, other))
		assert.Equal(t, http.StatusBadRequest, status, body)
		assert.Contains(t, body, "invalid_grant")
	})
	t.Run("RS256 under the same key refused", func(t *testing.T) {
		status, body := grant.exchange(t, resign(t, mint(), jwt.SigningMethodRS256, key))
		assert.Equal(t, http.StatusBadRequest, status, body)
		assert.Contains(t, body, "invalid_grant")
	})
}

// resign signs token's claims again with another method or key.
func resign(t *testing.T, token string, method jwt.SigningMethod, key *rsa.PrivateKey) string {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(token, claims)
	require.NoError(t, err)
	out, err := jwt.NewWithClaims(method, claims).SignedString(key)
	require.NoError(t, err)
	return out
}

// jwtGrant is the identity provider and client setupJWTGrant made.
type jwtGrant struct {
	clientID, secret string
	// userID is the Keycloak ID of the user linked to jwtGrantSubject.
	userID string
}

// exchange posts assertion as an RFC 7523 JWT bearer grant and returns the
// status and body.
func (g jwtGrant) exchange(t *testing.T, assertion string) (int, string) {
	t.Helper()
	resp, err := http.PostForm(keycloakTokenEndpoint(), url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":     {assertion},
		"client_id":     {g.clientID},
		"client_secret": {g.secret},
	})
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// setupJWTGrant registers, through Keycloak's admin API, an OIDC identity
// provider trusting pub for JWT Authorization Grant, a confidential client
// allowed to use it, and a link from the test user to jwtGrantSubject at
// that provider. Each run uses fresh names and removes them afterwards, so
// realm.json doesn't change and a running Keycloak needs no re-import.
func setupJWTGrant(t *testing.T, pub *rsa.PublicKey) jwtGrant {
	t.Helper()
	admin := newKeycloakAdmin(t)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	alias := "oneauth-ps256-" + suffix
	g := jwtGrant{clientID: "test-jwt-grant-" + suffix, secret: "jwt-grant-secret-" + suffix}

	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	admin.do(t, http.MethodPost, "/identity-provider/instances", map[string]any{
		"alias": alias, "providerId": "oidc", "enabled": true,
		"config": map[string]string{
			"issuer":                       jwtGrantIssuer,
			"clientId":                     jwtGrantAudience,
			"clientSecret":                 "unused",
			"authorizationUrl":             jwtGrantIssuer + "/authorize",
			"tokenUrl":                     jwtGrantIssuer + "/token",
			"validateSignature":            "true",
			"useJwksUrl":                   "false",
			"publicKeySignatureVerifier":   pemKey,
			"allowClientIdAsAudience":      "true",
			"jwtAuthorizationGrantEnabled": "true",
			"jwtAuthorizationGrantAssertionSignatureAlg": "PS256",
			// oneauth's ID tokens carry no jti, which Keycloak needs to
			// refuse a replay. The test mints a fresh token per case anyway.
			"jwtAuthorizationGrantAssertionReuseAllowed": "true",
		},
	}, http.StatusCreated)
	t.Cleanup(func() {
		admin.do(t, http.MethodDelete, "/identity-provider/instances/"+alias, nil, http.StatusNoContent)
	})

	loc := admin.do(t, http.MethodPost, "/clients", map[string]any{
		"clientId": g.clientID, "secret": g.secret, "enabled": true,
		"publicClient": false, "standardFlowEnabled": false, "directAccessGrantsEnabled": false,
		"attributes": map[string]string{
			"oauth2.jwt.authorization.grant.enabled": "true",
			"oauth2.jwt.authorization.grant.idp":     alias,
		},
	}, http.StatusCreated)
	clientPath := loc[strings.Index(loc, "/clients/"):]
	t.Cleanup(func() { admin.do(t, http.MethodDelete, clientPath, nil, http.StatusNoContent) })

	var users []struct{ ID string }
	require.NoError(t, json.Unmarshal([]byte(admin.get(t, "/users?exact=true&username="+testUsername)), &users))
	require.Len(t, users, 1)
	admin.do(t, http.MethodPost, "/users/"+users[0].ID+"/federated-identity/"+alias, map[string]string{
		"identityProvider": alias, "userId": jwtGrantSubject, "userName": jwtGrantSubject,
	}, http.StatusNoContent)
	g.userID = users[0].ID
	return g
}

// keycloakAdmin calls the admin REST API for the test realm as the
// bootstrap admin from docker-compose.yml.
type keycloakAdmin struct{ token string }

func newKeycloakAdmin(t *testing.T) keycloakAdmin {
	t.Helper()
	resp, err := http.PostForm(keycloakURL()+"/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"}, "password": {"admin"},
	})
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "Keycloak admin login")
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tok))
	return keycloakAdmin{token: tok.AccessToken}
}

// do sends body as JSON to the realm's admin path, requires want, and
// returns the Location header.
func (a keycloakAdmin) do(t *testing.T, method, path string, body any, want int) string {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, keycloakURL()+"/admin/realms/"+realmName+path, r)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	msg, _ := io.ReadAll(resp.Body)
	require.Equal(t, want, resp.StatusCode, "%s %s: %s", method, path, msg)
	return resp.Header.Get("Location")
}

func (a keycloakAdmin) get(t *testing.T, path string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, keycloakURL()+"/admin/realms/"+realmName+path, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+a.token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET %s: %s", path, body)
	return string(body)
}
