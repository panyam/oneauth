package apiauth_test

// Client authentication on the refresh_token grant. RFC 6749 §6 has the AS
// authenticate a confidential client and check that the refresh token was
// issued to the client presenting it. Without either check a leaked refresh
// token redeems from anywhere, under any client_id or none.
//
// References:
//   - RFC 6749 §6 (https://www.rfc-editor.org/rfc/rfc6749#section-6)
//   - RFC 6749 §10.4 (https://www.rfc-editor.org/rfc/rfc6749#section-10.4)
//   - OAuth 2.1 §4.3.1 (https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13#section-4.3.1)
//   - CWE-287 (https://cwe.mitre.org/data/definitions/287.html)

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/keys"
)

type refreshAuthFixture struct {
	*apiAuthFixture
	refreshStore core.RefreshTokenStore

	// proof, when set, is called for a fresh DPoP proof on each request.
	proof func() string
}

// newRefreshAuthFixture registers two confidential clients ("conf-client",
// "other-client", each with secret "<id>-secret") and one public client
// ("public-client"). The AppStore is wrapped so a test can make lookups fail.
func newRefreshAuthFixture(t *testing.T, appStoreErr *error) *refreshAuthFixture {
	t.Helper()
	ks := keys.NewInMemoryKeyStore()
	apps := core.NewInMemoryAppStore()
	for id, method := range map[string]string{"conf-client": "client_secret_post", "other-client": "client_secret_post", "public-client": "none"} {
		if method != "none" {
			_, _ = ks.PutKey(context.Background(), &keys.PutKeyRequest{Record: &keys.KeyRecord{
				ClientID: id, Key: []byte(id + "-secret"), Algorithm: "HS256",
			}})
		}
		_, err := apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
			ClientID: id, SigningAlg: "HS256", TokenEndpointAuthMethod: method,
		}})
		require.NoError(t, err)
	}
	var appStore core.AppRegistrationStore = apps
	if appStoreErr != nil {
		appStore = &failingAppStore{AppRegistrationStore: apps, err: appStoreErr}
	}
	store := newInMemoryRefreshStore()
	fx := newAPIAuthFixture(apiauth.OneAuthConfig{
		KeyStore:     ks,
		AppStore:     appStore,
		SigningKey:   []byte("server-jwt-secret-key-32chars!!"),
		SigningAlg:   "HS256",
		Issuer:       "refresh-auth-issuer",
		RefreshStore: store,
		DPoP:         apiauth.NewDPoPProofValidator(apiauth.DPoPConfig{EndpointURL: dpopTokenEndpointURL}),
	}, nil)
	return &refreshAuthFixture{apiAuthFixture: fx, refreshStore: store}
}

// failingAppStore returns *err from GetApp when it is set.
type failingAppStore struct {
	core.AppRegistrationStore
	err *error
}

func (s *failingAppStore) GetApp(ctx context.Context, req *core.GetAppRequest) (*core.GetAppResponse, error) {
	if *s.err != nil {
		return nil, *s.err
	}
	return s.AppRegistrationStore.GetApp(ctx, req)
}

func (fx *refreshAuthFixture) issue(t *testing.T, clientID string) string {
	t.Helper()
	created, err := fx.refreshStore.CreateRefreshToken(context.Background(), &core.CreateRefreshTokenRequest{
		Subject: "user-1", ClientID: clientID, Scopes: []string{"read"},
	})
	require.NoError(t, err)
	return created.Token.Token
}

func (fx *refreshAuthFixture) refresh(t *testing.T, token string, form url.Values, basic ...string) (int, map[string]any) {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", token)
	req := newFormRequest(form)
	if len(basic) == 2 {
		req.SetBasicAuth(basic[0], basic[1])
	}
	if fx.proof != nil {
		req.Header.Set("DPoP", fx.proof())
	}
	rr := httptest.NewRecorder()
	fx.TokenEndpoint.ServeHTTP(rr, req)
	return rr.Code, decodeJSON(t, rr)
}

// assertStillRedeemable proves a refused attempt did not rotate the token
// away from its owner.
func (fx *refreshAuthFixture) assertStillRedeemable(t *testing.T, token string, ownerForm url.Values) {
	t.Helper()
	code, body := fx.refresh(t, token, ownerForm)
	require.Equal(t, http.StatusOK, code, "the owner's token must survive a refused attempt: %v", body)
	assert.NotEmpty(t, body["access_token"])
}

func confForm(id string) url.Values {
	return url.Values{"client_id": {id}, "client_secret": {id + "-secret"}}
}

// See: https://www.rfc-editor.org/rfc/rfc6749#section-6 ("authenticate the
// client if client authentication is included")
func TestRefreshClientAuth_ConfidentialClientMustAuthenticate(t *testing.T) {
	fx := newRefreshAuthFixture(t, nil)

	for name, form := range map[string]url.Values{
		"client_id without the secret":    {"client_id": {"conf-client"}},
		"no client identification at all": nil,
		"wrong secret":                    {"client_id": {"conf-client"}, "client_secret": {"guess"}},
	} {
		t.Run(name, func(t *testing.T) {
			token := fx.issue(t, "conf-client")
			code, body := fx.refresh(t, token, form)
			assert.Equal(t, http.StatusUnauthorized, code)
			assert.Equal(t, "invalid_client", body["error"])
			assert.Nil(t, body["access_token"])
			fx.assertStillRedeemable(t, token, confForm("conf-client"))
		})
	}
}

func TestRefreshClientAuth_ConfidentialClientViaBasic(t *testing.T) {
	fx := newRefreshAuthFixture(t, nil)
	token := fx.issue(t, "conf-client")

	code, body := fx.refresh(t, token, nil, "conf-client", "conf-client-secret")

	require.Equal(t, http.StatusOK, code, body)
	assert.NotEmpty(t, body["refresh_token"])
}

// Another client authenticating correctly with its own credentials still
// can't redeem a token issued to someone else.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-5.2 (invalid_grant:
// "issued to another client")
func TestRefreshClientAuth_TokenOfAnotherConfidentialClient(t *testing.T) {
	fx := newRefreshAuthFixture(t, nil)
	token := fx.issue(t, "conf-client")

	code, body := fx.refresh(t, token, confForm("other-client"))

	assert.Equal(t, "invalid_grant", body["error"])
	assert.NotEqual(t, http.StatusOK, code)
	assert.Nil(t, body["access_token"])
	fx.assertStillRedeemable(t, token, confForm("conf-client"))
}

// A public client has nothing to authenticate with, so client_id is what ties
// the request to the token. OAuth 2.1 makes it required here.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13#section-4.3.1
func TestRefreshClientAuth_PublicClientMustNameItself(t *testing.T) {
	fx := newRefreshAuthFixture(t, nil)

	for name, form := range map[string]url.Values{
		"no client_id":        nil,
		"another client's id": {"client_id": {"other-client"}},
		"Basic as another":    nil,
	} {
		t.Run(name, func(t *testing.T) {
			token := fx.issue(t, "public-client")
			var code int
			var body map[string]any
			if name == "Basic as another" {
				code, body = fx.refresh(t, token, form, "other-client", "other-client-secret")
			} else {
				code, body = fx.refresh(t, token, form)
			}
			assert.Equal(t, "invalid_grant", body["error"])
			assert.NotEqual(t, http.StatusOK, code)
			assert.Nil(t, body["access_token"])
			fx.assertStillRedeemable(t, token, url.Values{"client_id": {"public-client"}})
		})
	}
}

// The SDK's Login issues tokens to "cli", which nothing registers. An
// unregistered owner is treated as a public client.
func TestRefreshClientAuth_UnregisteredOwnerIsPublic(t *testing.T) {
	fx := newRefreshAuthFixture(t, nil)
	token := fx.issue(t, "cli")

	code, body := fx.refresh(t, token, url.Values{"client_id": {"other-client"}})
	assert.Equal(t, "invalid_grant", body["error"])
	assert.NotEqual(t, http.StatusOK, code)

	fx.assertStillRedeemable(t, token, url.Values{"client_id": {"cli"}})
}

// A refresh token stored without a client can't be matched to one, so it
// redeems as before. Only tokens from grants that run without any client
// (the password grant with no client_id) are stored this way.
func TestRefreshClientAuth_TokenWithoutStoredClient(t *testing.T) {
	fx := newRefreshAuthFixture(t, nil)
	token := fx.issue(t, "")

	code, body := fx.refresh(t, token, nil)

	require.Equal(t, http.StatusOK, code, body)
}

// A registration lookup that errors must not be read as "unregistered", which
// would wave a confidential client through as public. The request carries a
// DPoP proof so it gets past the dpop_bound_access_tokens lookup, which
// already fails closed, and reaches the grant's own lookup.
//
// See: https://cwe.mitre.org/data/definitions/636.html (failing open)
func TestRefreshClientAuth_AppStoreErrorFailsClosed(t *testing.T) {
	var storeErr error
	fx := newRefreshAuthFixture(t, &storeErr)
	_, sign := newProofSigner(t)
	fx.proof = func() string { return sign(proofOpts{url: dpopTokenEndpointURL}) }
	token := fx.issue(t, "conf-client")
	storeErr = errors.New("datastore unavailable")

	code, body := fx.refresh(t, token, url.Values{"client_id": {"conf-client"}})

	assert.Equal(t, http.StatusInternalServerError, code)
	assert.Equal(t, "server_error", body["error"])
	assert.Nil(t, body["access_token"])

	storeErr = nil
	fx.assertStillRedeemable(t, token, confForm("conf-client"))
}

// The library entry point enforces the same match, for callers that drive
// TokenIssuer directly rather than through the token endpoint.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-6
func TestRefreshGrant_ClientMustMatchToken(t *testing.T) {
	fx := newRefreshAuthFixture(t, nil)

	for name, clientID := range map[string]string{"empty": "", "other": "other-client"} {
		t.Run(name, func(t *testing.T) {
			token := fx.issue(t, "public-client")
			_, err := fx.OneAuth.Issuer.RefreshGrant(context.Background(), &apiauth.RefreshGrantRequest{
				RefreshToken: token, ClientID: clientID,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid_grant")
		})
	}

	resp, err := fx.OneAuth.Issuer.RefreshGrant(context.Background(), &apiauth.RefreshGrantRequest{
		RefreshToken: fx.issue(t, "public-client"), ClientID: "public-client",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Tokens.AccessToken)
}
