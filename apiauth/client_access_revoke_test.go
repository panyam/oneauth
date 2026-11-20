package apiauth_test

// Disconnecting an app withdraws the user's consent and ends the app's
// sessions for that user: its refresh tokens are revoked family by
// family, and the access tokens issued with them are blacklisted. Other
// apps, and the same app's sessions for other users, are untouched.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
// See: https://openid.net/specs/openid-connect-core-1_0.html#Consent
// See: https://github.com/panyam/oneauth/issues/516

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/stores/fs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type clientAccessFixture struct {
	oa       *apiauth.OneAuth
	consents *core.InMemoryConsentStore
	revoked  []string // "subject|sid|client" per OnTokenRevoked
	mu       sync.Mutex
}

func newClientAccessFixture(t *testing.T) *clientAccessFixture {
	t.Helper()
	fx := &clientAccessFixture{consents: core.NewInMemoryConsentStore()}
	cfg := apiauth.OneAuthConfig{
		SigningKey:   []byte("client-access-revoke-secret-32ch!"),
		SigningAlg:   "HS256",
		Issuer:       "test-issuer",
		RefreshStore: fs.NewFSRefreshTokenStore(t.TempDir()),
		Blacklist:    core.NewInMemoryBlacklist(),
	}
	cfg.Hooks.Token.OnTokenRevoked = func(subject, sid, clientID string) {
		fx.mu.Lock()
		fx.revoked = append(fx.revoked, subject+"|"+sid+"|"+clientID)
		fx.mu.Unlock()
	}
	fx.oa = apiauth.NewOneAuth(cfg)
	return fx
}

// session is one grant's refresh token plus an access token recorded on it.
type session struct {
	refresh, access, family string
}

// connect records consent for (subject, client) and starts a session for
// it, as an approved authorization code redemption would.
func (fx *clientAccessFixture) connect(t *testing.T, subject, clientID string) session {
	t.Helper()
	ctx := context.Background()
	_, err := fx.consents.SaveConsent(ctx, &core.SaveConsentRequest{Grant: &core.ConsentGrant{
		Subject: subject, ClientID: clientID, Scopes: []string{"openid"},
		GrantedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}})
	require.NoError(t, err)
	return fx.startSession(t, subject, clientID)
}

func (fx *clientAccessFixture) startSession(t *testing.T, subject, clientID string) session {
	t.Helper()
	ctx := context.Background()
	rt, err := fx.oa.RefreshStore.CreateRefreshToken(ctx, &core.CreateRefreshTokenRequest{
		Subject: subject, ClientID: clientID, Scopes: []string{"openid"},
	})
	require.NoError(t, err)
	at, err := fx.oa.Issuer.CreateAccessToken(ctx, &apiauth.CreateAccessTokenRequest{Subject: subject, Scopes: []string{"openid"}})
	require.NoError(t, err)
	_, err = fx.oa.RefreshStore.RecordAccessToken(ctx, &core.RecordAccessTokenRequest{
		Token: rt.Token.Token, TokenID: at.TokenID, ExpiresAt: at.ExpiresAt,
	})
	require.NoError(t, err)
	return session{refresh: rt.Token.Token, access: at.Token, family: rt.Token.Family}
}

func (fx *clientAccessFixture) accessValid(token string) bool {
	_, err := fx.oa.Validator.ValidateToken(context.Background(), &apiauth.ValidateTokenRequest{Token: token})
	return err == nil
}

func (fx *clientAccessFixture) refresh(refreshToken, clientID string) (*core.TokenPair, error) {
	resp, err := fx.oa.Issuer.RefreshGrant(context.Background(), &apiauth.RefreshGrantRequest{RefreshToken: refreshToken, ClientID: clientID})
	if err != nil {
		return nil, err
	}
	return resp.Tokens, nil
}

func (fx *clientAccessFixture) hasConsent(subject, clientID string) bool {
	_, err := fx.consents.GetConsent(context.Background(), &core.GetConsentRequest{Subject: subject, ClientID: clientID})
	return err == nil
}

func TestRevokeClientAccess_EndsTheClientsGrantForTheUser(t *testing.T) {
	fx := newClientAccessFixture(t)
	target := fx.connect(t, "alice", "app-a")
	second := fx.startSession(t, "alice", "app-a") // another device, same app
	// Rotate the second session, so the family has a revoked generation
	// whose access token must be blacklisted too.
	rotated, err := fx.refresh(second.refresh, "app-a")
	require.NoError(t, err)
	otherApp := fx.connect(t, "alice", "app-b")
	otherUser := fx.connect(t, "bob", "app-a")

	resp, err := fx.oa.ClientAccessRevoker(fx.consents).RevokeClientAccess(context.Background(),
		&apiauth.RevokeClientAccessRequest{Subject: "alice", ClientID: "app-a"})
	require.NoError(t, err)
	assert.Equal(t, 2, resp.RevokedFamilies)
	assert.Equal(t, 3, resp.BlacklistedAccessTokens, "both sessions' tokens, the rotated generation included")

	assert.False(t, fx.hasConsent("alice", "app-a"), "consent withdrawn")
	for _, at := range []string{target.access, second.access, rotated.AccessToken} {
		assert.False(t, fx.accessValid(at), "access token of a revoked family")
	}
	_, err = fx.refresh(target.refresh, "app-a")
	assert.Error(t, err, "refresh token of a revoked family")
	_, err = fx.refresh(rotated.RefreshToken, "app-a")
	assert.Error(t, err, "the rotated refresh token")

	assert.True(t, fx.hasConsent("alice", "app-b"), "another app's consent")
	assert.True(t, fx.hasConsent("bob", "app-a"), "another user's consent for the same app")
	for name, s := range map[string]session{"other app": otherApp, "other user": otherUser} {
		assert.True(t, fx.accessValid(s.access), "%s: access token", name)
	}
	_, err = fx.refresh(otherApp.refresh, "app-b")
	assert.NoError(t, err, "another app's refresh token")
	_, err = fx.refresh(otherUser.refresh, "app-a")
	assert.NoError(t, err, "another user's refresh token for the same app")
}

// Each revoked family fires OnTokenRevoked, so back-channel logout tells
// the client its session for the user ended.
func TestRevokeClientAccess_FiresTokenRevokedPerFamily(t *testing.T) {
	fx := newClientAccessFixture(t)
	a := fx.connect(t, "alice", "app-a")
	fx.connect(t, "alice", "app-b")

	_, err := fx.oa.ClientAccessRevoker(fx.consents).RevokeClientAccess(context.Background(),
		&apiauth.RevokeClientAccessRequest{Subject: "alice", ClientID: "app-a"})
	require.NoError(t, err)
	assert.Equal(t, []string{"alice|" + a.family + "|app-a"}, fx.revoked)
}

// An empty subject or client is refused before anything is revoked, so a
// caller that lost the session's user can't revoke every user's grant.
func TestRevokeClientAccess_RefusesAnEmptyKey(t *testing.T) {
	fx := newClientAccessFixture(t)
	s := fx.connect(t, "alice", "app-a")
	r := fx.oa.ClientAccessRevoker(fx.consents)
	for _, req := range []*apiauth.RevokeClientAccessRequest{nil, {ClientID: "app-a"}, {Subject: "alice"}} {
		_, err := r.RevokeClientAccess(context.Background(), req)
		assert.ErrorIs(t, err, apiauth.ErrClientAccessKeyRequired, "%+v", req)
	}
	assert.True(t, fx.hasConsent("alice", "app-a"))
	assert.True(t, fx.accessValid(s.access))
}

// Revoking a client the user never connected succeeds and reports zero.
func TestRevokeClientAccess_Idempotent(t *testing.T) {
	fx := newClientAccessFixture(t)
	r := fx.oa.ClientAccessRevoker(fx.consents)
	fx.connect(t, "alice", "app-a")
	for i := 0; i < 2; i++ {
		_, err := r.RevokeClientAccess(context.Background(), &apiauth.RevokeClientAccessRequest{Subject: "alice", ClientID: "app-a"})
		require.NoError(t, err)
	}
	resp, err := r.RevokeClientAccess(context.Background(), &apiauth.RevokeClientAccessRequest{Subject: "alice", ClientID: "never"})
	require.NoError(t, err)
	assert.Equal(t, apiauth.RevokeClientAccessResponse{}, *resp)
}

// failingFamilyStore fails every RevokeTokenFamily.
type failingFamilyStore struct {
	core.RefreshTokenStore
}

func (failingFamilyStore) RevokeTokenFamily(context.Context, *core.RevokeTokenFamilyRequest) (*core.RevokeTokenFamilyResponse, error) {
	return nil, errors.New("store down")
}

// When a family can't be revoked the consent stays, so the app is still
// listed and the user can try again.
func TestRevokeClientAccess_KeepsConsentWhenATokenRevokeFails(t *testing.T) {
	fx := newClientAccessFixture(t)
	fx.connect(t, "alice", "app-a")
	r := fx.oa.ClientAccessRevoker(fx.consents)
	r.RefreshStore = failingFamilyStore{fx.oa.RefreshStore}

	_, err := r.RevokeClientAccess(context.Background(), &apiauth.RevokeClientAccessRequest{Subject: "alice", ClientID: "app-a"})
	assert.Error(t, err)
	assert.True(t, fx.hasConsent("alice", "app-a"))
}

// Without a refresh store the revoker still withdraws consent.
func TestRevokeClientAccess_ConsentOnly(t *testing.T) {
	fx := newClientAccessFixture(t)
	fx.connect(t, "alice", "app-a")
	r := &apiauth.ClientAccessRevoker{ConsentStore: fx.consents}
	_, err := r.RevokeClientAccess(context.Background(), &apiauth.RevokeClientAccessRequest{Subject: "alice", ClientID: "app-a"})
	require.NoError(t, err)
	assert.False(t, fx.hasConsent("alice", "app-a"))
}
