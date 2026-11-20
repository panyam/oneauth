package refreshtokentest

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/panyam/oneauth/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createFor(t *testing.T, s core.RefreshTokenStore, subject string) *core.RefreshToken {
	t.Helper()
	resp, err := s.CreateRefreshToken(context.Background(), &core.CreateRefreshTokenRequest{Subject: subject, ClientID: "client-x"})
	require.NoError(t, err)
	return resp.Token
}

func uniqueSubject(t *testing.T, name string) string {
	t.Helper()
	suffix, err := core.GenerateSecureToken()
	require.NoError(t, err)
	return name + "-" + suffix[:12]
}

func revokeSubject(t *testing.T, s core.RefreshTokenStore, subject string) []string {
	t.Helper()
	resp, err := s.RevokeSubjectTokens(context.Background(), &core.RevokeSubjectTokensRequest{Subject: subject})
	require.NoError(t, err)
	require.NotNil(t, resp)
	var ids []string
	for _, a := range resp.AccessTokens {
		ids = append(ids, a.TokenID)
	}
	sort.Strings(ids)
	return ids
}

// TestRevokeSubjectReturnsAccessTokens: logout-all and password reset
// revoke every session the user has, so they must get back the live
// access tokens of every family. That includes one issued before a
// rotation and one whose refresh token was revoked earlier, and excludes
// an expired one and another user's.
//
// See: https://www.rfc-editor.org/rfc/rfc7009#section-2.1
func TestRevokeSubjectReturnsAccessTokens(t *testing.T, factory Factory) {
	s := factory(t)
	ctx := context.Background()
	exp := time.Now().Add(15 * time.Minute)
	// Unique names: a factory may share storage across scenarios (the
	// Datastore emulator does), and the others create tokens for "alice".
	alice, bobName := uniqueSubject(t, "alice"), uniqueSubject(t, "bob")

	laptop := createFor(t, s, alice)
	record(t, s, laptop.Token, "at-laptop-1", exp)
	rot, err := s.RotateRefreshToken(ctx, &core.RotateRefreshTokenRequest{OldToken: laptop.Token})
	require.NoError(t, err)
	record(t, s, rot.Token.Token, "at-laptop-2", exp)

	phone := createFor(t, s, alice)
	record(t, s, phone.Token, "at-phone", exp)
	record(t, s, phone.Token, "at-phone-old", time.Now().Add(-time.Minute))

	tablet := createFor(t, s, alice)
	record(t, s, tablet.Token, "at-tablet", exp)
	revokeFamily(t, s, tablet.Family)

	bob := createFor(t, s, bobName)
	record(t, s, bob.Token, "at-bob", exp)

	assert.Equal(t, []string{"at-laptop-1", "at-laptop-2", "at-phone", "at-tablet"}, revokeSubject(t, s, alice))
	assert.True(t, revoked(t, s, rot.Token.Token))
	assert.True(t, revoked(t, s, phone.Token))
	assert.False(t, revoked(t, s, bob.Token))

	got := record(t, s, phone.Token, "at-phone-late", exp)
	assert.True(t, got.Revoked, "an access token minted after the revoke sees it")
}

// TestRevokeUnknownSubject is a no-op, not an error.
func TestRevokeUnknownSubject(t *testing.T, factory Factory) {
	s := factory(t)
	assert.Empty(t, revokeSubject(t, s, uniqueSubject(t, "nobody")))
}

// TestOIDCGrantSurvivesRotation: a refreshed ID token reports the
// original login (OIDC Core §12.2), so the store has to keep the login's
// auth_time, acr, amr and claims request through every rotation.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
func TestOIDCGrantSurvivesRotation(t *testing.T, factory Factory) {
	s := factory(t)
	ctx := context.Background()
	login := &core.OIDCGrant{
		AuthTime:       time.Now().Add(-time.Hour).Truncate(time.Second),
		ACR:            "1",
		AMR:            []string{"pwd"},
		IDTokenClaims:  []string{"email"},
		UserinfoClaims: []string{"name"},
	}
	created, err := s.CreateRefreshToken(ctx, &core.CreateRefreshTokenRequest{
		Subject: "alice", ClientID: "client-x", Scopes: []string{"openid"}, OIDC: login,
	})
	require.NoError(t, err)
	assertOIDCGrant(t, login, created.Token.OIDC, "create")

	got, err := s.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: created.Token.Token})
	require.NoError(t, err)
	assertOIDCGrant(t, login, got.Token.OIDC, "get")

	rot, err := s.RotateRefreshToken(ctx, &core.RotateRefreshTokenRequest{OldToken: created.Token.Token})
	require.NoError(t, err)
	assertOIDCGrant(t, login, rot.Token.OIDC, "rotate")

	got, err = s.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: rot.Token.Token})
	require.NoError(t, err)
	assertOIDCGrant(t, login, got.Token.OIDC, "get after rotate")

	plain := createFor(t, s, "bob")
	got, err = s.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: plain.Token})
	require.NoError(t, err)
	assert.Nil(t, got.Token.OIDC, "a grant without openid has no OIDC record")
}

func assertOIDCGrant(t *testing.T, want, got *core.OIDCGrant, step string) {
	t.Helper()
	require.NotNil(t, got, step)
	assert.True(t, want.AuthTime.Equal(got.AuthTime), "%s: auth_time %v, want %v", step, got.AuthTime, want.AuthTime)
	assert.Equal(t, want.ACR, got.ACR, step)
	assert.Equal(t, want.AMR, got.AMR, step)
	assert.Equal(t, want.IDTokenClaims, got.IDTokenClaims, step)
	assert.Equal(t, want.UserinfoClaims, got.UserinfoClaims, step)
}

// TestResourcesSurviveRotation: a refresh may bind its access token to any
// of the grant's RFC 8707 resources and no others, so the store has to keep
// them through every rotation. Losing them would let a refresh name any
// allowed resource.
//
// See: https://www.rfc-editor.org/rfc/rfc8707#section-2.2
func TestResourcesSurviveRotation(t *testing.T, factory Factory) {
	s := factory(t)
	ctx := context.Background()
	want := []string{"https://mcp-a.example/mcp", "https://mcp-b.example/mcp"}
	created, err := s.CreateRefreshToken(ctx, &core.CreateRefreshTokenRequest{Subject: "alice", ClientID: "client-x", Resources: want})
	require.NoError(t, err)
	assert.Equal(t, want, created.Token.Resources, "create")

	rot, err := s.RotateRefreshToken(ctx, &core.RotateRefreshTokenRequest{OldToken: created.Token.Token})
	require.NoError(t, err)
	assert.Equal(t, want, rot.Token.Resources, "rotate")

	got, err := s.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: rot.Token.Token})
	require.NoError(t, err)
	assert.Equal(t, want, got.Token.Resources, "get after rotate")

	plain := createFor(t, s, "bob")
	got, err = s.GetRefreshToken(ctx, &core.GetRefreshTokenRequest{Token: plain.Token})
	require.NoError(t, err)
	assert.Empty(t, got.Token.Resources)
}
