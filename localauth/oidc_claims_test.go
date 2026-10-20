package localauth_test

// localauth.ProfileClaims maps a local user's profile to OIDC Core §5.1
// standard claims and hands out only what the granted scopes allow
// (§5.4). email_verified must come from the verified identity, since a
// relying party may trust the address for account linking.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
// See: https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/localauth"
	"github.com/panyam/oneauth/stores/fs"
)

func TestProfileClaims_ScopesChooseTheClaims(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	users, identities, channels := fs.NewFSUserStore(dir), fs.NewFSIdentityStore(dir), fs.NewFSChannelStore(dir)
	email, phone := "ada@example.com", "+15551234567"
	user, err := localauth.NewCreateUserFunc(users, identities, channels)(&localauth.Credentials{
		Username: "ada", Email: &email, Phone: &phone, Password: "password123",
	})
	require.NoError(t, err)
	claims := localauth.ProfileClaims(users, identities)

	got, err := claims(ctx, user.Id(), []string{"openid"})
	require.NoError(t, err)
	assert.Empty(t, got, "openid alone grants no profile claims")

	got, err = claims(ctx, user.Id(), []string{"openid", "profile", "email", "phone"})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"preferred_username":    "ada",
		"email":                 email,
		"email_verified":        false,
		"phone_number":          phone,
		"phone_number_verified": false,
	}, got)

	_, err = identities.MarkIdentityVerified(ctx, &accounts.MarkIdentityVerifiedRequest{IdentityType: "email", IdentityValue: email})
	require.NoError(t, err)
	got, err = claims(ctx, user.Id(), []string{"email"})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"email": email, "email_verified": true}, got)
}

func TestProfileClaims_UnknownSubjectIsAnError(t *testing.T) {
	dir := t.TempDir()
	_, err := localauth.ProfileClaims(fs.NewFSUserStore(dir), fs.NewFSIdentityStore(dir))(context.Background(), "nobody", []string{"email"})
	assert.Error(t, err)
}
