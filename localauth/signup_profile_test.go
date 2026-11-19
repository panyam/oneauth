package localauth_test

// Standard OIDC profile claims (OIDC Core §5.1) given at signup, and
// handed back by ProfileClaims for the scopes that grant them (§5.4).
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
// See: https://github.com/panyam/oneauth/issues/481

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/accounts"
	"github.com/panyam/oneauth/localauth"
	"github.com/panyam/oneauth/stores/fs"
)

// ProfileClaims hands out any standard claim the profile holds under its
// own name, gated by scope, and nothing that isn't a standard claim.
func TestProfileClaims_StandardProfileClaimsPassThrough(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	users, identities, channels := fs.NewFSUserStore(dir), fs.NewFSIdentityStore(dir), fs.NewFSChannelStore(dir)
	email := "ada@example.com"
	address := map[string]any{"formatted": "12 St James's Square, London"}
	user, err := localauth.NewCreateUserFunc(users, identities, channels)(&localauth.Credentials{
		Username: "ada", Email: &email, Password: "password123",
		Profile: map[string]any{"name": "Ada Lovelace", "given_name": "Ada", "address": address, "role": "admin"},
	})
	require.NoError(t, err)
	claims := localauth.ProfileClaims(users, identities)

	got, err := claims(ctx, user.Id(), []string{"profile"})
	require.NoError(t, err)
	assert.Equal(t, "Ada Lovelace", got["name"])
	assert.Equal(t, "Ada", got["given_name"])
	assert.Equal(t, "ada", got["preferred_username"])
	assert.NotContains(t, got, "address", "address needs the address scope")
	assert.NotContains(t, got, "role", "not a standard claim")

	got, err = claims(ctx, user.Id(), []string{"address"})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"address": address}, got)
}

// The user's own profile fields can't overwrite the claims oneauth sets
// from the account: username, email and phone.
func TestCreateUser_ProfileCannotOverrideAccountFields(t *testing.T) {
	dir := t.TempDir()
	users := fs.NewFSUserStore(dir)
	email := "ada@example.com"
	user, err := localauth.NewCreateUserFunc(users, fs.NewFSIdentityStore(dir), fs.NewFSChannelStore(dir))(&localauth.Credentials{
		Username: "ada", Email: &email, Password: "password123",
		Profile: map[string]any{"username": "root", "email": "boss@example.com", "phone": "+15550000000", "name": "Ada"},
	})
	require.NoError(t, err)
	resp, err := users.GetUserById(context.Background(), &accounts.GetUserByIDRequest{UserID: user.Id()})
	require.NoError(t, err)
	p := resp.User.Profile()
	assert.Equal(t, "ada", p["username"])
	assert.Equal(t, email, p["email"])
	assert.NotContains(t, p, "phone", "the account has no phone, so none comes from the profile either")
	assert.Equal(t, "Ada", p["name"])
}

// Signup copies only the profile claims SignupPolicy.ProfileClaims lists.
// An `address` form field becomes the claim's `formatted` member, since
// the OIDC address claim is an object (§5.1.1).
func TestSignup_AcceptsTheListedProfileClaims(t *testing.T) {
	auth, service, _, tmpDir := setupPasswordResetAuth(t)
	defer cleanup(t, tmpDir)
	policy := localauth.DefaultSignupPolicy()
	policy.ProfileClaims = []string{"name", "address"}
	auth.SignupPolicy = &policy

	form := url.Values{
		"username": {"grace"}, "email": {"grace@example.com"}, "password": {"a-good-password-123"},
		"name": {"Grace Hopper"}, "address": {"1 Navy Way, Arlington"}, "given_name": {"Grace"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	auth.HandleSignup(rr, req)
	require.Less(t, rr.Code, 400, rr.Body.String())

	id, err := service.IdentityStore.GetIdentity(context.Background(), &accounts.GetIdentityRequest{IdentityType: "email", IdentityValue: "grace@example.com"})
	require.NoError(t, err)
	resp, err := service.UserStore.GetUserById(context.Background(), &accounts.GetUserByIDRequest{UserID: id.Identity.UserID})
	require.NoError(t, err)
	p := resp.User.Profile()
	assert.Equal(t, "Grace Hopper", p["name"])
	assert.Equal(t, map[string]any{"formatted": "1 Navy Way, Arlington"}, p["address"])
	assert.NotContains(t, p, "given_name", "not listed in ProfileClaims")
}

// Without ProfileClaims, signup ignores profile fields, as before.
func TestSignup_IgnoresProfileFieldsByDefault(t *testing.T) {
	_, err := localauth.ParseSignupProfile(url.Values{"name": {"Grace"}}, nil)
	assert.NoError(t, err)
	got, _ := localauth.ParseSignupProfile(url.Values{"name": {"Grace"}}, nil)
	assert.Empty(t, got)
}

// A ProfileClaims entry that isn't a standard profile claim is refused,
// so a deployment can't let users set arbitrary profile keys.
func TestSignup_ProfileClaimsMustBeStandard(t *testing.T) {
	for _, name := range []string{"email", "role", "username", "sub"} {
		_, err := localauth.ParseSignupProfile(url.Values{name: {"x"}}, []string{name})
		assert.Error(t, err, name)
	}
}
