// Tests for RP-initiated logout: the URL LogoutURL builds from the
// discovery document's end_session_endpoint.

package oidc_test

import (
	"errors"
	"net/url"
	"testing"

	"github.com/panyam/oneauth/oauth2/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// See: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
func TestOIDCLogout_URL(t *testing.T) {
	f := newFakeIssuer(t)
	p, _ := newProvider(t, f)

	raw, err := p.LogoutURL("the-id-token", "http://app.test/bye", "st-1")
	require.NoError(t, err)
	u, err := url.Parse(raw)
	require.NoError(t, err)

	assert.Equal(t, f.srv.URL+"/logout", u.Scheme+"://"+u.Host+u.Path)
	q := u.Query()
	assert.Equal(t, "the-id-token", q.Get("id_token_hint"))
	assert.Equal(t, testClientID, q.Get("client_id"))
	assert.Equal(t, "http://app.test/bye", q.Get("post_logout_redirect_uri"))
	assert.Equal(t, "st-1", q.Get("state"))
	assert.Equal(t, "keep", q.Get("tenant"), "the endpoint's own query must survive")
}

func TestOIDCLogout_OmitsEmptyParameters(t *testing.T) {
	f := newFakeIssuer(t)
	p, _ := newProvider(t, f)

	raw, err := p.LogoutURL("", "", "")
	require.NoError(t, err)
	u, err := url.Parse(raw)
	require.NoError(t, err)

	q := u.Query()
	assert.Equal(t, testClientID, q.Get("client_id"))
	for _, k := range []string{"id_token_hint", "post_logout_redirect_uri", "state"} {
		_, present := q[k]
		assert.False(t, present, "%s should be absent when empty", k)
	}
}

func TestOIDCLogout_NoEndSessionEndpoint(t *testing.T) {
	f := newFakeIssuer(t)
	f.noEndSession = true
	p, _ := newProvider(t, f)

	_, err := p.LogoutURL("tok", "", "")
	assert.True(t, errors.Is(err, oidc.ErrNoEndSessionEndpoint))
	assert.Empty(t, p.Metadata().EndSessionEndpoint)
}
