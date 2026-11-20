package client

// The automatic refresh keeps the ID token a refresh returns (OIDC Core
// §12.2, issue 485). When the login verified its ID token and the client
// has the AS metadata, the refreshed one is verified too and must name
// the same user. Without a new ID token the login's is kept.
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refreshAfterVerifiedLogin logs in with VerifyIDToken on a client that
// has the AS metadata, then runs the automatic refresh.
func refreshAfterVerifiedLogin(t *testing.T, as *oidcMockAS) (login, refreshed *ServerCredential, err error) {
	t.Helper()
	ctx := context.Background()
	meta, err := DiscoverASWithContext(ctx, as.srv.URL)
	require.NoError(t, err)
	c := NewAuthClient(as.srv.URL, nil, WithASMetadata(meta))
	login, err = c.LoginWithBrowser(ctx, &BrowserLoginRequest{
		ClientID:      idtClient,
		Timeout:       5 * time.Second,
		VerifyIDToken: true,
		OpenBrowser: func(authURL string) error {
			go simulateBrowser(authURL)
			return nil
		},
	})
	require.NoError(t, err)
	require.NotNil(t, login.IDTokenClaims)

	c.OnToken = func(cred *ServerCredential) { refreshed = cred }
	c.mu.Lock()
	err = c.refreshTokenLocked(login)
	c.mu.Unlock()
	if err != nil {
		return login, nil, err
	}
	require.NotNil(t, refreshed, "OnToken sees the refreshed credential")
	return login, refreshed, nil
}

func TestRefresh_KeepsAndVerifiesTheRefreshedIDToken(t *testing.T) {
	login, refreshed, err := refreshAfterVerifiedLogin(t, newOIDCMockAS(t))
	require.NoError(t, err)
	require.NotEmpty(t, refreshed.IDToken)
	assert.NotEqual(t, login.IDToken, refreshed.IDToken, "the refreshed ID token, not the login's")
	require.NotNil(t, refreshed.IDTokenClaims)
	assert.Equal(t, "user-1", refreshed.IDTokenClaims.Subject)
	assert.Empty(t, refreshed.IDTokenClaims.Nonce)
}

func TestRefresh_RefusesAnIDTokenForAnotherUser(t *testing.T) {
	as := newOIDCMockAS(t)
	as.refreshSub = "user-2"
	_, _, err := refreshAfterVerifiedLogin(t, as)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidIDToken), "got %v", err)
}

func TestRefresh_KeepsTheLoginsIDTokenWhenNoneComesBack(t *testing.T) {
	as := newOIDCMockAS(t)
	as.refreshOmitsIDToken = true
	login, refreshed, err := refreshAfterVerifiedLogin(t, as)
	require.NoError(t, err)
	assert.Equal(t, login.IDToken, refreshed.IDToken)
	assert.Equal(t, login.IDTokenClaims, refreshed.IDTokenClaims)
}
