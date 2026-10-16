package apiauth_test

// A client registered with require_pushed_authorization_requests can only
// start an authorization through PAR, even when the server accepts direct
// requests from other clients.
//
// See: https://www.rfc-editor.org/rfc/rfc9126#section-6
// See: https://github.com/panyam/oneauth/issues/88

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/core"
)

func TestPARPerClient_RegisteredRequirementIsEnforced(t *testing.T) {
	fx := newPARFixture(t)
	apps := core.NewInMemoryAppStore()
	_, err := apps.SaveApp(context.Background(), &core.SaveAppRequest{App: &core.AppRegistration{
		ClientID: parClientID, RedirectURIs: []string{parRedirectURI}, RequirePushedAuthorizationRequests: true,
	}})
	require.NoError(t, err)
	fx.authz.AppStore = apps

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+parForm(nil).Encode(), nil)
	_, displayErr, errCode, _ := fx.authz.ParseAndValidate(req)
	assert.Equal(t, "invalid_request", errCode, "a direct request from a PAR-only client")
	assert.True(t, displayErr)

	requestURI := fx.pushOK(t, parForm(nil), "")
	_, errCode, _ = fx.authorize(t, requestURI, parClientID)
	assert.Empty(t, errCode, "the same client through PAR")
}
