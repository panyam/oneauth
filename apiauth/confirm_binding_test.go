package apiauth_test

// ConfirmBindingMatches accepts a bound token only for the key a channel has
// already proven, such as the DPoP key a WebSocket upgrade request carried.
//
// See: https://www.rfc-editor.org/rfc/rfc9449#section-7.2
// See: https://github.com/panyam/oneauth/issues/458

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
)

func validateWithProven(proven *core.Confirmation, token string) error {
	_, err := bearerMiddleware(withDPoP).ValidateBearer(context.Background(), &apiauth.ValidateBearerRequest{
		Token:          token,
		ConfirmBinding: apiauth.ConfirmBindingMatches(proven),
	})
	return err
}

func TestConfirmBindingMatches_SameKeyAccepted(t *testing.T) {
	require.NoError(t, validateWithProven(&core.Confirmation{JKT: "jkt-1"}, boundToken(t, "jkt-1")))
}

func TestConfirmBindingMatches_OtherKeyRefused(t *testing.T) {
	err := validateWithProven(&core.Confirmation{JKT: "jkt-2"}, boundToken(t, "jkt-1"))

	ae := requireAuthError(t, err, "invalid_token")
	assert.Equal(t, apiauth.TokenTypeDPoP, ae.Scheme)
}

// A channel opened with a plain bearer token proved no key, so it can't
// accept a bound token later.
func TestConfirmBindingMatches_UnprovenChannelRefusesBoundToken(t *testing.T) {
	for name, proven := range map[string]*core.Confirmation{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			requireAuthError(t, validateWithProven(proven, boundToken(t, "jkt-1")), "invalid_token")
		})
	}
}

func TestConfirmBindingMatches_UnboundTokenUnaffected(t *testing.T) {
	require.NoError(t, validateWithProven(nil, signTimesToken(t, timesClaims())))
}
