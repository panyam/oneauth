package apiauth_test

// The error /par answers when a pushed request names a redirect_uri the
// client didn't register.
//
// References:
//   - RFC 9126 §2.3 (https://www.rfc-editor.org/rfc/rfc9126#section-2.3)
//   - RFC 6749 §4.1.2.1 (https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1)
//   - See: https://github.com/panyam/oneauth/issues/439

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// See: https://www.rfc-editor.org/rfc/rfc9126#section-2.3
func TestPAR_UnregisteredRedirectURIIsInvalidRequest(t *testing.T) {
	fx := newPARFixture(t)
	fx.authz.RedirectURIValidator = func(ctx context.Context, clientID, redirectURI string) error {
		if redirectURI != parRedirectURI {
			return errors.New("redirect_uri is not registered for this client")
		}
		return nil
	}

	rr := fx.push(t, parForm(url.Values{"redirect_uri": {"https://attacker.example/cb"}}), "")

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, "invalid_request", errorCode(t, rr))
}
