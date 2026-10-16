package apiauth_test

// The device verification pages refuse to be framed, so another site can't
// overlay them and trick a signed-in user into approving a device
// (clickjacking, RFC 6749 §10.13). The pages set it themselves rather than
// relying on the deployment's middleware.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-10.13
// See: https://www.rfc-editor.org/rfc/rfc8628#section-5.4
// See: https://github.com/panyam/oneauth/issues/88

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertNotFramable(t *testing.T, h http.Header, page string) {
	t.Helper()
	assert.Equal(t, "DENY", h.Get("X-Frame-Options"), page)
	assert.Contains(t, h.Get("Content-Security-Policy"), "frame-ancestors 'none'", page)
}

func TestFraming_DeviceVerificationPages(t *testing.T) {
	f := newDeviceVerifyFixture(t)

	form := httptest.NewRecorder()
	f.handler.Form(form, httptest.NewRequest(http.MethodGet, "/device", nil))
	require.Equal(t, http.StatusOK, form.Code)
	assertNotFramable(t, form.Header(), "the user-code form")

	f.sessionSubject = "alice"
	code := f.seedDeviceAuth(t, "client-tv", "WDJB-MJHT", []string{"read"})
	consent := httptest.NewRecorder()
	f.handler.Consent(consent, httptest.NewRequest(http.MethodGet, "/device/approve?user_code="+code, nil))
	require.Equal(t, http.StatusOK, consent.Code)
	assertNotFramable(t, consent.Header(), "the device consent page")
}

// A deployment's own CSP is kept; the page only adds frame-ancestors when
// no policy is set.
func TestFraming_KeepsAnExistingCSP(t *testing.T) {
	f := newDeviceVerifyFixture(t)
	rr := httptest.NewRecorder()
	rr.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'")
	f.handler.Form(rr, httptest.NewRequest(http.MethodGet, "/device", nil))

	assert.Equal(t, "default-src 'self'; frame-ancestors 'self'", rr.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "DENY", rr.Header().Get("X-Frame-Options"))
}
