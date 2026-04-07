package client

// Tests for token endpoint auth method selection logic (RFC 6749 §2.3, RFC 8414 §2).
// SelectAuthMethod negotiates the correct authentication method based on client
// credentials and AS-advertised capabilities.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3
// See: https://github.com/panyam/oneauth/issues/72

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSelectAuthMethod_NoSecret verifies that a public client (no secret)
// always selects "none" regardless of what the AS advertises. Public clients
// using PKCE never send a client_secret.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.1
func TestSelectAuthMethod_NoSecret(t *testing.T) {
	assert.Equal(t, AuthMethodNone, SelectAuthMethod("", nil))
	assert.Equal(t, AuthMethodNone, SelectAuthMethod("", []string{}))
	assert.Equal(t, AuthMethodNone, SelectAuthMethod("", []string{"client_secret_basic"}))
	assert.Equal(t, AuthMethodNone, SelectAuthMethod("", []string{"client_secret_post", "client_secret_basic"}))
}

// TestSelectAuthMethod_NoASMethods_DefaultsToBasic verifies that when the AS
// does not advertise token_endpoint_auth_methods_supported, the client defaults
// to client_secret_basic per RFC 6749 §2.3.1.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
func TestSelectAuthMethod_NoASMethods_DefaultsToBasic(t *testing.T) {
	assert.Equal(t, AuthMethodClientSecretBasic, SelectAuthMethod("secret", nil))
	assert.Equal(t, AuthMethodClientSecretBasic, SelectAuthMethod("secret", []string{}))
}

// TestSelectAuthMethod_PrefersBasic verifies that when the AS supports both
// client_secret_basic and client_secret_post, basic is preferred because
// credentials stay in the Authorization header rather than the request body.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
func TestSelectAuthMethod_PrefersBasic(t *testing.T) {
	methods := []string{"client_secret_post", "client_secret_basic"}
	assert.Equal(t, AuthMethodClientSecretBasic, SelectAuthMethod("secret", methods))

	// Order shouldn't matter
	methods = []string{"client_secret_basic", "client_secret_post"}
	assert.Equal(t, AuthMethodClientSecretBasic, SelectAuthMethod("secret", methods))
}

// TestSelectAuthMethod_FallsBackToPost verifies that when the AS only supports
// client_secret_post, the client uses it even though basic is preferred.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
func TestSelectAuthMethod_FallsBackToPost(t *testing.T) {
	methods := []string{"client_secret_post"}
	assert.Equal(t, AuthMethodClientSecretPost, SelectAuthMethod("secret", methods))
}

// TestSelectAuthMethod_UnknownMethods_DefaultsToBasic verifies that when the
// AS only advertises methods we don't support (e.g., private_key_jwt), we fall
// back to client_secret_basic as the RFC default.
//
// See: https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
func TestSelectAuthMethod_UnknownMethods_DefaultsToBasic(t *testing.T) {
	methods := []string{"private_key_jwt", "tls_client_auth"}
	assert.Equal(t, AuthMethodClientSecretBasic, SelectAuthMethod("secret", methods))
}

// TestApplyAuthToForm_None verifies that the "none" method puts client_id in
// the form body without any client_secret.
func TestApplyAuthToForm_None(t *testing.T) {
	data := url.Values{}
	applyAuthToForm(AuthMethodNone, "my-client", "", data)
	assert.Equal(t, "my-client", data.Get("client_id"))
	assert.Empty(t, data.Get("client_secret"))
}

// TestApplyAuthToForm_Post verifies that client_secret_post puts both client_id
// and client_secret in the form body.
func TestApplyAuthToForm_Post(t *testing.T) {
	data := url.Values{}
	applyAuthToForm(AuthMethodClientSecretPost, "my-client", "my-secret", data)
	assert.Equal(t, "my-client", data.Get("client_id"))
	assert.Equal(t, "my-secret", data.Get("client_secret"))
}

// TestApplyAuthToForm_Basic verifies that client_secret_basic does NOT put
// credentials in the form body (they go in the Authorization header instead).
func TestApplyAuthToForm_Basic(t *testing.T) {
	data := url.Values{}
	applyAuthToForm(AuthMethodClientSecretBasic, "my-client", "my-secret", data)
	assert.Empty(t, data.Get("client_id"), "basic auth should not put client_id in body")
	assert.Empty(t, data.Get("client_secret"), "basic auth should not put secret in body")
}
