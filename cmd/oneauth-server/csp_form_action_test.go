package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The server's CSP has no form-action. Chrome applies form-action to every
// redirect a form submission causes, and both the consent Approve POST and
// the login POST (via /authorize) end in a redirect to the client's
// redirect_uri, on another origin. With form-action 'self', a real browser
// could never finish an authorization; the OIDF harness drives one that
// ignores CSP, so only the OAuch run found it (issue 497). form-action
// doesn't fall back to default-src, so leaving it out allows the redirect.
//
// See: https://www.w3.org/TR/CSP3/#directive-form-action
// See: https://github.com/panyam/oneauth/issues/497
func TestServerCSP_AllowsTheRedirectAfterAForm(t *testing.T) {
	assert.False(t, strings.Contains(serverCSP, "form-action"), serverCSP)
	assert.Contains(t, serverCSP, "frame-ancestors 'none'", "clickjacking protection stays")
	assert.Contains(t, serverCSP, "default-src 'self'")
}
