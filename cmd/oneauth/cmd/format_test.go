package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/panyam/oneauth/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmit_JSON_RoundTrips — the json formatter emits the exact wire
// shape an OAuth 2.0 client expects per RFC 6749 §5.1, plus the
// CLI-only `issuer` field. expires_in is derived from ExpiresAt and
// `now` so callers get a fresh remaining-seconds value at print time.
func TestEmit_JSON_RoundTrips(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cred := &client.ServerCredential{
		AccessToken:  "AT",
		RefreshToken: "RT",
		TokenType:    "Bearer",
		Scope:        "read write",
		ExpiresAt:    now.Add(1800 * time.Second),
	}

	var buf bytes.Buffer
	require.NoError(t, emit(&buf, "json", cred, "https://issuer.example.com", now))

	var got tokenOutput
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, tokenOutput{
		AccessToken:  "AT",
		RefreshToken: "RT",
		ExpiresIn:    1800,
		TokenType:    "Bearer",
		Scope:        "read write",
		Issuer:       "https://issuer.example.com",
	}, got)
}

// TestEmit_JSON_DefaultsBearer — token_type defaults to "Bearer" when
// the AS omits it, matching the implicit OAuth 2.0 default.
func TestEmit_JSON_DefaultsBearer(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, emit(&buf, "json", &client.ServerCredential{AccessToken: "AT"}, "", time.Now()))
	var got tokenOutput
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, "Bearer", got.TokenType)
}

// TestEmit_Bash_Sourceable — bash format emits sourceable `export …=…`
// lines for each non-empty field. Single-quote escaping preserves
// special characters so `eval "$(oneauth ...)"` drops the values into
// the calling shell unchanged.
func TestEmit_Bash_Sourceable(t *testing.T) {
	expiry := time.Unix(1_700_001_800, 0)
	cred := &client.ServerCredential{
		AccessToken:  "AT-value",
		RefreshToken: "RT-value",
		ExpiresAt:    expiry,
	}
	var buf bytes.Buffer
	require.NoError(t, emit(&buf, "bash", cred, "https://issuer.example.com", time.Now()))
	out := buf.String()
	assert.Contains(t, out, "export OAUTH_ACCESS_TOKEN='AT-value'\n")
	assert.Contains(t, out, "export OAUTH_REFRESH_TOKEN='RT-value'\n")
	assert.Contains(t, out, "export OAUTH_EXPIRES_AT=1700001800\n")
	assert.Contains(t, out, "export OAUTH_ISSUER='https://issuer.example.com'\n")
}

// TestEmit_Bash_QuoteEscaped — the bash formatter survives single
// quotes inside the secret: the shell idiom `'\''` (close, escaped,
// reopen) is the only safe way to embed a `'` in a single-quoted shell
// literal.
func TestEmit_Bash_QuoteEscaped(t *testing.T) {
	cred := &client.ServerCredential{AccessToken: `it's-mine`}
	var buf bytes.Buffer
	require.NoError(t, emit(&buf, "bash", cred, "", time.Now()))
	assert.Equal(t, `export OAUTH_ACCESS_TOKEN='it'\''s-mine'`+"\n", buf.String())
}

// TestEmit_AccessTokenOnly — emits the bare token without a trailing
// newline so `$(oneauth ...)` doesn't smuggle one into shell contexts.
func TestEmit_AccessTokenOnly(t *testing.T) {
	cred := &client.ServerCredential{AccessToken: "AT"}
	var buf bytes.Buffer
	require.NoError(t, emit(&buf, "access-token-only", cred, "", time.Now()))
	assert.Equal(t, "AT", buf.String())
	assert.False(t, strings.HasSuffix(buf.String(), "\n"))
}

// TestEmit_UnknownFormat_Errors — unknown formats surface a typed
// error instead of falling through to a default.
func TestEmit_UnknownFormat_Errors(t *testing.T) {
	err := emit(&bytes.Buffer{}, "yaml", &client.ServerCredential{}, "", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
}

// TestExpiresIn_ExpiredCredential — a credential that's already past
// its expiry yields 0, not a negative seconds value.
func TestExpiresIn_ExpiredCredential(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cred := &client.ServerCredential{ExpiresAt: now.Add(-1 * time.Second)}
	assert.Equal(t, int64(0), expiresInFromCredential(cred, now))
}
