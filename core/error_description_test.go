package core

import "testing"

// See: https://www.rfc-editor.org/rfc/rfc6749#section-5.2
func TestOAuthErrorDescription(t *testing.T) {
	for in, want := range map[string]string{
		"plain text":            "plain text",
		"see RFC 6749 §3.2":     "see RFC 6749 section 3.2",
		"§§5":                   "section section 5",
		`unknown client "x\y"`:  "unknown client 'x/y'",
		"two\nlines\tand\rmore": "two lines and more",
		"café — 日":              "caf? ? ?",
		"":                      "",
	} {
		if got := OAuthErrorDescription(in); got != want {
			t.Errorf("OAuthErrorDescription(%q) = %q, want %q", in, got, want)
		}
	}
}
