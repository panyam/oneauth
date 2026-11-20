package core

import "strings"

// OAuthErrorDescription maps a human-readable error description into the
// character set RFC 6749 allows for error_description (§4.1.2.1, §5.2;
// RFC 6750 §3 and RFC 7591 §3.2.2 reuse it): printable ASCII without `"`
// or `\`. Writers of OAuth error responses pass every description through
// it, so a message may cite "RFC 6749 §3.2" or quote a value with %q and
// still reach the client in a form a strict client accepts (issue 526).
//
// "§" becomes "section ", `"` becomes `'`, `\` becomes `/`, and
// whitespace becomes a space. Any other character outside the set, such
// as a non-ASCII letter, becomes "?".
func OAuthErrorDescription(s string) string {
	s = strings.ReplaceAll(s, "§ ", "section ")
	s = strings.ReplaceAll(s, "§", "section ")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteByte('\'')
		case r == '\\':
			b.WriteByte('/')
		case r == '\t' || r == '\n' || r == '\r':
			b.WriteByte(' ')
		case r >= 0x20 && r <= 0x7E:
			b.WriteRune(r)
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}
