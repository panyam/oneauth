package httpauth

import (
	"net/http"
	"net/url"
	"strings"
)

// DenyFraming stops a browser from rendering the response inside another
// site's frame, which is how a clickjacking page tricks a signed-in user
// into clicking "Approve" (RFC 6749 §10.13, CWE-1021). It always sets
// X-Frame-Options: DENY, and adds a Content-Security-Policy of
// frame-ancestors 'none' only when the response has no policy yet, so a
// deployment's own CSP (from SecurityHeaders or its middleware) is kept.
//
// Call it before writing the body of any page that asks the user to act:
// consent, login, password and device-code forms.
func DenyFraming(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Frame-Options", "DENY")
	if h.Get("Content-Security-Policy") == "" {
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
	}
}

// LocalRedirect returns target when it is a path on this site, and
// fallback otherwise. Use it for any redirect whose destination came from
// the request (a ?to= or ?next= parameter, a callback cookie), or the
// endpoint becomes an open redirect (CWE-601).
//
// A local path starts with a single "/" and has no scheme or host:
// "/dashboard?tab=x" is local, while "https://evil.example",
// "//evil.example" and "/\evil.example" (which browsers treat as
// protocol-relative) are not.
func LocalRedirect(target, fallback string) string {
	if target == "" || !strings.HasPrefix(target, "/") ||
		strings.HasPrefix(target, "//") || strings.HasPrefix(target, "/\\") {
		return fallback
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return fallback
	}
	// Rebuilt from the parsed path, query and fragment, so nothing that
	// names a host can survive into the Location header.
	return (&url.URL{Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery, Fragment: u.Fragment}).String()
}

// CallbackURL returns the callbackURL a login or signup request carries, from
// the query string or a posted form, when it is a path on this site. It
// returns "" when there is none or it points off-site (see LocalRedirect).
//
// A login page that receives ?callbackURL= posts it back with the form, so the
// handler that finishes the login can send the user to where they started.
// The OAuth flow keeps the same value in the oauthCallbackURL cookie instead.
// An app's login error handler can use it to keep the value when it redirects
// back to the login page.
func CallbackURL(r *http.Request) string {
	target := r.URL.Query().Get("callbackURL")
	if target == "" {
		target = r.PostFormValue("callbackURL")
	}
	return LocalRedirect(target, "")
}
