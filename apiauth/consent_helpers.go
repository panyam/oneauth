package apiauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/panyam/oneauth/core"
)

// loginURLWithNext composes the URL to which a consent-flow handler
// redirects an unauthenticated user. The login page is expected to
// honor the supplied query parameter as a return-here-after hint.
//
// loginURL is the absolute or path-relative login URL. Empty defaults
// to "/auth/login" (the convention used elsewhere in the library).
// nextParam is the query parameter name carrying the return URL.
// Empty defaults to "next". next is the URL to return to after a
// successful login; the caller must compose it (it is URL-escaped here
// but otherwise opaque to the helper).
//
// Shared between DeviceVerificationHandler (RFC 8628 §3.3 consent UI)
// and AuthorizationHandler / AuthorizeVerificationHandler (RFC 6749
// §4.1 consent UI). Extracted because the `?` vs `&` separator dance is
// easy to get wrong inline.
func loginURLWithNext(loginURL, nextParam, next string) string {
	if loginURL == "" {
		loginURL = "/auth/login"
	}
	if nextParam == "" {
		nextParam = "next"
	}
	sep := "?"
	if strings.Contains(loginURL, "?") {
		sep = "&"
	}
	return fmt.Sprintf("%s%s%s=%s", loginURL, sep, nextParam, url.QueryEscape(next))
}

// lookupClientName returns the human-readable `client_name` for the
// given clientID, suitable for rendering on a consent screen. Falls
// back to clientID when store is nil, the clientID is empty, the
// lookup errors, or the registered app has no client_name.
//
// Shared between DeviceVerificationHandler.Consent and the
// authorize-flow consent screen so the fallback contract stays
// uniform: a consent screen NEVER fails to render because the AppStore
// is unreachable — it just shows the raw client_id.
func lookupClientName(ctx context.Context, store core.AppRegistrationStore, clientID string) string {
	if store == nil || clientID == "" {
		return clientID
	}
	resp, err := store.GetApp(ctx, &core.GetAppRequest{ClientID: clientID})
	if err != nil || resp == nil || resp.App == nil || resp.App.ClientName == "" {
		return clientID
	}
	return resp.App.ClientName
}

// lookupClientDisplayURIs returns the client's registered logo_uri,
// policy_uri and tos_uri, or empty strings when the client or store is
// missing. Registration accepts only https URLs for these (issue 507), so
// the consent page can put them in an <img src> and two links.
func lookupClientDisplayURIs(ctx context.Context, store core.AppRegistrationStore, clientID string) (logo, policy, tos string) {
	if store == nil || clientID == "" {
		return "", "", ""
	}
	resp, err := store.GetApp(ctx, &core.GetAppRequest{ClientID: clientID})
	if err != nil || resp == nil || resp.App == nil {
		return "", "", ""
	}
	return httpsOnly(resp.App.LogoURI), httpsOnly(resp.App.PolicyURI), httpsOnly(resp.App.TOSURI)
}

// httpsOnly returns raw if it is an absolute https URL, else "". It guards
// the consent page against a registration stored before validation existed.
func httpsOnly(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	return raw
}

// allowImageOrigin adds logoURI's origin to the img-src directive of the
// response's Content-Security-Policy, so the client's logo loads on the
// consent page and nothing else does. A policy without img-src gets one
// copied from default-src. A response without a policy, or a policy that
// restricts neither, already allows the image and is left alone.
func allowImageOrigin(h http.Header, logoURI string) {
	csp := h.Get("Content-Security-Policy")
	u, err := url.Parse(logoURI)
	if csp == "" || err != nil || u.Host == "" {
		return
	}
	origin := u.Scheme + "://" + u.Host
	directives := strings.Split(csp, ";")
	defaultSrc := ""
	for i, d := range directives {
		name, value, _ := strings.Cut(strings.TrimSpace(d), " ")
		switch name {
		case "img-src":
			directives[i] = " img-src " + strings.TrimSpace(value) + " " + origin
			h.Set("Content-Security-Policy", strings.TrimSpace(strings.Join(directives, ";")))
			return
		case "default-src":
			defaultSrc = strings.TrimSpace(value)
		}
	}
	if defaultSrc == "" {
		return
	}
	h.Set("Content-Security-Policy", strings.TrimSpace(csp)+"; img-src "+defaultSrc+" "+origin)
}
