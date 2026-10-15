package client

import (
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
)

var (
	consentFormRe   = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	consentActionRe = regexp.MustCompile(`(?i)\baction\s*=\s*"([^"]*)"`)
	consentFieldRe  = regexp.MustCompile(`(?is)<(input|button)\b([^>]*)>`)
	consentAttrRe   = regexp.MustCompile(`(?i)\b(name|value|type)\s*=\s*"([^"]*)"`)
	consentApproves = []string{"approve", "allow", "accept", "authorize", "consent", "yes"}
)

// ApproveConsent returns an OpenBrowser function that walks an authorization
// request the way a user clicking Approve would. It is meant for demo and
// test authorization servers that answer /authorize with a consent page
// instead of redirecting, where FollowRedirects would stop at the page.
//
// Redirects are followed with a cookie jar, since consent forms usually key
// on a session; if httpClient has no Jar, a copy of it gets one and the
// caller's client is left untouched. A server that redirects straight to the
// redirect_uri completes on the GET. Otherwise the first <form> on the page
// is posted with its inputs as served plus the one submit button whose value
// reads as approval ("approve", "allow", "accept", "authorize", "consent",
// "yes"). A form with no such button is refused rather than guessed at, so a
// login page asking for a password is never submitted.
//
// Error statuses fail fast the same way FollowRedirects does. Pages are
// scanned with regular expressions, not an HTML parser: this handles the
// plain consent forms demo servers serve, not arbitrary login UIs.
//
// See: https://github.com/panyam/oneauth/issues/387
func ApproveConsent(httpClient *http.Client) func(string) error {
	hc := &http.Client{}
	if httpClient != nil {
		copied := *httpClient
		hc = &copied
	}
	if hc.Jar == nil {
		jar, _ := cookiejar.New(nil)
		hc.Jar = jar
	}
	return func(authURL string) error {
		redirect := redirectOf(authURL)
		if redirect == "" {
			return errors.New("authorization URL carries no redirect_uri")
		}
		resp, err := hc.Get(authURL)
		if err != nil {
			return fmt.Errorf("headless consent failed: %w", err)
		}
		defer resp.Body.Close()
		if reachedRedirect(resp, redirect) {
			return nil
		}
		if resp.StatusCode >= 400 {
			return authorizeError(resp)
		}
		page, _ := io.ReadAll(resp.Body)

		action, values, err := approveForm(resp.Request.URL, page)
		if err != nil {
			return fmt.Errorf("authorization page (%s): %w", resp.Status, err)
		}
		post, err := hc.PostForm(action.String(), values)
		if err != nil {
			return fmt.Errorf("headless consent failed: %w", err)
		}
		defer post.Body.Close()
		if reachedRedirect(post, redirect) {
			return nil
		}
		if post.StatusCode >= 400 {
			return authorizeError(post)
		}
		return fmt.Errorf("approving the consent form ended at %s (%s), not the redirect_uri", post.Request.URL.Redacted(), post.Status)
	}
}

// approveForm extracts the first form on page and the values to post with
// approval selected. The form's action resolves against base.
func approveForm(base *url.URL, page []byte) (*url.URL, url.Values, error) {
	form := consentFormRe.FindSubmatch(page)
	if form == nil {
		return nil, nil, errors.New("no form to approve and no redirect")
	}
	action := base
	if m := consentActionRe.FindSubmatch(form[1]); m != nil {
		var err error
		if action, err = base.Parse(html.UnescapeString(string(m[1]))); err != nil {
			return nil, nil, err
		}
	}
	values := url.Values{}
	approved := false
	for _, f := range consentFieldRe.FindAllSubmatch(form[2], -1) {
		attrs := map[string]string{}
		for _, a := range consentAttrRe.FindAllSubmatch(f[2], -1) {
			attrs[strings.ToLower(string(a[1]))] = html.UnescapeString(string(a[2]))
		}
		name := attrs["name"]
		if name == "" {
			continue
		}
		if !strings.EqualFold(string(f[1]), "button") && attrs["type"] != "submit" {
			values.Set(name, attrs["value"])
			continue
		}
		for _, a := range consentApproves {
			if !approved && strings.EqualFold(attrs["value"], a) {
				values.Set(name, attrs["value"])
				approved = true
			}
		}
	}
	if !approved {
		return nil, nil, errors.New("authorization form has no approve button")
	}
	return action, values, nil
}
