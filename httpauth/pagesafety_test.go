package httpauth_test

// See: https://cwe.mitre.org/data/definitions/601.html

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/panyam/oneauth/httpauth"
)

func TestLocalRedirect(t *testing.T) {
	for target, want := range map[string]string{
		"/":                    "/",
		"/dashboard?tab=apps":  "/dashboard?tab=apps",
		"":                     "/fallback",
		"dashboard":            "/fallback",
		"https://evil.example": "/fallback",
		"//evil.example":       "/fallback",
		"/\\evil.example":      "/fallback",
		"javascript:alert(1)":  "/fallback",
		"http:/evil.example":   "/fallback",
		"/ok/../still-local":   "/ok/../still-local",
	} {
		assert.Equal(t, want, httpauth.LocalRedirect(target, "/fallback"), target)
	}
}

func TestCallbackURL(t *testing.T) {
	cases := []struct {
		name, query, form, want string
	}{
		{name: "query", query: "/notations/x/compose", want: "/notations/x/compose"},
		{name: "form", form: "/notations/x/compose?tab=1", want: "/notations/x/compose?tab=1"},
		{name: "query wins over form", query: "/a", form: "/b", want: "/a"},
		{name: "off-site", query: "https://evil.example/", want: ""},
		{name: "protocol-relative", form: "//evil.example/", want: ""},
		{name: "none", want: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target := "/login"
			if c.query != "" {
				target += "?callbackURL=" + url.QueryEscape(c.query)
			}
			body := url.Values{}
			if c.form != "" {
				body.Set("callbackURL", c.form)
			}
			req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			assert.Equal(t, c.want, httpauth.CallbackURL(req))
		})
	}
}
