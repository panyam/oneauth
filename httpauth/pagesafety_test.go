package httpauth_test

// See: https://cwe.mitre.org/data/definitions/601.html

import (
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
