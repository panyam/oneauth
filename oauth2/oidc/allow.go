package oidc

import (
	"slices"
	"strings"
)

// AllowList decides who may sign in, from the claims of a verified ID
// token. A person is allowed when any one rule matches. With no rules set
// it allows nobody, so an empty list fails closed.
type AllowList struct {
	// EmailDomains matches the domain of the `email` claim exactly and
	// case-insensitively ("example.com" doesn't match "sub.example.com").
	// The email counts only when `email_verified` is true, unless
	// AllowUnverifiedEmail is set.
	EmailDomains []string

	// AllowUnverifiedEmail accepts an email without `email_verified`.
	// Set it only for a provider that controls every address in the
	// domain and omits the claim, as Entra ID does for work accounts.
	AllowUnverifiedEmail bool

	// Groups matches any value in the GroupsClaim claim, which may be a
	// string or an array of strings.
	Groups []string

	// GroupsClaim names the claim Groups reads. Default "groups".
	GroupsClaim string

	// Subjects matches the `sub` claim exactly. `sub` is unique only
	// within one issuer, so use it with one Provider.
	Subjects []string
}

// Allows reports whether claims satisfy at least one rule.
func (a AllowList) Allows(claims map[string]any) bool {
	if sub, _ := claims["sub"].(string); sub != "" && slices.Contains(a.Subjects, sub) {
		return true
	}
	if len(a.EmailDomains) > 0 && a.emailAllowed(claims) {
		return true
	}
	if len(a.Groups) > 0 {
		name := a.GroupsClaim
		if name == "" {
			name = "groups"
		}
		switch g := claims[name].(type) {
		case string:
			return slices.Contains(a.Groups, g)
		case []any:
			for _, v := range g {
				if s, ok := v.(string); ok && slices.Contains(a.Groups, s) {
					return true
				}
			}
		case []string:
			for _, s := range g {
				if slices.Contains(a.Groups, s) {
					return true
				}
			}
		}
	}
	return false
}

func (a AllowList) emailAllowed(claims map[string]any) bool {
	email, _ := claims["email"].(string)
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return false
	}
	if !a.AllowUnverifiedEmail {
		// Some providers (AWS Cognito among them) send the string "true".
		switch v := claims["email_verified"].(type) {
		case bool:
			if !v {
				return false
			}
		case string:
			if v != "true" {
				return false
			}
		default:
			return false
		}
	}
	domain := email[at+1:]
	for _, d := range a.EmailDomains {
		if strings.EqualFold(d, domain) {
			return true
		}
	}
	return false
}
