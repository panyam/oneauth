package oidc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/panyam/oneauth/oauth2/oidc"
)

func TestAllowList(t *testing.T) {
	ada := map[string]any{"sub": "user-42", "email": "ada@Example.com", "email_verified": true, "groups": []any{"eng", "ops"}}
	unverified := map[string]any{"sub": "user-7", "email": "bob@example.com"}
	stringVerified := map[string]any{"email": "cy@example.com", "email_verified": "true"}
	falseVerified := map[string]any{"email": "dee@example.com", "email_verified": false}
	roles := map[string]any{"roles": "admin"}

	for name, tc := range map[string]struct {
		list   oidc.AllowList
		claims map[string]any
		want   bool
	}{
		"empty list allows nobody":            {list: oidc.AllowList{}, claims: ada, want: false},
		"domain match, case-insensitive":      {list: oidc.AllowList{EmailDomains: []string{"example.com"}}, claims: ada, want: true},
		"subdomain does not match":            {list: oidc.AllowList{EmailDomains: []string{"sub.example.com"}}, claims: ada, want: false},
		"parent domain does not match":        {list: oidc.AllowList{EmailDomains: []string{"com"}}, claims: ada, want: false},
		"unverified email refused":            {list: oidc.AllowList{EmailDomains: []string{"example.com"}}, claims: unverified, want: false},
		"email_verified false refused":        {list: oidc.AllowList{EmailDomains: []string{"example.com"}}, claims: falseVerified, want: false},
		"email_verified string true accepted": {list: oidc.AllowList{EmailDomains: []string{"example.com"}}, claims: stringVerified, want: true},
		"unverified allowed when opted in":    {list: oidc.AllowList{EmailDomains: []string{"example.com"}, AllowUnverifiedEmail: true}, claims: unverified, want: true},
		"group match":                         {list: oidc.AllowList{Groups: []string{"ops"}}, claims: ada, want: true},
		"group miss":                          {list: oidc.AllowList{Groups: []string{"finance"}}, claims: ada, want: false},
		"custom groups claim as string":       {list: oidc.AllowList{Groups: []string{"admin"}, GroupsClaim: "roles"}, claims: roles, want: true},
		"subject match":                       {list: oidc.AllowList{Subjects: []string{"user-7"}}, claims: unverified, want: true},
		"any rule suffices":                   {list: oidc.AllowList{Subjects: []string{"nobody"}, Groups: []string{"eng"}}, claims: ada, want: true},
		"malformed email":                     {list: oidc.AllowList{EmailDomains: []string{"example.com"}, AllowUnverifiedEmail: true}, claims: map[string]any{"email": "example.com"}, want: false},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.list.Allows(tc.claims))
		})
	}
}
