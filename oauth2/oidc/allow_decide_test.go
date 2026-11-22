// Tests for AllowList.Decide: Google's hd claim, the matched rule, and
// Entra's groups overage (issue 555).
package oidc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/panyam/oneauth/oauth2/oidc"
)

// See: https://developers.google.com/identity/openid-connect/openid-connect#an-id-tokens-payload
func TestAllowList_HostedDomain(t *testing.T) {
	workspace := map[string]any{"sub": "g-1", "email": "ada@example.com", "email_verified": true, "hd": "example.com"}
	gmail := map[string]any{"sub": "g-2", "email": "ada@gmail.com", "email_verified": true}
	list := oidc.AllowList{HostedDomains: []string{"Example.com"}}

	for name, tc := range map[string]struct {
		claims map[string]any
		want   bool
	}{
		"hd matches, case-insensitive": {claims: workspace, want: true},
		"no hd claim":                  {claims: gmail, want: false},
		"hd is another domain":         {claims: map[string]any{"hd": "example.org"}, want: false},
		"hd subdomain does not match":  {claims: map[string]any{"hd": "eng.example.com"}, want: false},
		"hd not a string":              {claims: map[string]any{"hd": true}, want: false},
	} {
		t.Run(name, func(t *testing.T) {
			d := list.Decide(tc.claims)
			assert.Equal(t, tc.want, d.Allowed)
			assert.Equal(t, tc.want, list.Allows(tc.claims))
			if tc.want {
				assert.Equal(t, oidc.RuleHostedDomain, d.Rule)
			} else {
				assert.Empty(t, d.Rule)
			}
		})
	}
}

func TestAllowList_DecideNamesTheRule(t *testing.T) {
	claims := map[string]any{"sub": "u-1", "email": "ada@example.com", "email_verified": true, "hd": "example.com", "groups": []any{"eng"}}
	for name, tc := range map[string]struct {
		list oidc.AllowList
		want oidc.Rule
	}{
		"subject":       {list: oidc.AllowList{Subjects: []string{"u-1"}}, want: oidc.RuleSubject},
		"email domain":  {list: oidc.AllowList{EmailDomains: []string{"example.com"}}, want: oidc.RuleEmailDomain},
		"hosted domain": {list: oidc.AllowList{HostedDomains: []string{"example.com"}}, want: oidc.RuleHostedDomain},
		"group":         {list: oidc.AllowList{Groups: []string{"eng"}}, want: oidc.RuleGroup},
		"subject first": {list: oidc.AllowList{Groups: []string{"eng"}, Subjects: []string{"u-1"}}, want: oidc.RuleSubject},
	} {
		t.Run(name, func(t *testing.T) {
			d := tc.list.Decide(claims)
			assert.True(t, d.Allowed)
			assert.Equal(t, tc.want, d.Rule)
		})
	}
}

// Entra ID replaces the groups claim with a distributed claim (OIDC Core
// §5.6.2) once a person is in more than 200 groups.
// See: https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference#groups-overage-claim
func TestAllowList_GroupsOverage(t *testing.T) {
	overage := map[string]any{
		"sub":            "u-1",
		"_claim_names":   map[string]any{"groups": "src1"},
		"_claim_sources": map[string]any{"src1": map[string]any{"endpoint": "https://graph.windows.net/t/users/u-1/getMemberObjects"}},
	}
	roleOverage := map[string]any{"_claim_names": map[string]any{"roles": "src1"}}
	withGroups := map[string]any{"groups": []any{"eng"}, "_claim_names": map[string]any{"groups": "src1"}}
	otherClaimNamed := map[string]any{"_claim_names": map[string]any{"address": "src1"}}

	for name, tc := range map[string]struct {
		list        oidc.AllowList
		claims      map[string]any
		wantAllowed bool
		wantOverage bool
	}{
		"overage refuses and says why":       {list: oidc.AllowList{Groups: []string{"eng"}}, claims: overage, wantOverage: true},
		"overage on a custom groups claim":   {list: oidc.AllowList{Groups: []string{"admin"}, GroupsClaim: "roles"}, claims: roleOverage, wantOverage: true},
		"claim present is not overage":       {list: oidc.AllowList{Groups: []string{"eng"}}, claims: withGroups, wantAllowed: true},
		"another claim named is not overage": {list: oidc.AllowList{Groups: []string{"eng"}}, claims: otherClaimNamed},
		"plain absence is not overage":       {list: oidc.AllowList{Groups: []string{"eng"}}, claims: map[string]any{"sub": "u-1"}},
		"reported when another rule admits":  {list: oidc.AllowList{Subjects: []string{"u-1"}}, claims: overage, wantAllowed: true, wantOverage: true},
	} {
		t.Run(name, func(t *testing.T) {
			d := tc.list.Decide(tc.claims)
			assert.Equal(t, tc.wantAllowed, d.Allowed)
			assert.Equal(t, tc.wantOverage, d.GroupsOverage)
		})
	}
}
