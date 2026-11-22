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

	// HostedDomains matches Google's `hd` claim exactly and
	// case-insensitively. Google sets `hd` only on a Workspace account,
	// so it admits Workspace accounts in the domain and refuses a
	// consumer Gmail account even when its email is in the domain.
	HostedDomains []string
}

// Rule names the AllowList rule that admitted a person.
type Rule string

// The rules a Decision can name.
const (
	RuleSubject      Rule = "subject"
	RuleEmailDomain  Rule = "email_domain"
	RuleHostedDomain Rule = "hosted_domain"
	RuleGroup        Rule = "group"
)

// Decision is the outcome of checking one person against an AllowList.
type Decision struct {
	// Allowed reports whether at least one rule matched.
	Allowed bool

	// Rule is the first rule that matched, checked in the order subject,
	// email domain, hosted domain, group. It is empty when Allowed is
	// false.
	Rule Rule

	// GroupsOverage reports that the provider left the groups claim out
	// because the person is in too many groups. Entra ID does this past
	// 200 groups in an ID token, and names the claim in `_claim_names`
	// instead. A Groups rule can't match until the groups are fetched, so
	// a refusal with GroupsOverage set means "unknown", not "not a
	// member". Resolve fetches them.
	GroupsOverage bool
}

// Allows reports whether claims satisfy at least one rule. It is
// Decide(claims).Allowed.
func (a AllowList) Allows(claims map[string]any) bool {
	return a.Decide(claims).Allowed
}

// Decide checks claims against every rule and reports which one matched,
// and whether the groups claim was left out for overage. GroupsOverage is
// set whether or not another rule matched, so an app can log it either
// way.
func (a AllowList) Decide(claims map[string]any) Decision {
	d := Decision{GroupsOverage: a.groupsOverage(claims)}
	switch {
	case a.subjectAllowed(claims):
		d.Rule = RuleSubject
	case len(a.EmailDomains) > 0 && a.emailAllowed(claims):
		d.Rule = RuleEmailDomain
	case a.hostedDomainAllowed(claims):
		d.Rule = RuleHostedDomain
	case len(a.Groups) > 0 && a.groupsMatch(claims[a.groupsClaim()]):
		d.Rule = RuleGroup
	}
	d.Allowed = d.Rule != ""
	return d
}

func (a AllowList) groupsClaim() string {
	if a.GroupsClaim == "" {
		return "groups"
	}
	return a.GroupsClaim
}

func (a AllowList) subjectAllowed(claims map[string]any) bool {
	sub, _ := claims["sub"].(string)
	return sub != "" && slices.Contains(a.Subjects, sub)
}

func (a AllowList) hostedDomainAllowed(claims map[string]any) bool {
	hd, _ := claims["hd"].(string)
	if hd == "" {
		return false
	}
	for _, d := range a.HostedDomains {
		if strings.EqualFold(d, hd) {
			return true
		}
	}
	return false
}

func (a AllowList) groupsMatch(groups any) bool {
	switch g := groups.(type) {
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
	return false
}

// groupsOverage reports an OIDC Core §5.6.2 distributed claim standing in
// for the groups claim: the claim itself is absent and `_claim_names`
// names it.
func (a AllowList) groupsOverage(claims map[string]any) bool {
	name := a.groupsClaim()
	if _, present := claims[name]; present {
		return false
	}
	names, _ := claims["_claim_names"].(map[string]any)
	_, named := names[name]
	return named
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
