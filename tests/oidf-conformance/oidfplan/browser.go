package oidfplan

import "net/url"

// User is the account the browser automation logs in as.
type User struct {
	Email    string
	Password string

	// Profile holds extra signup form fields, such as the standard OIDC
	// profile claims a plan's server accepts at signup. Nil sends none.
	Profile url.Values
}

// BrowserTask is one harness browser-automation entry: when the harness's
// headless browser is sent to a URL matching Match, it runs Tasks in order.
// The harness uses the first entry that matches. MatchLimit, when set, is how
// many visits the entry handles before the harness moves on to the next
// match.
type BrowserTask struct {
	Match      string        `json:"match"`
	MatchLimit int           `json:"match-limit,omitempty"`
	Tasks      []BrowserStep `json:"tasks"`
}

// BrowserStep runs Commands when the current page matches Match. Each
// command is the harness's [action, locator type, locator, value...] form.
type BrowserStep struct {
	Task     string  `json:"task"`
	Match    string  `json:"match"`
	Optional bool    `json:"optional,omitempty"`
	Commands [][]any `json:"commands"`
}

// LoginStep fills in oneauth's login form at issuer as u. It is optional,
// because the browser may already have a session.
func LoginStep(issuer string, u User) BrowserStep {
	return BrowserStep{Task: "Login", Match: issuer + "/auth/login*", Optional: true, Commands: [][]any{
		{"text", "name", "username", u.Email},
		{"text", "name", "password", u.Password},
		{"click", "xpath", "//button[@type='submit']"},
	}}
}

// ConsentStep clicks the button with the given value, approve or deny, on
// oneauth's consent page at issuer.
func ConsentStep(issuer, action string) BrowserStep {
	return BrowserStep{Task: "Consent", Match: issuer + "/authorize*", Commands: [][]any{
		{"click", "xpath", "//button[@value='" + action + "']"},
	}}
}

// CallbackStep waits for the harness callback page to report the
// authorization response submitted.
func CallbackStep() BrowserStep {
	return BrowserStep{Task: "Verify Complete", Match: "*/test/*/callback*", Commands: [][]any{
		{"wait", "id", "submission_complete", 10},
	}}
}

// ProfileClaims are the standard OIDC profile claims StandardProfile
// fills, which a plan's server config lists under signup.profile_claims.
var ProfileClaims = []string{"name", "given_name", "family_name", "middle_name", "nickname", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "address"}

// StandardProfile is signup form fields that give a user every claim the
// profile, address and phone scopes grant that a user can give at signup,
// plus a username for preferred_username. The modules that ask for claims
// by scope or by name then find them. updated_at is the one standard
// profile claim missing, since oneauth's user records don't expose it
// (issue 480).
func StandardProfile() url.Values {
	return url.Values{
		"username":    {"olive-doe"},
		"phone":       {"+15555550123"},
		"name":        {"Olive Ida Doe"},
		"given_name":  {"Olive"},
		"family_name": {"Doe"},
		"middle_name": {"Ida"},
		"nickname":    {"oli"},
		"profile":     {"https://example.com/oli"},
		"picture":     {"https://example.com/oli.png"},
		"website":     {"https://oli.example.com"},
		"gender":      {"female"},
		"birthdate":   {"1990-04-01"},
		"zoneinfo":    {"Europe/London"},
		"locale":      {"en-GB"},
		"address":     {"1 Example Street, London"},
	}
}
