package oidfplan

// User is the account the browser automation logs in as.
type User struct {
	Email    string
	Password string
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
