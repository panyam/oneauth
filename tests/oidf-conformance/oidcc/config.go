// Package oidcc defines the OpenID Foundation's OpenID Connect Basic OP
// certification plan (oidcc-basic-certification-test-plan) as oneauth runs
// it: the clients it registers, the variant, the plan config and the browser
// automation. oidfplan runs it. It is the exercise of mission 477, "an OIDC
// relying party passes the OIDF Basic OP plan against oneauth".
//
// The plan config here is pure (PlanConfig, BrowserAutomation, ...); the
// network side is in run.go.
package oidcc

import (
	"fmt"

	"github.com/panyam/oneauth/tests/oidf-conformance/oidfplan"
)

// PlanName is the harness plan this exercise runs.
const PlanName = "oidcc-basic-certification-test-plan"

// ModulePrefix starts every module name in the plan; the exercise prints
// names without it.
const ModulePrefix = "oidcc-"

// Client is a confidential client registered with oneauth through DCR. The
// harness authenticates as it with its secret.
type Client struct {
	ID     string
	Secret string
}

// Setup is everything the plan config needs.
type Setup struct {
	// Alias names the plan in the harness and forms its redirect URI.
	Alias string
	// HarnessURL is the harness origin the redirect URI points at.
	HarnessURL string
	// IssuerURL is oneauth's public URL as the harness container reaches it
	// (https://host.docker.internal:<port>), which is also the token issuer.
	IssuerURL string
	// Scope is registered for every client. The plan's modules ask for
	// their own scopes within it.
	Scope string
	// Clients are the plan's "client" and "client2", both using
	// client_secret_basic.
	Clients [2]Client
	// PostClient is the plan's "client_secret_post" client, which the
	// oidcc-server-client-secret-post module authenticates with.
	PostClient Client
	User       oidfplan.User
}

// PlanVariant is the Basic OP profile as oneauth implements it: the plan
// reads oneauth's discovery document, and uses clients registered up front
// (static_client) rather than registering its own.
func PlanVariant() map[string]string {
	return map[string]string{
		"server_metadata":     "discovery",
		"client_registration": "static_client",
	}
}

// RedirectURI is where the harness receives authorization responses for a
// plan with this alias.
func RedirectURI(harnessURL, alias string) string {
	return fmt.Sprintf("%s/test/a/%s/callback", harnessURL, alias)
}

// RegistrationRequest is the RFC 7591 body that registers one test client:
// confidential, with the given token endpoint auth method
// (client_secret_basic or client_secret_post), for the code grant.
func RegistrationRequest(authMethod, redirectURI, scope string) map[string]any {
	return map[string]any{
		"client_name":                "oidf-oidcc-" + authMethod,
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": authMethod,
		"scope":                      scope,
	}
}

// BrowserAutomation logs in on oneauth's login page, approves on its consent
// page, and waits for the harness callback to finish. ModuleBrowsers lists
// the modules that need something else.
func BrowserAutomation(s Setup) []oidfplan.BrowserTask {
	return []oidfplan.BrowserTask{{
		Match: s.IssuerURL + "/authorize*",
		Tasks: []oidfplan.BrowserStep{oidfplan.LoginStep(s.IssuerURL, s.User), oidfplan.ConsentStep(s.IssuerURL, "approve"), oidfplan.CallbackStep()},
	}}
}

// ModuleBrowsers is the browser automation for the modules the default
// script can't drive, keyed by module name. The plan config carries each
// one as an override, which replaces the whole browser list for that
// module.
//
//   - response-type-missing: oneauth sends the error back to the client's
//     redirect URI (RFC 6749 §4.1.2.1 allows that once the redirect URI is
//     known), so the browser goes straight to the harness callback.
//   - ensure-registered-redirect-uri: an unregistered redirect URI gets
//     oneauth's error page, never a redirect; the browser fills the
//     module's screenshot placeholder with it.
//   - prompt-login and max-age-1: the second authorization must show the
//     login page again. The browser captures it for the screenshot
//     placeholder and logs in. If oneauth skips the login, that step meets
//     the consent page instead and the module fails rather than waiting.
func ModuleBrowsers(s Setup) map[string][]oidfplan.BrowserTask {
	authorize := s.IssuerURL + "/authorize*"
	normal := BrowserAutomation(s)[0]
	firstVisitOnly := normal
	firstVisitOnly.MatchLimit = 1
	secondLogin := oidfplan.BrowserTask{Match: authorize, Tasks: []oidfplan.BrowserStep{{
		Task: "Login page", Match: s.IssuerURL + "/auth/login*", Commands: [][]any{
			{"wait", "xpath", "//h1[text()='Login']", 10, "Login", "update-image-placeholder"},
			{"text", "name", "username", s.User.Email},
			{"text", "name", "password", s.User.Password},
			{"click", "xpath", "//button[@type='submit']"},
		},
	}, oidfplan.ConsentStep(s.IssuerURL, "approve"), oidfplan.CallbackStep()}}
	errorPage := oidfplan.BrowserTask{Match: authorize, Tasks: []oidfplan.BrowserStep{oidfplan.LoginStep(s.IssuerURL, s.User), {
		Task: "Error page", Match: authorize, Commands: [][]any{
			{"wait", "id", "authorize-error", 10, "Authorization error", "update-image-placeholder"},
		},
	}}}
	return map[string][]oidfplan.BrowserTask{
		PlanModule("response-type-missing"):          {{Match: authorize, Tasks: []oidfplan.BrowserStep{oidfplan.CallbackStep()}}},
		PlanModule("ensure-registered-redirect-uri"): {errorPage},
		PlanModule("prompt-login"):                   {firstVisitOnly, secondLogin},
		PlanModule("max-age-1"):                      {firstVisitOnly, secondLogin},
	}
}

// PlanModule is the full harness name of a module given without
// ModulePrefix.
func PlanModule(short string) string { return ModulePrefix + short }

// PlanConfig is the JSON configuration the harness takes for PlanName.
func PlanConfig(s Setup) map[string]any {
	client := func(c Client) map[string]any {
		return map[string]any{"client_id": c.ID, "client_secret": c.Secret, "scope": s.Scope}
	}
	overrides := map[string]any{}
	for module, browser := range ModuleBrowsers(s) {
		overrides[module] = map[string]any{"browser": browser}
	}
	return map[string]any{
		"alias":              s.Alias,
		"description":        "oneauth OIDC Basic OP mission exercise (issue 477)",
		"server":             map[string]any{"discoveryUrl": s.IssuerURL + "/.well-known/openid-configuration"},
		"client":             client(s.Clients[0]),
		"client2":            client(s.Clients[1]),
		"client_secret_post": client(s.PostClient),
		"browser":            BrowserAutomation(s),
		"override":           overrides,
	}
}

// Scope is registered for every client: openid plus every scope the plan's
// modules ask for (the profile, email, address and phone claim scopes, and
// offline_access for the refresh-token module).
const Scope = "openid profile email address phone offline_access"
